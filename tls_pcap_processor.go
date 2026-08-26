package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/ip4defrag"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	tlsContentTypeChangeCipherSpec = 20
	tlsContentTypeAlert            = 21
	tlsContentTypeHandshake        = 22
	tlsContentTypeApplicationData  = 23

	tlsHandshakeClientHello = 1
	tlsHandshakeServerHello = 2
	tlsHandshakeFinished    = 20

	tlsVersion12 = 0x0303
	tlsVersion13 = 0x0304
)

type TLSReplayStats struct {
	TotalTCPFlows  int
	TLSFlows       int
	DecryptedFlows int
}

type streamSegment struct {
	seq     uint32
	payload []byte
}

type flowEndpoint struct {
	ip   net.IP
	port uint16
}

type bidirectionalTCPFlow struct {
	endpointA flowEndpoint
	endpointB flowEndpoint
	aToB      []streamSegment
	bToA      []streamSegment
	firstSeen time.Time
	lastSeen  time.Time
}

type tlsKeyLog struct {
	tls12ByClientRandom map[string][]byte
	tls12ByRandomPair   map[string][]byte
	tls13ByClientRandom map[string]*tls13Secrets
}

type tls13Secrets struct {
	clientHandshake []byte
	serverHandshake []byte
	clientApp       []byte
	serverApp       []byte
}

type tlsRecord struct {
	contentType uint8
	version     uint16
	payload     []byte
	header      [5]byte
}

type tlsClientHello struct {
	random []byte
}

type tlsServerHello struct {
	random      []byte
	sessionID   []byte
	cipherSuite uint16
	version     uint16
}

type aeadMode int

const (
	aeadModeAESGCM aeadMode = iota
	aeadModeChaCha20
)

type tlsCipherSuite struct {
	id               uint16
	name             string
	prfHash          func() hash.Hash
	keyLen           int
	ivLen            int
	explicitNonceLen int
	mode             aeadMode
	tls13            bool
}

type decryptedTLSFlow struct {
	clientIP   net.IP
	serverIP   net.IP
	clientPort uint16
	serverPort uint16
	clientData []byte
	serverData []byte
	startTime  time.Time
}

type tls12DirectionCipher struct {
	suite tlsCipherSuite
	aead  cipher.AEAD
	iv    []byte
}

type tls13DirectionCipher struct {
	aead cipher.AEAD
	iv   []byte
}

var tlsCipherSuites = map[uint16]tlsCipherSuite{
	0xC02B: {id: 0xC02B, name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", prfHash: sha256.New, keyLen: 16, ivLen: 4, explicitNonceLen: 8, mode: aeadModeAESGCM},
	0xC02C: {id: 0xC02C, name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", prfHash: sha512.New384, keyLen: 32, ivLen: 4, explicitNonceLen: 8, mode: aeadModeAESGCM},
	0xC02F: {id: 0xC02F, name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", prfHash: sha256.New, keyLen: 16, ivLen: 4, explicitNonceLen: 8, mode: aeadModeAESGCM},
	0xC030: {id: 0xC030, name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", prfHash: sha512.New384, keyLen: 32, ivLen: 4, explicitNonceLen: 8, mode: aeadModeAESGCM},
	0xCCA8: {id: 0xCCA8, name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", prfHash: sha256.New, keyLen: 32, ivLen: 12, explicitNonceLen: 0, mode: aeadModeChaCha20},
	0xCCA9: {id: 0xCCA9, name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", prfHash: sha256.New, keyLen: 32, ivLen: 12, explicitNonceLen: 0, mode: aeadModeChaCha20},
	0x1301: {id: 0x1301, name: "TLS_AES_128_GCM_SHA256", prfHash: sha256.New, keyLen: 16, ivLen: 12, explicitNonceLen: 0, mode: aeadModeAESGCM, tls13: true},
	0x1302: {id: 0x1302, name: "TLS_AES_256_GCM_SHA384", prfHash: sha512.New384, keyLen: 32, ivLen: 12, explicitNonceLen: 0, mode: aeadModeAESGCM, tls13: true},
	0x1303: {id: 0x1303, name: "TLS_CHACHA20_POLY1305_SHA256", prfHash: sha256.New, keyLen: 32, ivLen: 12, explicitNonceLen: 0, mode: aeadModeChaCha20, tls13: true},
}

func ProcessTLSReplayPCAP(inputPath, keylogPath, outputPath, replayMode string, portOffset int, debug bool) (*TLSReplayStats, error) {
	if replayMode != "decrypted" && replayMode != "mixed" {
		return nil, fmt.Errorf("unsupported tlsmode %q (expected decrypted or mixed)", replayMode)
	}

	// Detect pcapng format
	pcapng, err := isPcapNg(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect input format: %v", err)
	}

	// Build key log from available sources
	var keyLog *tlsKeyLog

	// Try extracting DSB keys from pcapng
	if pcapng {
		dsbData, err := extractDSBKeyLog(inputPath)
		if err != nil {
			if debug {
				log.Printf("[DEBUG] DSB extraction failed: %v", err)
			}
		} else if len(dsbData) > 0 {
			dsbKeyLog, err := parseTLSKeyLog(bytes.NewReader(dsbData))
			if err != nil {
				if debug {
					log.Printf("[DEBUG] DSB key log parsing failed: %v", err)
				}
			} else {
				keyLog = dsbKeyLog
				if debug {
					log.Printf("[DEBUG] Extracted TLS keys from pcapng DSB (%d bytes)", len(dsbData))
				}
			}
		}
	}

	// Parse external keylog file if provided
	if keylogPath != "" {
		fileKeyLog, err := parseTLSKeyLogFile(keylogPath)
		if err != nil {
			return nil, err
		}
		keyLog = mergeTLSKeyLogs(keyLog, fileKeyLog)
	}

	if keyLog == nil {
		return nil, fmt.Errorf("no TLS keys available: provide -keylog file or use a pcapng with embedded Decryption Secrets Blocks")
	}

	// Open input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open input: %v", err)
	}
	defer inputFile.Close()

	// Create appropriate reader based on format
	var linkType layers.LinkType
	var packetSource *gopacket.PacketSource

	if pcapng {
		ngReader, err := pcapgo.NewNgReader(inputFile, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to read pcapng input: %v", err)
		}
		linkType = ngReader.LinkType()
		packetSource = gopacket.NewPacketSource(ngReader, linkType)
	} else {
		reader, err := pcapgo.NewReader(inputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read pcap input: %v", err)
		}
		linkType = reader.LinkType()
		packetSource = gopacket.NewPacketSource(reader, linkType)
	}

	if replayMode == "mixed" && linkType != layers.LinkTypeEthernet {
		return nil, fmt.Errorf("mixed mode currently requires Ethernet input (got link type %v)", linkType)
	}

	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output PCAP: %v", err)
	}
	defer outputFile.Close()

	outputLinkType := layers.LinkTypeEthernet
	if replayMode == "mixed" {
		outputLinkType = linkType
	}

	writer := pcapgo.NewWriter(outputFile)
	if err := writer.WriteFileHeader(65536, outputLinkType); err != nil {
		return nil, fmt.Errorf("failed to write PCAP header: %v", err)
	}

	flows := map[string]*bidirectionalTCPFlow{}
	// A PacketSource decodes IPv4 fragments independently. Reassemble them
	// before decoding TCP to retain complete TLS records.
	defragmenter := ip4defrag.NewIPv4Defragmenter()
	var lastPacketTime time.Time

	for packet := range packetSource.Packets() {
		metadata := packet.Metadata()
		if metadata == nil {
			continue
		}
		if metadata.CaptureInfo.Timestamp.After(lastPacketTime) {
			lastPacketTime = metadata.CaptureInfo.Timestamp
		}

		if replayMode == "mixed" {
			if err := writer.WritePacket(metadata.CaptureInfo, packet.Data()); err != nil {
				return nil, fmt.Errorf("failed to copy original packet into mixed PCAP: %v", err)
			}
		}

		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv4Layer == nil {
			continue
		}
		ipv4 := ipv4Layer.(*layers.IPv4)
		ipv4, err = defragmenter.DefragIPv4WithTimestamp(ipv4, metadata.CaptureInfo.Timestamp)
		if err != nil {
			if debug {
				log.Printf("[DEBUG] IPv4 reassembly skipped: %v", err)
			}
			continue
		}
		if ipv4 == nil || ipv4.Protocol != layers.IPProtocolTCP {
			continue
		}

		var tcp layers.TCP
		if err := tcp.DecodeFromBytes(ipv4.Payload, gopacket.NilDecodeFeedback); err != nil {
			if debug {
				log.Printf("[DEBUG] TCP decode skipped for %s -> %s: %v", ipv4.SrcIP, ipv4.DstIP, err)
			}
			continue
		}
		if len(tcp.Payload) == 0 {
			continue
		}

		src := flowEndpoint{ip: append(net.IP(nil), ipv4.SrcIP.To4()...), port: uint16(tcp.SrcPort)}
		dst := flowEndpoint{ip: append(net.IP(nil), ipv4.DstIP.To4()...), port: uint16(tcp.DstPort)}
		if src.ip == nil || dst.ip == nil {
			continue
		}

		key, forward := canonicalFlowKey(src, dst)
		flow, ok := flows[key]
		if !ok {
			flow = &bidirectionalTCPFlow{
				endpointA: src,
				endpointB: dst,
				firstSeen: metadata.CaptureInfo.Timestamp,
			}
			if !forward {
				flow.endpointA = dst
				flow.endpointB = src
			}
			flows[key] = flow
		}
		flow.lastSeen = metadata.CaptureInfo.Timestamp

		segment := streamSegment{
			seq:     uint32(tcp.Seq),
			payload: append([]byte(nil), tcp.Payload...),
		}
		if forward {
			flow.aToB = append(flow.aToB, segment)
		} else {
			flow.bToA = append(flow.bToA, segment)
		}
	}

	orderedFlows := make([]*bidirectionalTCPFlow, 0, len(flows))
	for _, flow := range flows {
		orderedFlows = append(orderedFlows, flow)
	}
	sort.Slice(orderedFlows, func(i, j int) bool {
		return orderedFlows[i].firstSeen.Before(orderedFlows[j].firstSeen)
	})

	stats := &TLSReplayStats{}
	for i, flow := range orderedFlows {
		stats.TotalTCPFlows++

		decrypted, tlsDetected, err := decryptBidirectionalTLSFlow(flow, keyLog, debug)
		if tlsDetected {
			stats.TLSFlows++
		}
		if err != nil {
			if debug {
				log.Printf("[DEBUG] TLS replay skipped for %s: %v", describeFlow(flow), err)
			}
			continue
		}
		if decrypted == nil || (len(decrypted.clientData) == 0 && len(decrypted.serverData) == 0) {
			continue
		}

		if portOffset != 0 {
			shiftedPort := int(decrypted.serverPort) + portOffset
			if shiftedPort >= 1 && shiftedPort <= 65535 {
				decrypted.serverPort = uint16(shiftedPort)
			} else if debug {
				log.Printf("[DEBUG] port offset would produce invalid port %d for %s, keeping original port %d", shiftedPort, describeFlow(flow), decrypted.serverPort)
			}
		}

		packetGen := NewPacketGenerator(writer, decrypted.clientIP, decrypted.serverIP, decrypted.clientPort, decrypted.serverPort, debug)
		if replayMode == "mixed" {
			packetGen.timestamp = lastPacketTime.Add(time.Duration(i+1) * 50 * time.Millisecond)
		} else if !decrypted.startTime.IsZero() {
			packetGen.timestamp = decrypted.startTime
		}

		if err := packetGen.GenerateTCPSession(decrypted.clientData, decrypted.serverData); err != nil {
			return nil, fmt.Errorf("failed to write decrypted TLS flow for %s: %v", describeFlow(flow), err)
		}
		stats.DecryptedFlows++
	}

	return stats, nil
}

func parseTLSKeyLog(reader io.Reader) (*tlsKeyLog, error) {
	keyLog := &tlsKeyLog{
		tls12ByClientRandom: make(map[string][]byte),
		tls12ByRandomPair:   make(map[string][]byte),
		tls13ByClientRandom: make(map[string]*tls13Secrets),
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case strings.HasPrefix(line, "CLIENT_RANDOM "):
			fields := strings.Fields(line)
			if len(fields) != 3 {
				continue
			}
			clientRandom, err := decodeHexString(fields[1])
			if err != nil {
				continue
			}
			secret, err := decodeHexString(fields[2])
			if err != nil {
				continue
			}
			keyLog.tls12ByClientRandom[hex.EncodeToString(clientRandom)] = secret

		case strings.HasPrefix(line, "RSA Session-ID:") && strings.Contains(line, "Master-Key:"):
			sessionIDHex, masterSecretHex := parseRSASessionKeyLogLine(line)
			if sessionIDHex == "" || masterSecretHex == "" {
				continue
			}
			masterSecret, err := decodeHexString(masterSecretHex)
			if err != nil {
				continue
			}
			keyLog.tls12ByRandomPair[sessionIDKey(sessionIDHex)] = masterSecret

		case strings.HasPrefix(line, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ") ||
			strings.HasPrefix(line, "SERVER_HANDSHAKE_TRAFFIC_SECRET ") ||
			strings.HasPrefix(line, "CLIENT_TRAFFIC_SECRET_0 ") ||
			strings.HasPrefix(line, "SERVER_TRAFFIC_SECRET_0 "):
			fields := strings.Fields(line)
			if len(fields) != 3 {
				continue
			}
			clientRandomHex := strings.ToLower(fields[1])
			secret, err := decodeHexString(fields[2])
			if err != nil {
				continue
			}
			entry := keyLog.ensureTLS13Secrets(clientRandomHex)
			switch fields[0] {
			case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
				entry.clientHandshake = secret
			case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
				entry.serverHandshake = secret
			case "CLIENT_TRAFFIC_SECRET_0":
				entry.clientApp = secret
			case "SERVER_TRAFFIC_SECRET_0":
				entry.serverApp = secret
			}

		case strings.Contains(line, "client_random:") && strings.Contains(line, "master_secret:"):
			clientRandomHex, serverRandomHex, masterSecretHex := parseCapeTLSKeyLogLine(line)
			if clientRandomHex == "" || masterSecretHex == "" {
				continue
			}
			masterSecret, err := decodeHexString(masterSecretHex)
			if err != nil {
				continue
			}
			keyLog.tls12ByClientRandom[clientRandomHex] = masterSecret
			if serverRandomHex != "" {
				keyLog.tls12ByRandomPair[randomPairKey(clientRandomHex, serverRandomHex)] = masterSecret
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read TLS key log: %v", err)
	}

	return keyLog, nil
}

func parseTLSKeyLogFile(path string) (*tlsKeyLog, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open TLS key log: %v", err)
	}
	defer file.Close()
	return parseTLSKeyLog(file)
}

func (k *tlsKeyLog) ensureTLS13Secrets(clientRandomHex string) *tls13Secrets {
	if entry, ok := k.tls13ByClientRandom[clientRandomHex]; ok {
		return entry
	}
	entry := &tls13Secrets{}
	k.tls13ByClientRandom[clientRandomHex] = entry
	return entry
}

func parseCapeTLSKeyLogLine(line string) (clientRandomHex, serverRandomHex, masterSecretHex string) {
	parts := strings.Split(line, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "client_random:"):
			clientRandomHex = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(part, "client_random:")))
		case strings.HasPrefix(part, "server_random:"):
			serverRandomHex = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(part, "server_random:")))
		case strings.HasPrefix(part, "master_secret:"):
			masterSecretHex = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(part, "master_secret:")))
		}
	}
	return clientRandomHex, serverRandomHex, masterSecretHex
}

func parseRSASessionKeyLogLine(line string) (sessionIDHex, masterSecretHex string) {
	parts := strings.Fields(line)
	for _, part := range parts {
		switch {
		case strings.HasPrefix(part, "Session-ID:"):
			sessionIDHex = strings.ToLower(strings.TrimPrefix(part, "Session-ID:"))
		case strings.HasPrefix(part, "Master-Key:"):
			masterSecretHex = strings.ToLower(strings.TrimPrefix(part, "Master-Key:"))
		}
	}
	return sessionIDHex, masterSecretHex
}

func decryptBidirectionalTLSFlow(flow *bidirectionalTCPFlow, keyLog *tlsKeyLog, debug bool) (*decryptedTLSFlow, bool, error) {
	aBytes := reassembleOrderedStream(flow.aToB)
	bBytes := reassembleOrderedStream(flow.bToA)
	if len(aBytes) == 0 || len(bBytes) == 0 {
		return nil, false, nil
	}

	aClientHello := findClientHello(aBytes)
	aServerHello := findServerHello(aBytes)
	bClientHello := findClientHello(bBytes)
	bServerHello := findServerHello(bBytes)

	var clientStream, serverStream []byte
	var clientEndpoint, serverEndpoint flowEndpoint
	var clientHello *tlsClientHello
	var serverHello *tlsServerHello

	switch {
	case aClientHello != nil && bServerHello != nil:
		clientStream, serverStream = aBytes, bBytes
		clientEndpoint, serverEndpoint = flow.endpointA, flow.endpointB
		clientHello, serverHello = aClientHello, bServerHello
	case bClientHello != nil && aServerHello != nil:
		clientStream, serverStream = bBytes, aBytes
		clientEndpoint, serverEndpoint = flow.endpointB, flow.endpointA
		clientHello, serverHello = bClientHello, aServerHello
	default:
		return nil, false, nil
	}

	suite, ok := tlsCipherSuites[serverHello.cipherSuite]
	if !ok {
		return nil, true, fmt.Errorf("unsupported cipher suite 0x%04x", serverHello.cipherSuite)
	}

	var clientData, serverData []byte
	var err error

	clientRandomHex := hex.EncodeToString(clientHello.random)
	serverRandomHex := hex.EncodeToString(serverHello.random)

	switch serverHello.version {
	case tlsVersion13:
		secrets := keyLog.tls13ByClientRandom[clientRandomHex]
		if secrets == nil {
			return nil, true, fmt.Errorf("missing TLS 1.3 secrets for client_random=%s", clientRandomHex)
		}
		// Decrypt each direction independently — allow partial decryption when
		// some secrets are missing (e.g., CLIENT_TRAFFIC_SECRET_0 may not be
		// emitted by some TLS implementations' keylog callbacks)
		clientData, err = decryptTLS13Stream(clientStream, suite, secrets.clientHandshake, secrets.clientApp)
		if err != nil {
			if debug {
				log.Printf("[DEBUG] client TLS 1.3 decrypt failed (partial ok): %v", err)
			}
			clientData = nil
		}
		serverData, err = decryptTLS13Stream(serverStream, suite, secrets.serverHandshake, secrets.serverApp)
		if err != nil {
			if debug {
				log.Printf("[DEBUG] server TLS 1.3 decrypt failed (partial ok): %v", err)
			}
			serverData = nil
		}
		if clientData == nil && serverData == nil {
			return nil, true, fmt.Errorf("TLS 1.3 decrypt failed for both directions, client_random=%s", clientRandomHex)
		}

	case tlsVersion12:
		masterSecret := keyLog.lookupTLS12Secret(clientRandomHex, serverRandomHex, hex.EncodeToString(serverHello.sessionID))
		if len(masterSecret) == 0 {
			return nil, true, fmt.Errorf("missing TLS 1.2 master secret for client_random=%s", clientRandomHex)
		}
		clientKey, serverKey, clientIV, serverIV := deriveTLS12TrafficKeys(suite, masterSecret, clientHello.random, serverHello.random)
		clientCipher, err := newTLS12DirectionCipher(suite, clientKey, clientIV)
		if err != nil {
			return nil, true, fmt.Errorf("failed to initialize client cipher: %v", err)
		}
		serverCipher, err := newTLS12DirectionCipher(suite, serverKey, serverIV)
		if err != nil {
			return nil, true, fmt.Errorf("failed to initialize server cipher: %v", err)
		}
		clientData, err = decryptTLS12Stream(clientStream, clientCipher)
		if err != nil {
			return nil, true, fmt.Errorf("client TLS 1.2 decrypt failed: %v", err)
		}
		serverData, err = decryptTLS12Stream(serverStream, serverCipher)
		if err != nil {
			return nil, true, fmt.Errorf("server TLS 1.2 decrypt failed: %v", err)
		}

	default:
		return nil, true, fmt.Errorf("unsupported TLS version 0x%04x", serverHello.version)
	}

	if debug {
		log.Printf("[DEBUG] replayed TLS flow %s using %s", describeFlow(flow), suite.name)
	}

	return &decryptedTLSFlow{
		clientIP:   clientEndpoint.ip,
		serverIP:   serverEndpoint.ip,
		clientPort: clientEndpoint.port,
		serverPort: serverEndpoint.port,
		clientData: clientData,
		serverData: serverData,
		startTime:  flow.firstSeen,
	}, true, nil
}

func (k *tlsKeyLog) lookupTLS12Secret(clientRandomHex, serverRandomHex, sessionIDHex string) []byte {
	if secret, ok := k.tls12ByRandomPair[randomPairKey(clientRandomHex, serverRandomHex)]; ok {
		return secret
	}
	if sessionIDHex != "" {
		if secret, ok := k.tls12ByRandomPair[sessionIDKey(sessionIDHex)]; ok {
			return secret
		}
	}
	return k.tls12ByClientRandom[clientRandomHex]
}

func canonicalFlowKey(src, dst flowEndpoint) (string, bool) {
	srcKey := endpointSortKey(src)
	dstKey := endpointSortKey(dst)
	if srcKey <= dstKey {
		return srcKey + "|" + dstKey, true
	}
	return dstKey + "|" + srcKey, false
}

func endpointSortKey(endpoint flowEndpoint) string {
	return endpoint.ip.String() + ":" + fmt.Sprintf("%05d", endpoint.port)
}

func describeFlow(flow *bidirectionalTCPFlow) string {
	return fmt.Sprintf("%s:%d <-> %s:%d", flow.endpointA.ip, flow.endpointA.port, flow.endpointB.ip, flow.endpointB.port)
}

// seqDiff returns the signed distance from a to b in TCP sequence space,
// handling uint32 wrapping correctly. Positive means b is ahead of a.
func seqDiff(a, b uint32) int32 {
	return int32(b - a)
}

func reassembleOrderedStream(segments []streamSegment) []byte {
	if len(segments) == 0 {
		return nil
	}

	sorted := make([]streamSegment, len(segments))
	copy(sorted, segments)

	// Use the first segment's seq as reference point for wrap-safe sorting
	refSeq := sorted[0].seq
	sort.Slice(sorted, func(i, j int) bool {
		di := seqDiff(refSeq, sorted[i].seq)
		dj := seqDiff(refSeq, sorted[j].seq)
		if di == dj {
			return len(sorted[i].payload) < len(sorted[j].payload)
		}
		return di < dj
	})

	var out bytes.Buffer
	nextSeq := sorted[0].seq
	first := true

	for _, segment := range sorted {
		if len(segment.payload) == 0 {
			continue
		}

		if first {
			out.Write(segment.payload)
			nextSeq = segment.seq + uint32(len(segment.payload))
			first = false
			continue
		}

		segmentEnd := segment.seq + uint32(len(segment.payload))

		// Wrap-safe: if segmentEnd is at or behind nextSeq, skip (duplicate/retransmit)
		if seqDiff(nextSeq, segmentEnd) <= 0 {
			continue
		}

		// Wrap-safe gap detection: if segment.seq is ahead of nextSeq, there's a gap
		if seqDiff(nextSeq, segment.seq) > 0 {
			return nil // gap in stream — cannot reliably reassemble
		}

		start := 0
		if seqDiff(segment.seq, nextSeq) > 0 {
			start = int(nextSeq - segment.seq)
		}
		out.Write(segment.payload[start:])
		nextSeq = segment.seq + uint32(len(segment.payload))
	}

	return out.Bytes()
}

func parseTLSRecords(data []byte) []tlsRecord {
	if len(data) < 5 {
		return nil
	}

	var records []tlsRecord
	for offset := 0; offset+5 <= len(data); {
		contentType := data[offset]
		if contentType < tlsContentTypeChangeCipherSpec || contentType > tlsContentTypeApplicationData {
			break
		}

		version := binary.BigEndian.Uint16(data[offset+1 : offset+3])
		length := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		if length <= 0 || offset+5+length > len(data) {
			break
		}

		record := tlsRecord{
			contentType: contentType,
			version:     version,
			payload:     data[offset+5 : offset+5+length],
		}
		copy(record.header[:], data[offset:offset+5])
		records = append(records, record)
		offset += 5 + length
	}

	return records
}

func parseHandshakeMessages(data []byte) []tlsRecord {
	var messages []tlsRecord
	for offset := 0; offset+4 <= len(data); {
		msgLen := int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
		if msgLen < 0 || offset+4+msgLen > len(data) {
			break
		}
		record := tlsRecord{
			contentType: data[offset],
			payload:     data[offset+4 : offset+4+msgLen],
		}
		messages = append(messages, record)
		offset += 4 + msgLen
	}
	return messages
}

func findClientHello(data []byte) *tlsClientHello {
	for _, record := range parseTLSRecords(data) {
		if record.contentType != tlsContentTypeHandshake {
			continue
		}
		for _, message := range parseHandshakeMessages(record.payload) {
			if message.contentType != tlsHandshakeClientHello {
				continue
			}
			hello := parseClientHello(message.payload)
			if hello != nil {
				return hello
			}
		}
	}
	return nil
}

func findServerHello(data []byte) *tlsServerHello {
	for _, record := range parseTLSRecords(data) {
		if record.contentType != tlsContentTypeHandshake {
			continue
		}
		for _, message := range parseHandshakeMessages(record.payload) {
			if message.contentType != tlsHandshakeServerHello {
				continue
			}
			hello := parseServerHello(message.payload)
			if hello != nil {
				return hello
			}
		}
	}
	return nil
}

func parseClientHello(data []byte) *tlsClientHello {
	if len(data) < 34 {
		return nil
	}
	random := append([]byte(nil), data[2:34]...)
	return &tlsClientHello{random: random}
}

func parseServerHello(data []byte) *tlsServerHello {
	if len(data) < 38 {
		return nil
	}

	random := append([]byte(nil), data[2:34]...)
	sessionIDLen := int(data[34])
	cursor := 35
	if cursor+sessionIDLen+3 > len(data) {
		return nil
	}
	sessionID := append([]byte(nil), data[cursor:cursor+sessionIDLen]...)
	cursor += sessionIDLen

	cipherSuite := binary.BigEndian.Uint16(data[cursor : cursor+2])
	cursor += 2

	// Skip compression method.
	cursor++

	version := binary.BigEndian.Uint16(data[0:2])
	if cursor+2 <= len(data) {
		extLen := int(binary.BigEndian.Uint16(data[cursor : cursor+2]))
		cursor += 2
		if cursor+extLen <= len(data) {
			version = extractSupportedVersion(data[cursor:cursor+extLen], version)
		}
	}

	return &tlsServerHello{
		random:      random,
		sessionID:   sessionID,
		cipherSuite: cipherSuite,
		version:     version,
	}
}

func extractSupportedVersion(extensions []byte, fallback uint16) uint16 {
	for cursor := 0; cursor+4 <= len(extensions); {
		extType := binary.BigEndian.Uint16(extensions[cursor : cursor+2])
		extLen := int(binary.BigEndian.Uint16(extensions[cursor+2 : cursor+4]))
		cursor += 4
		if cursor+extLen > len(extensions) {
			break
		}
		if extType == 0x002b && extLen == 2 {
			return binary.BigEndian.Uint16(extensions[cursor : cursor+2])
		}
		cursor += extLen
	}
	return fallback
}

func deriveTLS12TrafficKeys(suite tlsCipherSuite, masterSecret, clientRandom, serverRandom []byte) (clientKey, serverKey, clientIV, serverIV []byte) {
	seed := append(append([]byte{}, serverRandom...), clientRandom...)
	keyMaterial := tls12PRF(suite.prfHash, masterSecret, []byte("key expansion"), seed, 2*suite.keyLen+2*suite.ivLen)
	clientKey = append([]byte(nil), keyMaterial[:suite.keyLen]...)
	keyMaterial = keyMaterial[suite.keyLen:]
	serverKey = append([]byte(nil), keyMaterial[:suite.keyLen]...)
	keyMaterial = keyMaterial[suite.keyLen:]
	clientIV = append([]byte(nil), keyMaterial[:suite.ivLen]...)
	keyMaterial = keyMaterial[suite.ivLen:]
	serverIV = append([]byte(nil), keyMaterial[:suite.ivLen]...)
	return clientKey, serverKey, clientIV, serverIV
}

func newTLS12DirectionCipher(suite tlsCipherSuite, key, iv []byte) (*tls12DirectionCipher, error) {
	aeadCipher, err := newAEAD(suite, key)
	if err != nil {
		return nil, err
	}
	return &tls12DirectionCipher{
		suite: suite,
		aead:  aeadCipher,
		iv:    append([]byte(nil), iv...),
	}, nil
}

func decryptTLS12Stream(stream []byte, directionCipher *tls12DirectionCipher) ([]byte, error) {
	records := parseTLSRecords(stream)
	if len(records) == 0 {
		return nil, fmt.Errorf("no TLS records found")
	}

	var out bytes.Buffer
	protected := false
	var seq uint64
	successfulDecryptions := 0

	for _, record := range records {
		if !protected {
			if record.contentType == tlsContentTypeChangeCipherSpec {
				protected = true
				seq = 0
			}
			continue
		}

		if record.contentType != tlsContentTypeHandshake &&
			record.contentType != tlsContentTypeApplicationData &&
			record.contentType != tlsContentTypeAlert {
			continue
		}

		plaintext, err := directionCipher.decrypt(record, seq)
		seq++
		if err != nil {
			if successfulDecryptions == 0 {
				return nil, err
			}
			continue
		}
		successfulDecryptions++

		if record.contentType == tlsContentTypeApplicationData && len(plaintext) > 0 {
			out.Write(plaintext)
		}
	}

	if successfulDecryptions == 0 {
		return nil, fmt.Errorf("no protected TLS 1.2 records decrypted")
	}

	return out.Bytes(), nil
}

func decryptTLS13Stream(stream []byte, suite tlsCipherSuite, handshakeSecret, appSecret []byte) ([]byte, error) {
	if len(handshakeSecret) == 0 {
		return nil, fmt.Errorf("TLS 1.3 replay requires at least the handshake traffic secret")
	}

	handshakeCipher, err := newTLS13DirectionCipher(suite, handshakeSecret)
	if err != nil {
		return nil, err
	}
	var appCipher *tls13DirectionCipher
	if len(appSecret) > 0 {
		appCipher, err = newTLS13DirectionCipher(suite, appSecret)
		if err != nil {
			return nil, err
		}
	}

	type epoch int
	const (
		epochInitial epoch = iota
		epochHandshake
		epochApplication
	)

	records := parseTLSRecords(stream)
	if len(records) == 0 {
		return nil, fmt.Errorf("no TLS records found")
	}

	currentEpoch := epochInitial
	var seq uint64
	successfulDecryptions := 0
	var out bytes.Buffer

	for _, record := range records {
		switch record.contentType {
		case tlsContentTypeHandshake, tlsContentTypeChangeCipherSpec:
			continue
		case tlsContentTypeApplicationData:
		default:
			continue
		}

		if currentEpoch == epochInitial {
			currentEpoch = epochHandshake
			seq = 0
		}

		currentCipher := handshakeCipher
		if currentEpoch == epochApplication {
			if appCipher == nil {
				// Missing application traffic secret — skip application data
				continue
			}
			currentCipher = appCipher
		}

		plaintext, innerType, err := currentCipher.decrypt(record, seq)
		seq++
		if err != nil {
			if successfulDecryptions == 0 {
				return nil, err
			}
			continue
		}
		successfulDecryptions++

		switch innerType {
		case tlsContentTypeHandshake:
			if containsFinishedMessage(plaintext) {
				currentEpoch = epochApplication
				seq = 0
			}
		case tlsContentTypeApplicationData:
			out.Write(plaintext)
		}
	}

	if successfulDecryptions == 0 {
		return nil, fmt.Errorf("no TLS 1.3 records decrypted")
	}

	return out.Bytes(), nil
}

func containsFinishedMessage(data []byte) bool {
	for _, message := range parseHandshakeMessages(data) {
		if message.contentType == tlsHandshakeFinished {
			return true
		}
	}
	return false
}

func (c *tls12DirectionCipher) decrypt(record tlsRecord, seq uint64) ([]byte, error) {
	switch c.suite.mode {
	case aeadModeAESGCM:
		if len(record.payload) < c.suite.explicitNonceLen+c.aead.Overhead() {
			return nil, fmt.Errorf("TLS 1.2 AES-GCM record too short")
		}
		explicitNonce := record.payload[:c.suite.explicitNonceLen]
		ciphertext := record.payload[c.suite.explicitNonceLen:]
		nonce := append(append([]byte(nil), c.iv...), explicitNonce...)
		additionalData := make([]byte, 13)
		binary.BigEndian.PutUint64(additionalData[0:8], seq)
		additionalData[8] = record.contentType
		binary.BigEndian.PutUint16(additionalData[9:11], record.version)
		plainLen := len(ciphertext) - c.aead.Overhead()
		binary.BigEndian.PutUint16(additionalData[11:13], uint16(plainLen))
		return c.aead.Open(nil, nonce, ciphertext, additionalData)

	case aeadModeChaCha20:
		if len(record.payload) < c.aead.Overhead() {
			return nil, fmt.Errorf("TLS 1.2 ChaCha20 record too short")
		}
		nonce := xorSeqNonce(c.iv, seq)
		additionalData := make([]byte, 13)
		binary.BigEndian.PutUint64(additionalData[0:8], seq)
		additionalData[8] = record.contentType
		binary.BigEndian.PutUint16(additionalData[9:11], record.version)
		plainLen := len(record.payload) - c.aead.Overhead()
		binary.BigEndian.PutUint16(additionalData[11:13], uint16(plainLen))
		return c.aead.Open(nil, nonce, record.payload, additionalData)

	default:
		return nil, fmt.Errorf("unsupported AEAD mode")
	}
}

func newTLS13DirectionCipher(suite tlsCipherSuite, trafficSecret []byte) (*tls13DirectionCipher, error) {
	key, iv, err := tls13TrafficKey(suite, trafficSecret)
	if err != nil {
		return nil, err
	}
	aeadCipher, err := newAEAD(suite, key)
	if err != nil {
		return nil, err
	}
	return &tls13DirectionCipher{
		aead: aeadCipher,
		iv:   iv,
	}, nil
}

func (c *tls13DirectionCipher) decrypt(record tlsRecord, seq uint64) ([]byte, uint8, error) {
	nonce := xorSeqNonce(c.iv, seq)
	plaintext, err := c.aead.Open(nil, nonce, record.payload, record.header[:])
	if err != nil {
		return nil, 0, err
	}

	index := len(plaintext) - 1
	for index >= 0 && plaintext[index] == 0 {
		index--
	}
	if index < 0 {
		return nil, 0, fmt.Errorf("TLS 1.3 inner plaintext missing content type")
	}

	innerType := plaintext[index]
	content := append([]byte(nil), plaintext[:index]...)
	return content, innerType, nil
}

func newAEAD(suite tlsCipherSuite, key []byte) (cipher.AEAD, error) {
	switch suite.mode {
	case aeadModeAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case aeadModeChaCha20:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("unsupported AEAD mode")
	}
}

func tls13TrafficKey(suite tlsCipherSuite, trafficSecret []byte) ([]byte, []byte, error) {
	key, err := hkdfExpandLabel(suite.prfHash, trafficSecret, "key", nil, suite.keyLen)
	if err != nil {
		return nil, nil, err
	}
	iv, err := hkdfExpandLabel(suite.prfHash, trafficSecret, "iv", nil, suite.ivLen)
	if err != nil {
		return nil, nil, err
	}
	return key, iv, nil
}

func hkdfExpandLabel(hashFunc func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := append([]byte("tls13 "), []byte(label)...)
	info := make([]byte, 0, 4+len(fullLabel)+len(context))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)

	out := make([]byte, length)
	reader := hkdf.Expand(hashFunc, secret, info)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, err
	}
	return out, nil
}

func tls12PRF(hashFunc func() hash.Hash, secret, label, seed []byte, length int) []byte {
	labelAndSeed := append(append([]byte{}, label...), seed...)
	result := make([]byte, length)
	pHash(result, secret, labelAndSeed, hashFunc)
	return result
}

func pHash(result, secret, seed []byte, hashFunc func() hash.Hash) {
	h := hmac.New(hashFunc, secret)
	a := append([]byte(nil), seed...)
	var offset int

	for offset < len(result) {
		h.Reset()
		h.Write(a)
		a = h.Sum(nil)

		h.Reset()
		h.Write(a)
		h.Write(seed)
		block := h.Sum(nil)

		offset += copy(result[offset:], block)
	}
}

func xorSeqNonce(base []byte, seq uint64) []byte {
	nonce := append([]byte(nil), base...)
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	for i := 0; i < len(seqBytes); i++ {
		nonce[len(nonce)-len(seqBytes)+i] ^= seqBytes[i]
	}
	return nonce
}

func randomPairKey(clientRandomHex, serverRandomHex string) string {
	return clientRandomHex + "|" + serverRandomHex
}

func sessionIDKey(sessionIDHex string) string {
	return "sessionid|" + sessionIDHex
}

func decodeHexString(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty hex string")
	}
	return hex.DecodeString(value)
}

// pcapng constants for DSB extraction
const (
	pcapngSHBMagic     = 0x0A0D0D0A
	pcapngByteOrderLE  = 0x1A2B3C4D
	pcapngByteOrderBE  = 0x4D3C2B1A
	pcapngBlockTypeDSB = 0x0000000A
	pcapngDSBTypeTLS   = 0x544c534b
)

// isPcapNg checks if a file is pcapng format by reading the first 4 bytes.
func isPcapNg(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	var magic uint32
	if err := binary.Read(file, binary.LittleEndian, &magic); err != nil {
		return false, err
	}
	return magic == pcapngSHBMagic, nil
}

// extractDSBKeyLog pre-scans a pcapng file for TLS Decryption Secrets Blocks
// and returns the concatenated key log bytes.
func extractDSBKeyLog(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcapng file: %v", err)
	}
	defer file.Close()

	// Read Section Header Block type
	var shbType uint32
	if err := binary.Read(file, binary.LittleEndian, &shbType); err != nil {
		return nil, fmt.Errorf("failed to read pcapng header: %v", err)
	}
	if shbType != pcapngSHBMagic {
		return nil, fmt.Errorf("not a pcapng file (magic: 0x%08x)", shbType)
	}

	// Read SHB total length (initially as little-endian)
	var shbLen uint32
	if err := binary.Read(file, binary.LittleEndian, &shbLen); err != nil {
		return nil, fmt.Errorf("failed to read SHB length: %v", err)
	}

	// Read byte order magic
	var byteOrderMagic uint32
	if err := binary.Read(file, binary.LittleEndian, &byteOrderMagic); err != nil {
		return nil, fmt.Errorf("failed to read byte order magic: %v", err)
	}

	var bo binary.ByteOrder
	switch byteOrderMagic {
	case pcapngByteOrderLE:
		bo = binary.LittleEndian
	case pcapngByteOrderBE:
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("invalid pcapng byte order magic: 0x%08x", byteOrderMagic)
	}

	// Re-interpret SHB length with correct byte order if big-endian
	if bo == binary.BigEndian {
		shbLen = swapUint32(shbLen)
	}

	// Seek to end of SHB
	if _, err := file.Seek(int64(shbLen), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek past SHB: %v", err)
	}

	// Scan remaining blocks for DSBs
	var keyLogData []byte
	for {
		var blockType, blockLen uint32
		if err := binary.Read(file, bo, &blockType); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, fmt.Errorf("failed to read block type: %v", err)
		}
		if err := binary.Read(file, bo, &blockLen); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, fmt.Errorf("failed to read block length: %v", err)
		}

		if blockLen < 12 {
			break // invalid block
		}
		bodyLen := int64(blockLen) - 12 // subtract header (8) + trailing length (4)

		if blockType == pcapngBlockTypeDSB && bodyLen >= 8 {
			var secretsType, secretsLen uint32
			if err := binary.Read(file, bo, &secretsType); err != nil {
				return nil, fmt.Errorf("failed to read DSB secrets type: %v", err)
			}
			if err := binary.Read(file, bo, &secretsLen); err != nil {
				return nil, fmt.Errorf("failed to read DSB secrets length: %v", err)
			}

			if secretsType == pcapngDSBTypeTLS && secretsLen > 0 {
				payload := make([]byte, secretsLen)
				if _, err := io.ReadFull(file, payload); err != nil {
					return nil, fmt.Errorf("failed to read DSB payload: %v", err)
				}
				keyLogData = append(keyLogData, payload...)
				if len(keyLogData) > 0 && keyLogData[len(keyLogData)-1] != '\n' {
					keyLogData = append(keyLogData, '\n')
				}
				// Skip remaining body (padding + options) and trailing length
				// pcapng requires 4-byte aligned blocks
				alignedLen := (int64(secretsLen) + 3) &^ 3
				remaining := bodyLen - 8 - alignedLen
				if remaining > 0 {
					if _, err := file.Seek(remaining+4, io.SeekCurrent); err != nil {
						break
					}
				} else {
					if _, err := file.Seek(4, io.SeekCurrent); err != nil {
						break
					}
				}
				continue
			}
			// Non-TLS DSB — skip body remainder + trailing length
			remaining := bodyLen - 8
			if remaining > 0 {
				if _, err := file.Seek(remaining+4, io.SeekCurrent); err != nil {
					break
				}
			} else {
				if _, err := file.Seek(4, io.SeekCurrent); err != nil {
					break
				}
			}
		} else if blockType == pcapngSHBMagic {
			// New section — re-read byte order
			var newBOM uint32
			if err := binary.Read(file, binary.LittleEndian, &newBOM); err != nil {
				break
			}
			switch newBOM {
			case pcapngByteOrderLE:
				bo = binary.LittleEndian
			case pcapngByteOrderBE:
				bo = binary.BigEndian
			}
			if bo == binary.BigEndian {
				blockLen = swapUint32(blockLen)
			}
			// Skip rest of SHB (subtract 8 header + 4 BOM already read)
			remaining := int64(blockLen) - 12
			if remaining > 0 {
				if _, err := file.Seek(remaining, io.SeekCurrent); err != nil {
					break
				}
			}
		} else {
			// Skip non-DSB block body + trailing length
			if _, err := file.Seek(bodyLen+4, io.SeekCurrent); err != nil {
				break
			}
		}
	}

	return keyLogData, nil
}

func swapUint32(v uint32) uint32 {
	return (v>>24)&0xff | (v>>8)&0xff00 | (v<<8)&0xff0000 | (v<<24)&0xff000000
}

// mergeTLSKeyLogs combines two key logs. Entries in override take precedence.
func mergeTLSKeyLogs(base, override *tlsKeyLog) *tlsKeyLog {
	if base == nil {
		return override
	}
	if override == nil {
		return base
	}

	merged := &tlsKeyLog{
		tls12ByClientRandom: make(map[string][]byte),
		tls12ByRandomPair:   make(map[string][]byte),
		tls13ByClientRandom: make(map[string]*tls13Secrets),
	}

	for k, v := range base.tls12ByClientRandom {
		merged.tls12ByClientRandom[k] = v
	}
	for k, v := range base.tls12ByRandomPair {
		merged.tls12ByRandomPair[k] = v
	}
	for k, v := range base.tls13ByClientRandom {
		merged.tls13ByClientRandom[k] = v
	}

	for k, v := range override.tls12ByClientRandom {
		merged.tls12ByClientRandom[k] = v
	}
	for k, v := range override.tls12ByRandomPair {
		merged.tls12ByRandomPair[k] = v
	}
	for k, v := range override.tls13ByClientRandom {
		merged.tls13ByClientRandom[k] = v
	}

	return merged
}

// stripLeadingTLSRecords removes TLS record-layer framed data from the
// beginning of a byte stream and returns only the trailing plaintext.
// SSLproxy synthetic PCAPs prepend the original TLS ClientHello (and
// sometimes ServerHello) to the decrypted application data. Suricata
// sees those bytes, classifies the flow as TLS, and ignores the HTTP
// that follows. This function strips them.
func stripLeadingTLSRecords(data []byte) []byte {
	offset := 0
	for offset+5 <= len(data) {
		contentType := data[offset]
		// Valid TLS content types: 20-23
		if contentType < tlsContentTypeChangeCipherSpec || contentType > tlsContentTypeApplicationData {
			break
		}
		length := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		if length <= 0 || offset+5+length > len(data) {
			break
		}
		offset += 5 + length
	}
	if offset == 0 {
		return data // no TLS records found, return as-is
	}
	return data[offset:]
}

// ProcessSSLProxyCleanPCAP reads SSLproxy synthetic PCAPs (which contain
// TLS ClientHello bytes prepended to decrypted plaintext), strips the TLS
// record-layer framing from the start of each client→server stream, and
// writes clean TCP sessions that Suricata can parse for protocol detection.
//
// The inputPath can be a single PCAP file or a directory of PCAPs (as
// produced by SSLproxy's -Y flag). All flows are merged into one output.
func ProcessSSLProxyCleanPCAP(inputPath, outputPath string, portOffset int, debug bool) (*TLSReplayStats, error) {
	// Collect input files
	var inputFiles []string
	info, err := os.Stat(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat input: %v", err)
	}
	if info.IsDir() {
		entries, err := os.ReadDir(inputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read input directory: %v", err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasSuffix(name, ".pcap") || strings.HasSuffix(name, ".pcapng") {
				inputFiles = append(inputFiles, filepath.Join(inputPath, name))
			}
		}
		if len(inputFiles) == 0 {
			return nil, fmt.Errorf("no .pcap/.pcapng files found in %s", inputPath)
		}
		sort.Strings(inputFiles)
	} else {
		inputFiles = []string{inputPath}
	}

	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output PCAP: %v", err)
	}
	defer outputFile.Close()

	writer := pcapgo.NewWriter(outputFile)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return nil, fmt.Errorf("failed to write PCAP header: %v", err)
	}

	stats := &TLSReplayStats{}

	for _, inputFile := range inputFiles {
		if err := processOneSSLProxyPCAP(inputFile, writer, stats, portOffset, debug); err != nil {
			if debug {
				log.Printf("[DEBUG] Skipping %s: %v", inputFile, err)
			}
			continue
		}
	}

	return stats, nil
}

func processOneSSLProxyPCAP(inputPath string, writer *pcapgo.Writer, stats *TLSReplayStats, portOffset int, debug bool) error {
	f, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	pcapng, err := isPcapNg(inputPath)
	if err != nil {
		return err
	}

	var packetSource *gopacket.PacketSource
	if pcapng {
		ngReader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return err
		}
		packetSource = gopacket.NewPacketSource(ngReader, ngReader.LinkType())
	} else {
		reader, err := pcapgo.NewReader(f)
		if err != nil {
			return err
		}
		packetSource = gopacket.NewPacketSource(reader, reader.LinkType())
	}

	// Group packets by TCP flow
	flows := map[string]*bidirectionalTCPFlow{}
	for packet := range packetSource.Packets() {
		metadata := packet.Metadata()
		if metadata == nil {
			continue
		}

		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv4Layer == nil {
			continue
		}
		ipv4 := ipv4Layer.(*layers.IPv4)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp := tcpLayer.(*layers.TCP)
		if len(tcp.Payload) == 0 {
			continue
		}

		src := flowEndpoint{ip: append(net.IP(nil), ipv4.SrcIP.To4()...), port: uint16(tcp.SrcPort)}
		dst := flowEndpoint{ip: append(net.IP(nil), ipv4.DstIP.To4()...), port: uint16(tcp.DstPort)}
		if src.ip == nil || dst.ip == nil {
			continue
		}

		key, forward := canonicalFlowKey(src, dst)
		flow, ok := flows[key]
		if !ok {
			flow = &bidirectionalTCPFlow{
				endpointA: src,
				endpointB: dst,
				firstSeen: metadata.CaptureInfo.Timestamp,
			}
			if !forward {
				flow.endpointA = dst
				flow.endpointB = src
			}
			flows[key] = flow
		}
		flow.lastSeen = metadata.CaptureInfo.Timestamp

		segment := streamSegment{
			seq:     uint32(tcp.Seq),
			payload: append([]byte(nil), tcp.Payload...),
		}
		if forward {
			flow.aToB = append(flow.aToB, segment)
		} else {
			flow.bToA = append(flow.bToA, segment)
		}
	}

	// Process each flow
	orderedFlows := make([]*bidirectionalTCPFlow, 0, len(flows))
	for _, flow := range flows {
		orderedFlows = append(orderedFlows, flow)
	}
	sort.Slice(orderedFlows, func(i, j int) bool {
		return orderedFlows[i].firstSeen.Before(orderedFlows[j].firstSeen)
	})

	for _, flow := range orderedFlows {
		stats.TotalTCPFlows++

		streamA := reassembleOrderedStream(flow.aToB)
		streamB := reassembleOrderedStream(flow.bToA)

		// Determine which side is the client (sent TLS ClientHello)
		clientData, serverData := streamA, streamB
		clientEP, serverEP := flow.endpointA, flow.endpointB
		aHasTLS := len(streamA) >= 6 && streamA[0] == tlsContentTypeHandshake && streamA[1] == 0x03 && streamA[5] == tlsHandshakeClientHello
		bHasTLS := len(streamB) >= 6 && streamB[0] == tlsContentTypeHandshake && streamB[1] == 0x03 && streamB[5] == tlsHandshakeClientHello

		if bHasTLS && !aHasTLS {
			clientData, serverData = streamB, streamA
			clientEP, serverEP = flow.endpointB, flow.endpointA
		} else if !aHasTLS && !bHasTLS {
			// No TLS records in either direction — pass through as-is
			if len(streamA) == 0 && len(streamB) == 0 {
				continue
			}
		}

		if aHasTLS || bHasTLS {
			stats.TLSFlows++
		}

		// Strip leading TLS records only from flows that had TLS
		var cleanClient, cleanServer []byte
		if aHasTLS || bHasTLS {
			cleanClient = stripLeadingTLSRecords(clientData)
			cleanServer = stripLeadingTLSRecords(serverData)
		} else {
			cleanClient = clientData
			cleanServer = serverData
		}

		if len(cleanClient) == 0 && len(cleanServer) == 0 {
			if debug {
				log.Printf("[DEBUG] sslproxy-clean: flow %s had only TLS records, no plaintext", describeFlow(flow))
			}
			continue
		}

		dstPort := serverEP.port
		if portOffset != 0 {
			shifted := int(dstPort) + portOffset
			if shifted >= 1 && shifted <= 65535 {
				dstPort = uint16(shifted)
			}
		}

		pg := NewPacketGenerator(writer, clientEP.ip, serverEP.ip, clientEP.port, dstPort, debug)
		if !flow.firstSeen.IsZero() {
			pg.timestamp = flow.firstSeen
		}

		if err := pg.GenerateTCPSession(cleanClient, cleanServer); err != nil {
			if debug {
				log.Printf("[DEBUG] sslproxy-clean: failed to write flow %s: %v", describeFlow(flow), err)
			}
			continue
		}
		stats.DecryptedFlows++
	}

	return nil
}
