package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	// maxPCAPPacketSize is the maximum size of a packet that can be stored in a PCAP file
	// This is 64KB (65536), which is the standard PCAP packet size limit
	maxPCAPPacketSize = 64 * 1024 // 65536 bytes
	// maxIPPacketSize is the maximum size of an IPv4 packet
	maxIPPacketSize = 65535 // Maximum IPv4 packet size
)

// PacketGenerator holds the state and configuration for packet generation
type PacketGenerator struct {
	writer    *pcapgo.Writer
	srcIP     net.IP
	dstIP     net.IP
	srcPort   uint16
	dstPort   uint16
	timestamp time.Time
	linkType  layers.LinkType
	srcMAC    net.HardwareAddr
	dstMAC    net.HardwareAddr
	debug     bool
}

// NewPacketGenerator creates a new packet generator with the given configuration
func NewPacketGenerator(writer *pcapgo.Writer, srcIP, dstIP net.IP, srcPort, dstPort uint16, debug bool) *PacketGenerator {
	// Default MAC addresses (can be customized if needed)
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("66:77:88:99:aa:bb")

	// Ensure we're using IPv4 addresses
	srcIP = ensureIPv4(srcIP, net.IPv4(192, 168, 1, 1))
	dstIP = ensureIPv4(dstIP, net.IPv4(10, 0, 0, 1))

	return &PacketGenerator{
		writer:    writer,
		srcIP:     srcIP,
		dstIP:     dstIP,
		srcPort:   srcPort,
		dstPort:   dstPort,
		timestamp: time.Now(),
		linkType:  layers.LinkTypeEthernet,
		srcMAC:    srcMAC,
		dstMAC:    dstMAC,
		debug:     debug,
	}
}

// ensureIPv4 ensures the IP is an IPv4 address
func ensureIPv4(ip net.IP, defaultIP net.IP) net.IP {
	if ip == nil {
		return defaultIP
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return defaultIP
}

// GenerateTCPSession generates a complete TCP session with the given request and response data
func (pg *PacketGenerator) GenerateTCPSession(requestData, responseData []byte) error {
	// Initialize TCP sequence numbers
	clientISN := uint32(rand.Intn(1<<32 - 1))
	serverISN := uint32(rand.Intn(1<<32 - 1))

	// Build the TCP handshake
	if err := pg.generateTCPHandshake(clientISN, serverISN); err != nil {
		return fmt.Errorf("error generating TCP handshake: %v", err)
	}

	// Send the HTTP request with segmentation
	currentSeq := clientISN + 1
	currentAck := serverISN + 1

	if len(requestData) > 0 {
		if err := pg.segmentAndSendData(pg.srcIP, pg.dstIP, pg.srcPort, pg.dstPort,
			currentSeq, currentAck, requestData); err != nil {
			return fmt.Errorf("error sending request data: %v", err)
		}
		currentSeq += uint32(len(requestData))
	}

	// Send the HTTP response with segmentation
	if len(responseData) > 0 {
		if err := pg.segmentAndSendData(pg.dstIP, pg.srcIP, pg.dstPort, pg.srcPort,
			currentAck, currentSeq, responseData); err != nil {
			return fmt.Errorf("error sending response data: %v", err)
		}
		currentAck += uint32(len(responseData))
	}

	// Send the TCP connection termination (FIN, ACK)
	return pg.generateTCPTeardown(currentSeq, currentAck)
}

// generateTCPHandshake generates the TCP three-way handshake
func (pg *PacketGenerator) generateTCPHandshake(clientISN, serverISN uint32) error {
	// 1. SYN packet (client → server)
	synEth := &layers.Ethernet{
		SrcMAC:       pg.srcMAC,
		DstMAC:       pg.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	synIP := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    pg.srcIP,
		DstIP:    pg.dstIP,
	}

	synTCP := &layers.TCP{
		SrcPort: layers.TCPPort(pg.srcPort),
		DstPort: layers.TCPPort(pg.dstPort),
		Seq:     clientISN,
		SYN:     true,
		Window:  64240,
	}
	synTCP.SetNetworkLayerForChecksum(synIP)

	// Send SYN
	if err := pg.sendPacket(synEth, synIP, synTCP, nil); err != nil {
		return fmt.Errorf("error sending SYN: %v", err)
	}

	// 2. SYN-ACK packet (server → client)
	synAckEth := &layers.Ethernet{
		SrcMAC:       pg.dstMAC,
		DstMAC:       pg.srcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	synAckIP := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    pg.dstIP,
		DstIP:    pg.srcIP,
	}

	synAckTCP := &layers.TCP{
		SrcPort: layers.TCPPort(pg.dstPort),
		DstPort: layers.TCPPort(pg.srcPort),
		Seq:     serverISN,
		Ack:     clientISN + 1,
		SYN:     true,
		ACK:     true,
		Window:  64240,
	}
	synAckTCP.SetNetworkLayerForChecksum(synAckIP)

	// Send SYN-ACK
	if err := pg.sendPacket(synAckEth, synAckIP, synAckTCP, nil); err != nil {
		return fmt.Errorf("error sending SYN-ACK: %v", err)
	}

	// 3. ACK packet (client → server)
	ackEth := &layers.Ethernet{
		SrcMAC:       pg.srcMAC,
		DstMAC:       pg.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ackIP := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    pg.srcIP,
		DstIP:    pg.dstIP,
	}

	ackTCP := &layers.TCP{
		SrcPort: layers.TCPPort(pg.srcPort),
		DstPort: layers.TCPPort(pg.dstPort),
		Seq:     clientISN + 1,
		Ack:     serverISN + 1,
		ACK:     true,
		Window:  64240,
	}
	ackTCP.SetNetworkLayerForChecksum(ackIP)

	// Send ACK
	return pg.sendPacket(ackEth, ackIP, ackTCP, nil)
}

// segmentAndSendData segments a large payload into smaller TCP packets and sends them
func (pg *PacketGenerator) segmentAndSendData(srcIP, dstIP net.IP, srcPort, dstPort uint16,
	seq, ack uint32, data []byte) error {
	// Constants for packet sizing
	const (
		// Ethernet header (14) + IP header (20) + TCP header (20) = 54 bytes
		headersSize = 54
		// Standard Ethernet MTU is 1500 bytes
		ethernetMTU = 1500
		// Safe segment size that fits in Ethernet MTU with some room for options
		safeSegmentSize = ethernetMTU - headersSize
	)

	// Ensure we're using IPv4
	srcIP = ensureIPv4(srcIP, net.IPv4(192, 168, 1, 1))
	dstIP = ensureIPv4(dstIP, net.IPv4(192, 168, 1, 2))

	totalBytes := len(data)
	if totalBytes == 0 {
		return nil // Nothing to send
	}

	// Calculate number of segments needed
	segmentSize := safeSegmentSize
	if totalBytes < segmentSize {
		segmentSize = totalBytes
	}

	segmentCount := (totalBytes + segmentSize - 1) / segmentSize
	if segmentCount <= 0 {
		segmentCount = 1
	}

	// Send data in segments
	for i := 0; i < segmentCount; i++ {
		offset := i * segmentSize
		end := offset + segmentSize
		if end > totalBytes {
			end = totalBytes
		}

		// Ensure we don't have a zero-length segment
		if offset >= end {
			continue
		}

		segment := data[offset:end]
		isLast := (i == segmentCount-1)

		// Create Ethernet layer
		eth := &layers.Ethernet{
			SrcMAC:       pg.srcMAC,
			DstMAC:       pg.dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}

		// Calculate packet length
		packetLength := headersSize + len(segment)
		if packetLength > ethernetMTU {
			return fmt.Errorf("calculated packet size %d exceeds Ethernet MTU of %d", packetLength, ethernetMTU)
		}

		// Create IP layer with proper length calculation
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Length:   uint16(packetLength),
		}

		// Create TCP layer for this segment
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			Seq:     seq + uint32(offset),
			Ack:     ack,
			PSH:     isLast, // Set PSH only on the last segment
			ACK:     true,
			Window:  65535,
		}

		// Set the network layer for checksum calculation
		tcp.SetNetworkLayerForChecksum(ip)

		// Update timestamp for each packet and add small delay between packets
		pg.timestamp = pg.timestamp.Add(2 * time.Millisecond)

		// Send the data packet
		if err := pg.sendPacket(eth, ip, tcp, segment); err != nil {
			return fmt.Errorf("error sending data segment %d/%d (offset: %d, len: %d): %v",
				i+1, segmentCount, offset, len(segment), err)
		}

		// Small delay between packets to avoid overwhelming the system
		time.Sleep(1 * time.Millisecond)
	}

	// Send ACK for the entire data transfer
	ackEth := &layers.Ethernet{
		SrcMAC:       pg.dstMAC,
		DstMAC:       pg.srcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ackIP := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    dstIP,
		DstIP:    srcIP,
	}

	// Calculate next expected sequence number
	nextSeq := seq + uint32(totalBytes)

	ackTCP := &layers.TCP{
		SrcPort: layers.TCPPort(dstPort),
		DstPort: layers.TCPPort(srcPort),
		Seq:     ack,
		Ack:     nextSeq,
		ACK:     true,
		Window:  65535,
	}
	ackTCP.SetNetworkLayerForChecksum(ackIP)

	// Update timestamp for ACK with a small delay
	pg.timestamp = pg.timestamp.Add(5 * time.Millisecond)

	if err := pg.sendPacket(ackEth, ackIP, ackTCP, nil); err != nil {
		return fmt.Errorf("error sending final ACK: %v", err)
	}

	return nil
}

// generateTCPTeardown generates the TCP connection termination packets
func (pg *PacketGenerator) generateTCPTeardown(clientSeq, serverSeq uint32) error {
	// Client sends FIN
	finEth := &layers.Ethernet{
		SrcMAC:       pg.srcMAC,
		DstMAC:       pg.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	finIP := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    pg.srcIP,
		DstIP:    pg.dstIP,
	}

	finTCP := &layers.TCP{
		SrcPort: layers.TCPPort(pg.srcPort),
		DstPort: layers.TCPPort(pg.dstPort),
		Seq:     clientSeq,
		Ack:     serverSeq,
		FIN:     true,
		ACK:     true,
		Window:  64240,
	}
	finTCP.SetNetworkLayerForChecksum(finIP)

	if err := pg.sendPacket(finEth, finIP, finTCP, nil); err != nil {
		return fmt.Errorf("error sending FIN: %v", err)
	}

	// Server sends ACK
	ackEth := &layers.Ethernet{
		SrcMAC:       pg.dstMAC,
		DstMAC:       pg.srcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ackIP := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    pg.dstIP,
		DstIP:    pg.srcIP,
	}

	ackTCP := &layers.TCP{
		SrcPort: layers.TCPPort(pg.dstPort),
		DstPort: layers.TCPPort(pg.srcPort),
		Seq:     serverSeq,
		Ack:     clientSeq + 1,
		ACK:     true,
		Window:  64240,
	}
	ackTCP.SetNetworkLayerForChecksum(ackIP)

	if err := pg.sendPacket(ackEth, ackIP, ackTCP, nil); err != nil {
		return fmt.Errorf("error sending FIN-ACK: %v", err)
	}

	// Server sends FIN
	finEth2 := &layers.Ethernet{
		SrcMAC:       pg.dstMAC,
		DstMAC:       pg.srcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	finIP2 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    pg.dstIP,
		DstIP:    pg.srcIP,
	}

	finTCP2 := &layers.TCP{
		SrcPort: layers.TCPPort(pg.dstPort),
		DstPort: layers.TCPPort(pg.srcPort),
		Seq:     serverSeq,
		Ack:     clientSeq + 1,
		FIN:     true,
		ACK:     true,
		Window:  64240,
	}
	finTCP2.SetNetworkLayerForChecksum(finIP2)

	if err := pg.sendPacket(finEth2, finIP2, finTCP2, nil); err != nil {
		return fmt.Errorf("error sending FIN-ACK: %v", err)
	}

	// Client sends final ACK
	finalAckEth := &layers.Ethernet{
		SrcMAC:       pg.srcMAC,
		DstMAC:       pg.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	finalAckIP := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    pg.srcIP,
		DstIP:    pg.dstIP,
	}

	finalAckTCP := &layers.TCP{
		SrcPort: layers.TCPPort(pg.srcPort),
		DstPort: layers.TCPPort(pg.dstPort),
		Seq:     clientSeq + 1,
		Ack:     serverSeq + 1,
		ACK:     true,
		Window:  64240,
	}
	finalAckTCP.SetNetworkLayerForChecksum(finalAckIP)

	return pg.sendPacket(finalAckEth, finalAckIP, finalAckTCP, nil)
}

// sendPacket is a helper function to send a packet with the given layers
func (pg *PacketGenerator) sendPacket(
	eth *layers.Ethernet,
	ip *layers.IPv4,
	tcp *layers.TCP,
	payload []byte,
) error {
	// Debug: Log packet info only if debug mode is enabled
	if pg.debug {
		log.Printf("sendPacket: src=%s:%d dst=%s:%d seq=%d ack=%d payload_len=%d",
			ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, tcp.Seq, tcp.Ack, len(payload))
	}

	// Constants for packet size calculations
	const (
		maxMTU         = 1500 // Standard Ethernet MTU
		ipHeaderSize   = 20   // IPv4 header size (minimum, without options)
		tcpHeaderSize  = 20   // TCP header size (minimum, without options)
		ethHeaderSize  = 14   // Ethernet header size
		maxPayloadSize = maxMTU - ethHeaderSize - ipHeaderSize - tcpHeaderSize
	)

	// Ensure payload size is reasonable
	if len(payload) > maxPayloadSize {
		return fmt.Errorf("payload too large: %d bytes (max %d)", len(payload), maxPayloadSize)
	}

	// Set TCP checksum reference before calculating lengths
	tcp.SetNetworkLayerForChecksum(ip)

	// Calculate and set IP total length correctly
	// IP total length includes IP header + TCP header + payload
	ipTotalLength := ipHeaderSize + tcpHeaderSize + len(payload)
	if ipTotalLength > maxIPPacketSize {
		return fmt.Errorf("IP packet too large: %d bytes (max %d)", ipTotalLength, maxIPPacketSize)
	}
	ip.Length = uint16(ipTotalLength)

	// Create buffer and options
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Serialize the packet with validation
	err := func() error {
		// Serialize the packet layers
		err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
		if err != nil {
			return fmt.Errorf("error serializing layers: %v", err)
		}

		// Get the serialized packet
		packetBytes := buf.Bytes()

		// Verify the final packet size against PCAP limits
		if len(packetBytes) > maxPCAPPacketSize {
			return fmt.Errorf("serialized packet too large: %d bytes (max %d)",
				len(packetBytes), maxPCAPPacketSize)
		}

		// Ensure the packet has a reasonable minimum size
		minPacketSize := ethHeaderSize + ipHeaderSize + tcpHeaderSize
		if len(packetBytes) < minPacketSize {
			return fmt.Errorf("packet too small: %d bytes (min %d)",
				len(packetBytes), minPacketSize)
		}

		// Verify IP total length field matches our calculation
		if len(packetBytes) >= ethHeaderSize+4 { // Need at least 4 bytes for IP total length field
			// Extract IP total length from the packet (big-endian, bytes 2-3 of IP header)
			ipTotalLenFromPacket := int(packetBytes[ethHeaderSize+2])<<8 | int(packetBytes[ethHeaderSize+3])
			expectedIPLength := len(packetBytes) - ethHeaderSize

			if ipTotalLenFromPacket != expectedIPLength {
				if pg.debug {
					log.Printf("Warning: IP total length field %d doesn't match actual IP packet length %d (full packet: %d bytes)",
						ipTotalLenFromPacket, expectedIPLength, len(packetBytes))
				}
				// This is a warning, not an error, as gopacket might have added padding or options
			}

			// Validate that the IP length is within acceptable bounds
			if ipTotalLenFromPacket > maxIPPacketSize || ipTotalLenFromPacket < ipHeaderSize+tcpHeaderSize {
				return fmt.Errorf("invalid IP total length in packet: %d (must be between %d and %d)",
					ipTotalLenFromPacket, ipHeaderSize+tcpHeaderSize, maxIPPacketSize)
			}
		}

		return nil
	}()

	if err != nil {
		if pg.debug {
			log.Printf("Packet serialization error: %v", err)
		}
		return err
	}

	// Get the serialized packet
	packetBytes := buf.Bytes()

	// Calculate capture length (should be same as packet length for our case)
	captureLen := len(packetBytes)

	// Log packet info for debugging
	if pg.debug {
		log.Printf("Writing packet: len=%d, captureLen=%d, timestamp=%v",
			len(packetBytes), captureLen, pg.timestamp)

		// Debug: Log first 32 bytes of packet in hex
		hexLen := 32
		if hexLen > len(packetBytes) {
			hexLen = len(packetBytes)
		}
		hexDump := fmt.Sprintf("% x", packetBytes[:hexLen])
		log.Printf("Packet data (first %d bytes): %s", hexLen, hexDump)

		// Debug: Log packet details
		log.Printf("Packet details: eth=%+v, ip=%+v, tcp=%+v, payload_len=%d",
			eth, ip, tcp, len(payload))
	}

	// Write the packet to the PCAP file with validation
	if captureLen <= 0 || captureLen > maxPCAPPacketSize {
		return fmt.Errorf("invalid capture length: %d (must be 1-%d)",
			captureLen, maxPCAPPacketSize)
	}

	// Ensure the packet data is not empty
	if len(packetBytes) == 0 {
		return fmt.Errorf("empty packet data")
	}

	// Write the packet to PCAP file
	err = pg.writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:      pg.timestamp,
		CaptureLength:  captureLen,
		Length:         captureLen,
		InterfaceIndex: 0,
	}, packetBytes)

	if err != nil {
		log.Printf("Failed to write packet to PCAP: %v", err)
		return fmt.Errorf("error writing packet to PCAP: %v", err)
	}

	return nil
}
