package main

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// These variables are defined in main.go and passed as parameters to the functions

// deProxyURL removes proxy information from a URL, leaving only the path with a leading slash
func deProxyURL(urlStr string) string {
	// Parse the URL first to handle it properly
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		// Note: Debug logging not available in this function since it doesn't have debug parameter
		// This is fine as deProxyURL is a utility function
		return "/" // Return root path as fallback
	}

	// Start with the path
	path := "/"

	// Use Path if available
	if parsedURL.Path != "" {
		path = parsedURL.Path
		// Ensure path starts with a single slash
		path = "/" + strings.TrimLeft(path, "/")
	}

	// Add query string if present
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	} else if parsedURL.Fragment != "" {
		// Add fragment if present and no query string
		path += "#" + parsedURL.Fragment
	} else if path == "/" && parsedURL.RawPath != "" {
		// If path is still just "/" and we have a RawPath, use that
		path = "/" + strings.TrimLeft(parsedURL.RawPath, "/")
	}

	return path
}

// splitString splits a string by whitespace, handling quoted strings properly
func splitString(s string) []string {
	var result []string
	var buf bytes.Buffer
	inQuotes := false
	escape := false

	for _, r := range s {
		switch {
		case escape:
			buf.WriteRune(r)
			escape = false
		case r == '\\':
			escape = true
		case r == '"':
			inQuotes = !inQuotes
		case !inQuotes && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			if buf.Len() > 0 {
				result = append(result, buf.String())
				buf.Reset()
			}
		default:
			buf.WriteRune(r)
		}
	}

	if buf.Len() > 0 {
		result = append(result, buf.String())
	}

	return result
}

// processSession processes a single session from a SAZ file
func processSession(dirPath, sessionID string, writer *pcapgo.Writer, deProxy, debug bool) error {
	if debug {
		log.Printf("Processing session %s", sessionID)
	}

	// Load metadata
	metaPath := filepath.Join(dirPath, sessionID+"_m.xml")
	// No need to read file content directly, parseMetadata will do that
	// Just check if the file exists
	if _, err := os.Stat(metaPath); err != nil {
		return fmt.Errorf("metadata file not found: %v", err)
	}

	// Parse metadata from the XML file
	meta, err := parseMetadata(metaPath)
	if err != nil {
		return fmt.Errorf("failed to parse metadata for session %s: %v", sessionID, err)
	}

	// Read request data
	reqPath := filepath.Join(dirPath, sessionID+"_c.txt")
	reqData, err := os.ReadFile(reqPath)
	if err != nil {
		return fmt.Errorf("failed to read request for session %s: %v", sessionID, err)
	}

	// Handle deproxying if enabled
	if len(reqData) > 0 && deProxy {
		if debug {
			log.Printf("Applying deproxy to session %s", sessionID)
		}
		reqStr := string(reqData)

		// Extract the request line and headers
		lines := strings.SplitN(reqStr, "\r\n", 2)
		if len(lines) < 1 {
			return fmt.Errorf("invalid request format")
		}

		// Parse the request line (e.g., "GET https://example.com/ HTTP/1.1")
		reqLine := strings.TrimSpace(lines[0])
		parts := strings.Fields(reqLine)
		if len(parts) < 3 {
			return fmt.Errorf("invalid request line: %s", reqLine)
		}

		// Extract URL and determine if it's HTTP or HTTPS
		urlStr := parts[1]
		isHTTPS := strings.HasPrefix(strings.ToLower(urlStr), "https://")
		if debug {
			log.Printf("Original URL: %s, HTTPS: %v", urlStr, isHTTPS)
		}

		// Extract host and port from URL
		var port int = 0

		// Remove protocol
		urlStr = strings.TrimPrefix(strings.TrimPrefix(urlStr, "http://"), "https://")

		// Split host:port/path
		hostPath := strings.SplitN(urlStr, "/", 2)
		hostPort := hostPath[0]
		path := "/"
		if len(hostPath) > 1 {
			path = "/" + hostPath[1]
		}

		// Split host and port
		if strings.Contains(hostPort, ":") {
			hostPortParts := strings.Split(hostPort, ":")
			var err error
			port, err = strconv.Atoi(hostPortParts[1])
			if err != nil || port <= 0 || port > 65535 {
				port = 0
			}
		}

		// Set default ports if not specified
		if port == 0 {
			if isHTTPS {
				port = 443
			} else {
				port = 80
			}
		}

		// Update the destination port in metadata
		meta.dstPort = port

		// If host IP is missing, try to resolve it from the hostname
		if meta.hostIP == "" && hostPort != "" {
			// Extract just the hostname (remove port if present)
			hostname := hostPort
			if idx := strings.Index(hostname, ":"); idx != -1 {
				hostname = hostname[:idx]
			}

			// Resolve hostname to IP
			addrs, err := net.LookupHost(hostname)
			if err == nil && len(addrs) > 0 {
				meta.hostIP = addrs[0]
			}
		}

		// Modify the request line to use the path instead of full URL
		modifiedReqLine := fmt.Sprintf("%s %s %s", parts[0], path, parts[2])
		if debug {
			log.Printf("Modified request line: %s", modifiedReqLine)
		}

		// Rebuild request with new request line and original headers
		modifiedReqStr := modifiedReqLine
		if len(lines) > 1 {
			modifiedReqStr += "\r\n" + lines[1]
		}

		// Update request data
		reqData = []byte(modifiedReqStr)
	}

	// Read response data (if available)
	respPath := filepath.Join(dirPath, sessionID+"_s.txt")
	respData, err := os.ReadFile(respPath)
	if err != nil {
		if debug {
			log.Printf("No response data found for session %s: %v", sessionID, err)
		}
	}

	// Generate and write packets
	return generateSessionPackets(meta, reqData, respData, writer, debug)
}

// generateSessionPackets generates PCAP packets for a session and writes them to the PCAP writer
func generateSessionPackets(meta sessionMetadata, reqData, respData []byte, writer *pcapgo.Writer, debug bool) error {
	if debug {
		log.Printf("Generating packets for session")
	}

	// Parse IP addresses
	var srcIP net.IP
	if meta.clientIP != "" {
		srcIP = net.ParseIP(meta.clientIP)
	}
	if srcIP == nil {
		srcIP = net.ParseIP("192.168.1.1") // Default source IP
	}

	var dstIP net.IP
	if meta.hostIP != "" {
		dstIP = net.ParseIP(meta.hostIP)
	}
	if dstIP == nil {
		dstIP = net.ParseIP("10.0.0.1") // Default destination IP
	}

	// Parse ports
	var srcPort uint16
	if meta.srcPort != 0 {
		srcPort = uint16(meta.srcPort)
	}
	if srcPort == 0 {
		srcPort = 12345 // Default source port
	}

	var dstPort uint16
	if meta.dstPort != 0 {
		dstPort = uint16(meta.dstPort)
	}
	if dstPort == 0 {
		dstPort = 80 // Default destination port
	}

	// Create a packet generator with the configured parameters
	packetGen := NewPacketGenerator(writer, srcIP, dstIP, srcPort, dstPort, debug)

	// Generate the TCP session with request and response data
	if err := packetGen.GenerateTCPSession(reqData, respData); err != nil {
		return fmt.Errorf("error generating TCP session: %v", err)
	}

	if debug {
		log.Printf("Successfully generated packets for session")
	}
	return nil
}

// ProcessSessions processes all session files in the given directory and writes them to a PCAP file
func ProcessSessions(dirPath, outputPath string, deProxy, split, jsonOutput, debug bool) ([]SessionData, error) {
	var writers pcapWriters
	var err error

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	log.Printf("Starting to process sessions in directory: %s", dirPath)
	var sessionsData []SessionData
	sessionIndex := 1 // Start session index at 1 to match Fiddler numbering

	// Read directory entries
	if _, err := os.ReadDir(dirPath); err != nil {
		return nil, fmt.Errorf("failed to read directory: %v", err)
	}

	if split {
		// Create separate output files for HTTP and HTTPS
		httpPath := outputPath + ".http.pcap"
		httpsPath := outputPath + ".https.pcap"

		httpFile, err := os.Create(httpPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP output file: %v", err)
		}

		httpsFile, err := os.Create(httpsPath)
		if err != nil {
			httpFile.Close() // Close the HTTP file if we can't create the HTTPS file
			return nil, fmt.Errorf("failed to create HTTPS output file: %v", err)
		}

		// Initialize writers for both HTTP and HTTPS with buffered writers
		bufHttp := bufio.NewWriterSize(httpFile, 1<<20)   // 1MB buffer
		bufHttps := bufio.NewWriterSize(httpsFile, 1<<20) // 1MB buffer

		httpWriter := pcapgo.NewWriter(bufHttp)
		httpsWriter := pcapgo.NewWriter(bufHttps)

		// Write PCAP headers with Ethernet frames and maximum snapshot length
		snapshotLength := uint32(65535) // Standard Ethernet MTU
		if err := httpWriter.WriteFileHeader(snapshotLength, layers.LinkTypeEthernet); err != nil {
			httpFile.Close()
			httpsFile.Close()
			return nil, fmt.Errorf("failed to write HTTP PCAP header: %v", err)
		}
		if err := httpsWriter.WriteFileHeader(snapshotLength, layers.LinkTypeEthernet); err != nil {
			httpFile.Close()
			httpsFile.Close()
			return nil, fmt.Errorf("failed to write HTTPS PCAP header: %v", err)
		}

		writers = pcapWriters{
			http:      httpWriter,
			https:     httpsWriter,
			httpFile:  httpFile,
			httpsFile: httpsFile,
			httpBuf:   bufHttp,
			httpsBuf:  bufHttps,
		}
	} else {
		// Single output file for all traffic
		outputFile, err := os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %v", err)
		}

		// Use buffered writer for better performance
		buf := bufio.NewWriterSize(outputFile, 1<<20) // 1MB buffer

		httpWriter := pcapgo.NewWriter(buf)

		// Write PCAP header with Ethernet frames and maximum snapshot length
		snapshotLength := uint32(65535) // Standard Ethernet MTU
		if err := httpWriter.WriteFileHeader(snapshotLength, layers.LinkTypeEthernet); err != nil {
			outputFile.Close()
			return nil, fmt.Errorf("failed to write PCAP header: %v", err)
		}

		writers = pcapWriters{
			http:      httpWriter,
			https:     nil, // Not used in non-split mode
			httpFile:  outputFile,
			httpsFile: nil, // Not used in non-split mode
			httpBuf:   buf,
		}
	}

	// Check for raw subdirectory
	rawDir := filepath.Join(dirPath, "raw")
	if _, err := os.Stat(rawDir); os.IsNotExist(err) {
		if debug {
			log.Printf("Warning: raw directory not found in %s, using directory directly", dirPath)
		}
	} else {
		dirPath = rawDir
		if debug {
			log.Printf("Using raw directory: %s", dirPath)
		}
	}

	// Process each session file
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		writers.cleanup()
		return nil, fmt.Errorf("failed to read directory: %v", err)
	}

	if debug {
		log.Printf("Found %d entries in directory %s", len(entries), dirPath)
	}

	for _, entry := range entries {
		if debug {
			log.Printf("Processing entry: %s (isDir: %v)", entry.Name(), entry.IsDir())
		}

		if !entry.IsDir() && strings.HasSuffix(entry.Name(), "_m.xml") {
			sessionID := entry.Name()[:len(entry.Name())-6] // Remove "_m.xml" suffix
			if debug {
				log.Printf("Found session metadata file: %s (sessionID: %s)", entry.Name(), sessionID)
			}

			// Read metadata
			metaPath := filepath.Join(dirPath, sessionID+"_m.xml")
			meta, err := parseMetadata(metaPath)
			if err != nil {
				if debug {
					log.Printf("Failed to parse metadata for session %s: %v", sessionID, err)
				}
			} else {
				if debug {
					log.Printf("Parsed metadata for session %s: %+v", sessionID, meta)
				}
			}

			// Read request data
			reqPath := filepath.Join(dirPath, sessionID+"_c.txt")
			reqData, err := os.ReadFile(reqPath)
			if err != nil {
				if debug {
					log.Printf("Failed to read request file %s: %v", reqPath, err)
				}
				continue
			}
			if debug {
				log.Printf("Read request data for session %s (%d bytes)", sessionID, len(reqData))
			}

			// Read response data (ignore errors as response might be missing)
			respPath := filepath.Join(dirPath, sessionID+"_s.txt")
			respData, err := os.ReadFile(respPath)
			if err != nil {
				if debug {
					log.Printf("Note: No response data found for session %s: %v", sessionID, err)
				}
			} else {
				if debug {
					log.Printf("Read response data for session %s (%d bytes)", sessionID, len(respData))
				}
			}

			// Get the writer based on the split flag
			var writer *pcapgo.Writer
			if split {
				// Determine if this is HTTPS based on the URL in the request
				isHTTPS := bytes.Contains(reqData, []byte("CONNECT")) ||
					bytes.Contains(reqData, []byte("https://"))
				if debug {
					log.Printf("Session %s is HTTPS: %v", sessionID, isHTTPS)
				}
				if isHTTPS {
					writer = writers.https
				} else {
					writer = writers.http
				}
			} else {
				writer = writers.http
			}

			// Process the session for PCAP
			if err := processSession(dirPath, sessionID, writer, deProxy, debug); err != nil {
				writers.cleanup()
				log.Printf("Error processing session %s: %v", sessionID, err)
				continue // Skip to next session if this one fails
			}

			// Always collect session data for tracking, regardless of JSON output
			metaPath = filepath.Join(dirPath, sessionID+"_m.xml")
			meta, err = parseMetadata(metaPath)
			if err != nil {
				log.Printf("Failed to parse metadata for session %s: %v", sessionID, err)
				continue
			}

			// Parse XML metadata for additional fields
			var xmlMeta xmlMetadata
			data, err := ioutil.ReadFile(metaPath)
			if err == nil {
				_ = xml.Unmarshal(data, &xmlMeta) // Ignore errors, we'll use what we can
			}

			sessionData := collectSessionData(dirPath, sessionID, meta, reqData, respData, xmlMeta)
			sessionData.Index = sessionIndex
			sessionIndex++

			// Update URL if deproxying
			if sessionData.URL != "" && deProxy {
				sessionData.URL = strings.TrimPrefix(sessionData.URL, "http://")
				sessionData.URL = strings.TrimPrefix(sessionData.URL, "https://")
				if parts := strings.SplitN(sessionData.URL, "/", 2); len(parts) > 1 {
					sessionData.URL = parts[1]
				}
			}

			sessionsData = append(sessionsData, sessionData)
		}
	}

	// Export to JSON if enabled
	if jsonOutput && len(sessionsData) > 0 {
		// Create JSON file path by adding .json extension to the PCAP output path
		jsonPath := outputPath
		if !strings.HasSuffix(strings.ToLower(jsonPath), ".json") {
			jsonPath += ".json"
		}

		if err := exportToJSON(sessionsData, jsonPath); err != nil {
			writers.cleanup()
			log.Printf("Failed to export JSON: %v", err)
		}
	}

	// Flush and close all writers
	writers.cleanup()
	return sessionsData, nil
}

// pcapWriters is defined in main.go
