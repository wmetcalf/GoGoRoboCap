package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// HostMapper handles hostname to IP address mappings
type HostMapper struct {
	hostnameMap map[string]string
	mutex       sync.RWMutex
}

// NewHostMapper creates a new HostMapper instance
func NewHostMapper() *HostMapper {
	return &HostMapper{
		hostnameMap: make(map[string]string),
	}
}

// AddMapping adds a hostname to IP mapping
func (hm *HostMapper) AddMapping(hostname, ip string) {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()
	hm.hostnameMap[strings.ToLower(hostname)] = ip
}

// GetIP looks up a hostname in the mapping or returns the default IP
func (hm *HostMapper) GetIP(hostname, defaultIP string) string {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()
	if ip, exists := hm.hostnameMap[strings.ToLower(hostname)]; exists {
		return ip
	}
	return defaultIP
}

// GetDefaultIP returns the appropriate default IP based on the hostname
func GetDefaultIP(hostname string) string {
	// Check if it's a loopback address
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return "127.0.0.1"
	}
	// Return a default non-routable address
	return "10.0.0.1"
}

var (
	// hostMapper handles hostname to IP mappings
	hostMapper = NewHostMapper()
)

// AddHostnameMapping adds a hostname to IP mapping
// This is a wrapper around hostMapper.AddMapping with additional validation
func AddHostnameMapping(hostname, ip string) {
	if hostname == "" || ip == "" {
		return
	}

	// Don't add localhost mappings as they can cause issues
	if ip == "127.0.0.1" || ip == "::1" {
		return
	}

	// Skip if we already have this mapping
	existingIP := hostMapper.GetIP(hostname, "")
	if existingIP == ip {
		return
	}

	// Add the new mapping
	hostMapper.AddMapping(hostname, ip)
}

// ResolveHostIP resolves a hostname to an IP address using the hostname mapping or returns the default IP
func ResolveHostIP(hostname, defaultIP string) string {
	if hostname == "" {
		return defaultIP
	}

	// Check if it's already an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		return hostname
	}

	// Remove port if present
	hostWithoutPort := strings.Split(hostname, ":")[0]

	// Try to get from hostname mapping first
	if ip := hostMapper.GetIP(hostWithoutPort, ""); ip != "" {
		return ip
	}

	// If we have a port in the original hostname, try with it
	if hostWithoutPort != hostname {
		if ip := hostMapper.GetIP(hostname, ""); ip != "" {
			return ip
		}
	}

	// Try to resolve the hostname via DNS
	ips, err := net.LookupIP(hostWithoutPort)
	if err != nil {
		log.Printf("[WARN] DNS resolution failed for '%s': %v", hostWithoutPort, err)
		return defaultIP
	}

	if len(ips) == 0 {
		log.Printf("[WARN] No IPs found for hostname: %s", hostWithoutPort)
		return defaultIP
	}

	// Use the first IPv4 address if available, otherwise use the first address
	for _, ip := range ips {
		if ip.To4() != nil {
			ipStr := ip.String()
			AddHostnameMapping(hostWithoutPort, ipStr)
			if hostWithoutPort != hostname {
				AddHostnameMapping(hostname, ipStr)
			}
			return ipStr
		}
	}

	// If no IPv4, use the first address
	ipStr := ips[0].String()
	AddHostnameMapping(hostWithoutPort, ipStr)
	if hostWithoutPort != hostname {
		AddHostnameMapping(hostname, ipStr)
	}
	return ipStr
}

// HARData represents the top-level structure of a HAR file
type HARData struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"creator"`
		Browser struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"browser"`
		Pages   []interface{} `json:"pages"`
		Entries []HAREntry    `json:"entries"`
	} `json:"log"`
}

// HAREntry represents a single HTTP request/response pair in a HAR file
type HAREntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         struct {
		Blocked float64 `json:"blocked"`
		DNS     float64 `json:"dns"`
		Connect float64 `json:"connect"`
		Send    float64 `json:"send"`
		Wait    float64 `json:"wait"`
		Receive float64 `json:"receive"`
		SSL     float64 `json:"ssl"`
	} `json:"timings"`
	ServerIPAddress string `json:"serverIPAddress"`
	Connection      string `json:"connection"`
}

// HARRequest represents an HTTP request in a HAR file
type HARRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	QueryString []HARHeader `json:"queryString"`
	Cookies     []HARCookie `json:"cookies"`
	PostData    struct {
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
		Params   []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"params"`
	} `json:"postData"`
	HeadersSize int `json:"headersSize"`
	BodySize    int `json:"bodySize"`
}

// HARResponse represents an HTTP response in a HAR file
type HARResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	Cookies     []HARCookie `json:"cookies"`
	Content     struct {
		Size        int    `json:"size"`
		MimeType    string `json:"mimeType"`
		Text        string `json:"text"`
		Encoding    string `json:"encoding"`
		Compression int    `json:"compression"`
	} `json:"content"`
	RedirectURL  string `json:"redirectURL"`
	HeadersSize  int    `json:"headersSize"`
	BodySize     int    `json:"bodySize"`
	TransferSize int    `json:"_transferSize"`
}

// HARHeader represents an HTTP header in a HAR file
type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARCookie represents a cookie in a HAR file
type HARCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	Expires  string `json:"expires"`
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
}

// ProcessHAR processes a HAR file and generates a PCAP file with optional deproxy support
// Returns the list of processed sessions and any error that occurred
func ProcessHAR(harPath, outputPath string, deProxy, debug bool, srcIP, dstIP string) ([]SessionData, error) {
	var sessions []SessionData

	if debug {
		log.Printf("Processing HAR file: %s", harPath)
	}

	// Read the HAR file
	data, err := os.ReadFile(harPath)
	if err != nil {
		return sessions, fmt.Errorf("error reading HAR file: %v", err)
	}

	// Parse the HAR data
	var harData HARData
	if err := json.Unmarshal(data, &harData); err != nil {
		return sessions, fmt.Errorf("error parsing HAR data: %v", err)
	}

	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return sessions, fmt.Errorf("error creating output file: %v", err)
	}
	defer outputFile.Close()

	// Create PCAP writer
	pcapWriter := pcapgo.NewWriter(outputFile)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return sessions, fmt.Errorf("error writing PCAP header: %v", err)
	}

	// Process each entry in the HAR file
	if debug {
		log.Printf("Found %d entries in HAR file", len(harData.Log.Entries))
	}

	for i, entry := range harData.Log.Entries {
		session, err := processHAREntry(entry, i, pcapWriter, deProxy, debug, srcIP, dstIP)
		if err != nil {
			if debug {
				log.Printf("Error processing entry %d: %v", i, err)
			}
			continue
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// processHAREntry processes a single entry from a HAR file
func processHAREntry(entry HAREntry, index int, writer *pcapgo.Writer, deProxy, debug bool, srcIP, dstIP string) (SessionData, error) {
	session := SessionData{
		Index:           index,
		RequestHeaders:  make(map[string]string),
		ResponseHeaders: make(map[string]string),
	}

	// Parse URL
	parsedURL, err := url.Parse(entry.Request.URL)
	if err != nil {
		return session, fmt.Errorf("failed to parse URL: %v", err)
	}

	if debug {
		log.Printf("Processing HAR entry %d: %s %s", index, entry.Request.Method, entry.Request.URL)
		log.Printf("HAR Entry ServerIPAddress: '%s' (empty means not present)", entry.ServerIPAddress)
		log.Printf("Parsed URL - Scheme: %s, Host: %s, Path: %s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
	}

	// Handle special cases for file:// URLs - spoof them as HTTP requests
	if parsedURL.Scheme == "file" {
		if debug {
			log.Printf("Detected file:// URL, spoofing as HTTP request")
		}
		// Convert file:// URL to HTTP
		session.Method = entry.Request.Method
		if session.Method == "" {
			session.Method = "GET"
		}
		session.Protocol = "HTTP/1.1" // Force HTTP/1.1 for file submissions

		// Use default destination IP as the host for file URLs
		session.Host = dstIP

		// Use the file path as the HTTP path
		path := parsedURL.Path
		if path == "" {
			path = "/"
		}
		// Add query parameters if present
		if parsedURL.RawQuery != "" {
			path += "?" + parsedURL.RawQuery
		}
		session.Path = path

		// Create a spoofed HTTP URL for the session
		session.URL = fmt.Sprintf("http://%s%s", dstIP, path)
		session.IsDeproxied = false
	} else {
		// Extract request information for normal HTTP/HTTPS URLs
		session.Method = entry.Request.Method
		session.Protocol = entry.Request.HTTPVersion
		session.Host = parsedURL.Host

		// Set URL path
		path := parsedURL.Path
		if path == "" {
			path = "/"
		}
		// Add query parameters if present
		if parsedURL.RawQuery != "" {
			path += "?" + parsedURL.RawQuery
		}
		session.Path = path
		session.URL = entry.Request.URL

		// Apply deproxy if requested
		if deProxy {
			session.URL = deProxyURL(entry.Request.URL)
			session.IsDeproxied = true
		}
	}

	// Extract request headers
	for _, header := range entry.Request.Headers {
		session.RequestHeaders[header.Name] = header.Value
	}

	// Set request body
	if entry.Request.PostData.Text != "" {
		session.RequestBody = entry.Request.PostData.Text
		session.IsReqBinary = false // HAR text is typically not binary
	}

	// Extract response information
	session.Status = entry.Response.Status

	// Extract response headers
	for _, header := range entry.Response.Headers {
		session.ResponseHeaders[header.Name] = header.Value
	}

	// Set response body
	if entry.Response.Content.Text != "" {
		session.ResponseBody = entry.Response.Content.Text
		session.IsRespBinary = false // HAR text is typically not binary
	}

	hostname := parsedURL.Host

	// For file:// URLs that we've spoofed, use the destination IP as hostname
	if parsedURL.Scheme == "file" {
		hostname = dstIP
		if debug {
			log.Printf("Using spoofed hostname for file:// URL: %s", hostname)
		}
	}

	if debug {
		log.Printf("Processing entry with hostname: %s", hostname)
	}

	var resolvedIP string

	// For spoofed file URLs, use the destination IP directly
	if parsedURL.Scheme == "file" {
		resolvedIP = dstIP
		if debug {
			log.Printf("Using destination IP for spoofed file:// URL: %s", resolvedIP)
		}
	} else if entry.ServerIPAddress != "" {
		resolvedIP = entry.ServerIPAddress
		// Add to hostname mapping for future use
		AddHostnameMapping(hostname, resolvedIP)
		// Also add mapping for hostname without port if it has one
		if strings.Contains(hostname, ":") {
			hostWithoutPort := strings.Split(hostname, ":")[0]
			AddHostnameMapping(hostWithoutPort, resolvedIP)
		}
	} else {
		// Check if hostname is an IP address
		if ip := net.ParseIP(hostname); ip != nil {
			resolvedIP = ip.String()
		} else {
			// Try to resolve the hostname
			resolvedIP = ResolveHostIP(hostname, dstIP)
		}

		// Log warnings for potential issues
		if resolvedIP == "127.0.0.1" {
			log.Printf("[WARN] Resolved '%s' to localhost (127.0.0.1)", hostname)
		}

		// Add to hostname mapping if we have a valid IP
		if resolvedIP != "" && resolvedIP != dstIP {
			AddHostnameMapping(hostname, resolvedIP)
			if strings.Contains(hostname, ":") {
				hostWithoutPort := strings.Split(hostname, ":")[0]
				AddHostnameMapping(hostWithoutPort, resolvedIP)
			}
		}
	}

	// Set the server IP and port in the session metadata
	session.Metadata.ServerIP = resolvedIP
	session.Metadata.Protocol = parsedURL.Scheme

	// Handle port assignment
	if parsedURL.Scheme == "file" {
		// For spoofed file URLs, use HTTP port
		session.Metadata.ServerPort = 80
		session.Metadata.Protocol = "http" // Store as http for packet generation
	} else {
		session.Metadata.ServerPort = 80
		if parsedURL.Scheme == "https" {
			session.Metadata.ServerPort = 443
		}

		// If we have a port in the URL, use it
		if parsedURL.Port() != "" {
			if port, err := strconv.Atoi(parsedURL.Port()); err == nil {
				session.Metadata.ServerPort = port
			}
		}
	}

	session.Metadata.ClientIP = srcIP
	session.Metadata.ClientPort = 12345 + index%1000 // Simple port allocation

	if debug {
		log.Printf("Processed entry %d: %s %s -> %s:%d (mapped: %v)",
			index, entry.Request.Method, hostname, session.Metadata.ServerIP,
			session.Metadata.ServerPort, entry.ServerIPAddress != "")
	}

	// Generate packets
	if err := generatePacketsFromHAR(session, writer, debug); err != nil {
		return session, fmt.Errorf("failed to generate packets: %v", err)
	}

	return session, nil
}

// buildHTTPRequest builds an HTTP request from session data
func buildHTTPRequest(session SessionData) []byte {
	var request strings.Builder

	// Build the path/URL to use in the request line
	requestPath := session.Path
	if requestPath == "" {
		requestPath = "/"
	}

	// Request line
	httpVersion := session.Protocol
	if httpVersion == "" {
		httpVersion = "HTTP/1.1"
	}
	request.WriteString(fmt.Sprintf("%s %s %s\r\n", session.Method, requestPath, httpVersion))

	// Ensure we have a Host header - this is required for HTTP/1.1
	hasHostHeader := false
	for name := range session.RequestHeaders {
		if strings.ToLower(name) == "host" {
			hasHostHeader = true
			break
		}
	}

	// Add Host header if not present
	if !hasHostHeader && session.Host != "" {
		request.WriteString(fmt.Sprintf("Host: %s\r\n", session.Host))
	}

	// Add other headers
	for name, value := range session.RequestHeaders {
		request.WriteString(fmt.Sprintf("%s: %s\r\n", name, value))
	}

	// Empty line separating headers from body
	request.WriteString("\r\n")

	// Body (if present)
	if session.RequestBody != "" {
		request.WriteString(session.RequestBody)
	}

	return []byte(request.String())
}

// buildHTTPResponse builds an HTTP response from session data
func buildHTTPResponse(session SessionData) []byte {
	var response strings.Builder

	// Status line
	statusText := http.StatusText(session.Status)
	if statusText == "" {
		statusText = "Unknown"
	}

	httpVersion := session.Protocol
	if httpVersion == "" {
		httpVersion = "HTTP/1.1"
	}

	response.WriteString(fmt.Sprintf("%s %d %s\r\n", httpVersion, session.Status, statusText))

	// Add headers
	for name, value := range session.ResponseHeaders {
		response.WriteString(fmt.Sprintf("%s: %s\r\n", name, value))
	}

	// Empty line separating headers from body
	response.WriteString("\r\n")

	// Body (if present)
	if session.ResponseBody != "" {
		response.WriteString(session.ResponseBody)
	}

	return []byte(response.String())
}

// generatePacketsFromHAR generates PCAP packets from HAR session data
func generatePacketsFromHAR(session SessionData, writer *pcapgo.Writer, debug bool) error {
	// Parse source and destination IPs from session metadata
	srcIP := net.ParseIP(session.Metadata.ClientIP)
	if srcIP == nil {
		srcIP = net.ParseIP("192.168.1.1") // Fallback default source IP
	}

	dstIP := net.ParseIP(session.Metadata.ServerIP)
	if dstIP == nil {
		dstIP = net.ParseIP("10.0.0.1") // Fallback default destination IP
	}

	// Set ports
	srcPort := uint16(session.Metadata.ClientPort)
	if srcPort == 0 {
		srcPort = 12345 // Default source port
	}

	dstPort := uint16(session.Metadata.ServerPort)
	if dstPort == 0 {
		dstPort = 80 // Default destination port for HTTP
		if session.Protocol == "https" {
			dstPort = 443
		}
	}

	if debug {
		log.Printf("[DEBUG] Generating packets for %s %s", session.Method, session.URL)
		log.Printf("[DEBUG] Using src: %s:%d, dst: %s:%d (from session metadata)",
			srcIP, srcPort, dstIP, dstPort)
		log.Printf("[DEBUG] Session metadata: %+v", session.Metadata)
	}

	// Prepare HTTP request and response data
	reqData := buildHTTPRequest(session)
	respData := buildHTTPResponse(session)

	// Create packet generator
	packetGen := NewPacketGenerator(writer, srcIP, dstIP, srcPort, dstPort, debug)

	// Generate the TCP session with request and response data
	if err := packetGen.GenerateTCPSession(reqData, respData); err != nil {
		return fmt.Errorf("error generating TCP session: %v", err)
	}

	return nil
}
