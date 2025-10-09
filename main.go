// Package main provides a tool to convert Fiddler session files to PCAP format.
//
// Usage:
//
//	fiddler2pcap -i input.saz -o output.pcap --saz
//	fiddler2pcap -i input.har -o output.pcap --har
//	fiddler2pcap -i input.har.gz -o output.pcap --gz
//	fiddler2pcap -i input.saz.gz -o output.pcap --gz --saz
//	fiddler2pcap -i input.har.gz -o output.pcap --gz --har
//	fiddler2pcap -i /path/to/raw/sessions/ -o output.pcap
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/gopacket/pcapgo"
)

// sessionMetadata holds metadata about a Fiddler session
type sessionMetadata struct {
	clientIP string
	hostIP   string
	srcPort  int
	dstPort  int
}

// SessionData represents a complete session with metadata, request, and response
type SessionData struct {
	Index              int    `json:"index"`
	URL                string `json:"url,omitempty"`
	Host               string `json:"host,omitempty"`
	Path               string `json:"path,omitempty"`
	Method             string `json:"method,omitempty"`
	Protocol           string `json:"protocol,omitempty"`
	Status             int    `json:"status,omitempty"`
	IsDeproxied        bool   `json:"is_deproxied,omitempty"`
	IsHTTP11Normalized bool   `json:"is_http11_normalized,omitempty"`
	IsDNSResolved      bool   `json:"is_dns_resolved,omitempty"`

	// Request data
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
	RequestBody    string            `json:"request_body,omitempty"`
	IsReqBinary    bool              `json:"is_req_binary,omitempty"`

	// Response data
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	IsRespBinary    bool              `json:"is_resp_binary,omitempty"`

	// Backward compatibility
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	IsBinary bool   `json:"is_binary,omitempty"`

	// Metadata contains additional information about the session
	Metadata struct {
		ClientIP   string `json:"client_ip,omitempty"`
		ClientPort int    `json:"client_port,omitempty"`
		ServerIP   string `json:"server_ip,omitempty"`
		ServerPort int    `json:"server_port,omitempty"`
		Protocol   string `json:"protocol,omitempty"`
		Timing     struct {
			ClientBegin string `json:"client_begin,omitempty"`
			ClientDone  string `json:"client_done,omitempty"`
			ServerBegin string `json:"server_begin,omitempty"`
			ServerDone  string `json:"server_done,omitempty"`
		} `json:"timing,omitempty"`
		Flags map[string]string `json:"flags,omitempty"`
	} `json:"metadata,omitempty"`
}

var (
	srcIP        string
	dstIP        string
	srcPort      int
	dstPort      int
	outputPath   string
	inputPath    string
	sazMode      bool
	harMode      bool
	gzMode       bool
	jsonOutput   bool
	debugMode    bool
	deProxy      bool
	resolveHosts bool
	http11       bool
	split        bool
)

// exportToJSON exports session data to a JSON file
func exportToJSON(sessions []SessionData, outputPath string) error {
	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(outputPath)
	if outputDir != "." {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}
	}

	// Create or truncate the output file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	// URL normalization is now handled in processHAREntry and processSession

	// Configure JSON encoder
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	// Write JSON data
	if err := encoder.Encode(sessions); err != nil {
		return fmt.Errorf("failed to encode session data to JSON: %v", err)
	}

	log.Printf("Exported %d sessions to %s\n", len(sessions), outputPath)
	return nil
}

// detectFileType tries to determine if the input file is a SAZ, HAR, or GZ file
func detectFileType(filePath string) (string, error) {
	// Check the file extension first
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".saz" {
		return "saz", nil
	} else if ext == ".har" {
		return "har", nil
	} else if ext == ".gz" {
		return "gz", nil
	}

	// If extension doesn't clearly indicate the type, try to read file contents
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file for type detection: %v", err)
	}
	defer file.Close()

	// Read a small chunk to determine file type
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read file for type detection: %v", err)
	}
	buf = buf[:n]

	// Check if it's a JSON file (HAR)
	if n > 1 && buf[0] == '{' {
		// Try to determine if it's a HAR file by looking for specific HAR format identifiers
		if bytes.Contains(buf, []byte("\"log\":")) &&
			(bytes.Contains(buf, []byte("\"entries\":")) ||
				bytes.Contains(buf, []byte("\"version\":")) ||
				bytes.Contains(buf, []byte("\"creator\":")) ||
				bytes.Contains(buf, []byte("\"pages\":")) ||
				bytes.Contains(buf, []byte("\"browser\":")) ||
				bytes.Contains(buf, []byte("\"comment\":"))) {
			return "har", nil
		}
	}

	// Check if it's a ZIP file (SAZ)
	if n > 2 && buf[0] == 0x50 && buf[1] == 0x4B {
		return "saz", nil
	}

	// Default to directory mode if it's a directory
	fileInfo, err := os.Stat(filePath)
	if err == nil && fileInfo.IsDir() {
		return "dir", nil
	}

	return "", fmt.Errorf("unable to determine file type")
}

// decompressGZ decompresses a .gz file and returns the decompressed data and detected inner type
// If innerTypeHint is provided (e.g., "saz" or "har"), it will be used instead of auto-detection
func decompressGZ(gzPath string, innerTypeHint string) (string, string, error) {
	// Open the gzip file
	file, err := os.Open(gzPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open gz file: %v", err)
	}
	defer file.Close()

	// Create gzip reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return "", "", fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzReader.Close()

	// Create temporary file for decompressed content
	tempFile, err := os.CreateTemp("", "robocap-decompressed-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp file: %v", err)
	}
	tempPath := tempFile.Name()

	// Copy decompressed data to temp file
	_, err = io.Copy(tempFile, gzReader)
	tempFile.Close()
	if err != nil {
		os.Remove(tempPath)
		return "", "", fmt.Errorf("failed to decompress gz file: %v", err)
	}

	// Use the hint if provided
	var innerType string
	if innerTypeHint != "" {
		innerType = innerTypeHint
		log.Printf("Using provided inner type hint: %s", innerType)
	} else {
		// Detect the type of the decompressed file
		innerType, err = detectFileType(tempPath)
		if err != nil {
			// If detection fails, try to infer from the original filename
			baseName := filepath.Base(gzPath)
			baseName = strings.TrimSuffix(baseName, ".gz")
			baseExt := strings.ToLower(filepath.Ext(baseName))

			if baseExt == ".har" {
				innerType = "har"
			} else if baseExt == ".saz" {
				innerType = "saz"
			} else {
				os.Remove(tempPath)
				return "", "", fmt.Errorf("unable to determine inner file type: %v", err)
			}
		}
	}

	return tempPath, innerType, nil
}

func main() {
	// Parse command line flags
	flag.StringVar(&srcIP, "sip", "192.168.1.1", "Source IP address")
	flag.StringVar(&dstIP, "dip", "10.0.0.1", "Destination IP address")
	flag.IntVar(&srcPort, "sp", 12345, "Source port")
	flag.IntVar(&dstPort, "dp", 80, "Destination port")
	flag.StringVar(&outputPath, "o", "output.pcap", "Output PCAP file path")
	flag.StringVar(&inputPath, "i", "", "Input directory, SAZ, HAR, or GZ file")
	flag.BoolVar(&sazMode, "saz", false, "Input is a SAZ file (auto-detected if not specified)")
	flag.BoolVar(&harMode, "har", false, "Input is a HAR file (auto-detected if not specified)")
	flag.BoolVar(&gzMode, "gz", false, "Input is a gzipped file (auto-detected if not specified)")
	flag.BoolVar(&jsonOutput, "json", false, "Output session data as JSON")
	flag.BoolVar(&debugMode, "debug", false, "Enable debug logging")
	flag.BoolVar(&deProxy, "deproxy", false, "Remove proxy information from URLs")
	flag.BoolVar(&resolveHosts, "resolve", false, "Resolve hostnames to IP addresses via DNS (only applies when -deproxy is used)")
	flag.BoolVar(&http11, "http11", false, "Downgrade HTTP/2 to HTTP/1.1 and add Content-Length headers")
	flag.BoolVar(&split, "split", false, "Split output into separate files for HTTP and HTTPS")

	flag.Parse()

	// Validate input path
	if inputPath == "" {
		log.Fatal("Input path (-i) is required")
	}

	// Set up logging
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Auto-detect file type if not explicitly specified
	fileType := ""
	var innerTypeHint string // Hint for what's inside a gz file

	// Check if gz is used with saz or har flags
	if gzMode && (sazMode || harMode) {
		fileType = "gz"
		if sazMode {
			innerTypeHint = "saz"
			log.Printf("GZ mode with SAZ hint: file will be decompressed and treated as SAZ")
		} else if harMode {
			innerTypeHint = "har"
			log.Printf("GZ mode with HAR hint: file will be decompressed and treated as HAR")
		}
	} else if !sazMode && !harMode && !gzMode {
		detectedType, err := detectFileType(inputPath)
		if err != nil {
			log.Printf("Warning: could not auto-detect file type: %v, assuming directory mode", err)
			fileType = "dir"
		} else {
			fileType = detectedType
			log.Printf("Auto-detected file type: %s", fileType)
		}
	} else if sazMode {
		fileType = "saz"
	} else if harMode {
		fileType = "har"
	} else if gzMode {
		fileType = "gz"
	}

	// Process input based on detected or specified file type
	switch fileType {
	case "gz":
		// Decompress GZ file and process the inner content
		log.Printf("Decompressing GZ file: %s", inputPath)
		tempPath, innerType, err := decompressGZ(inputPath, innerTypeHint)
		if err != nil {
			log.Fatalf("Failed to decompress GZ file: %v", err)
		}
		defer os.Remove(tempPath)

		log.Printf("Detected inner file type: %s", innerType)

		// Process based on inner file type
		switch innerType {
		case "saz":
			// Extract SAZ file to a temporary directory
			tempDir, err := os.MkdirTemp("", "robocap")
			if err != nil {
				log.Fatalf("Failed to create temporary directory: %v", err)
			}
			defer os.RemoveAll(tempDir)

			log.Printf("Extracting SAZ file to: %s", tempDir)
			if err := extractSAZ(tempPath, tempDir); err != nil {
				log.Fatalf("Failed to extract SAZ file: %v", err)
			}

			// Process extracted sessions
			rawDir := filepath.Join(tempDir, "raw")
			sessions, err := ProcessSessions(rawDir, outputPath, deProxy, resolveHosts, http11, split, jsonOutput, debugMode, srcIP, dstIP)
			if err != nil {
				log.Fatalf("Failed to process sessions: %v", err)
			}

			// Log files created
			if split {
				fmt.Printf("Created: %s.http.pcap\n", outputPath)
				fmt.Printf("Created: %s.https.pcap\n", outputPath)
			} else {
				fmt.Printf("Created: %s\n", outputPath)
			}
			if jsonOutput {
				jsonPath := outputPath + ".json"
				fmt.Printf("Created: %s\n", jsonPath)
			}
			fmt.Printf("Processed %d sessions\n", len(sessions))

		case "har":
			// Process HAR file
			log.Printf("Processing HAR file from decompressed GZ")
			sessions, err := ProcessHAR(tempPath, outputPath, deProxy, resolveHosts, http11, debugMode, srcIP, dstIP)
			if err != nil {
				log.Fatalf("Failed to process HAR file: %v", err)
			}

			// Export to JSON if enabled
			if jsonOutput {
				jsonPath := outputPath + ".json"
				if err := exportToJSON(sessions, jsonPath); err != nil {
					log.Fatalf("Failed to export JSON: %v", err)
				}
			}

			// Log files created
			fmt.Printf("Created: %s\n", outputPath)
			if jsonOutput {
				jsonPath := outputPath + ".json"
				fmt.Printf("Created: %s\n", jsonPath)
			}
			fmt.Printf("Processed %d sessions\n", len(sessions))

		default:
			log.Fatalf("Unsupported inner file type in GZ: %s", innerType)
		}

	case "saz":
		// Extract SAZ file to a temporary directory
		tempDir, err := os.MkdirTemp("", "robocap")
		if err != nil {
			log.Fatalf("Failed to create temporary directory: %v", err)
		}
		defer os.RemoveAll(tempDir)

		log.Printf("Extracting SAZ file to: %s", tempDir)
		if err := extractSAZ(inputPath, tempDir); err != nil {
			log.Fatalf("Failed to extract SAZ file: %v", err)
		}

		// Process extracted sessions
		rawDir := filepath.Join(tempDir, "raw")
		sessions, err := ProcessSessions(rawDir, outputPath, deProxy, resolveHosts, http11, split, jsonOutput, debugMode, srcIP, dstIP)
		if err != nil {
			log.Fatalf("Failed to process sessions: %v", err)
		}

		// Log files created
		if split {
			fmt.Printf("Created: %s.http.pcap\n", outputPath)
			fmt.Printf("Created: %s.https.pcap\n", outputPath)
		} else {
			fmt.Printf("Created: %s\n", outputPath)
		}
		if jsonOutput {
			jsonPath := outputPath + ".json"
			fmt.Printf("Created: %s\n", jsonPath)
		}
		fmt.Printf("Processed %d sessions\n", len(sessions))

	case "har":
		// Process HAR file
		log.Printf("Processing HAR file: %s", inputPath)
		sessions, err := ProcessHAR(inputPath, outputPath, deProxy, resolveHosts, http11, debugMode, srcIP, dstIP)
		if err != nil {
			log.Fatalf("Failed to process HAR file: %v", err)
		}

		// Log files created
		fmt.Printf("Created: %s\n", outputPath)
		if jsonOutput {
			jsonPath := outputPath + ".json"
			fmt.Printf("Created: %s\n", jsonPath)
		}
		fmt.Printf("Processed %d sessions\n", len(sessions))

	case "dir", "":
		// Process raw directory
		log.Printf("Processing directory: %s", inputPath)
		sessions, err := ProcessSessions(inputPath, outputPath, deProxy, resolveHosts, http11, split, jsonOutput, debugMode, srcIP, dstIP)
		if err != nil {
			log.Fatalf("Failed to process sessions: %v", err)
		}

		// Log files created
		if split {
			fmt.Printf("Created: %s.http.pcap\n", outputPath)
			fmt.Printf("Created: %s.https.pcap\n", outputPath)
		} else {
			fmt.Printf("Created: %s\n", outputPath)
		}
		if jsonOutput {
			jsonPath := outputPath + ".json"
			fmt.Printf("Created: %s\n", jsonPath)
		}
		fmt.Printf("Processed %d sessions\n", len(sessions))

	default:
		log.Fatalf("Unsupported file type: %s", fileType)
	}

	// JSON export is now handled within the processing functions
}

// extractSAZ extracts a SAZ file to the specified directory
func extractSAZ(sazPath, outputDir string) error {
	// Open the SAZ file
	r, err := zip.OpenReader(sazPath)
	if err != nil {
		return fmt.Errorf("failed to open SAZ file: %v", err)
	}
	defer r.Close()

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Extract each file in the archive
	for _, f := range r.File {
		// Skip directories
		if f.FileInfo().IsDir() {
			continue
		}

		// Create the output file
		outputPath := filepath.Join(outputDir, f.Name)

		// Create parent directories if they don't exist
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory for %s: %v", f.Name, err)
		}

		// Open the file in the archive
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed to open file %s in archive: %v", f.Name, err)
		}

		// Create the output file
		outFile, err := os.Create(outputPath)
		if err != nil {
			rc.Close()
			return fmt.Errorf("failed to create output file %s: %v", outputPath, err)
		}

		// Copy the file contents
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return fmt.Errorf("failed to extract file %s: %v", f.Name, err)
		}

		// Set file permissions
		if err := os.Chmod(outputPath, f.Mode()); err != nil {
			return fmt.Errorf("failed to set permissions for %s: %v", outputPath, err)
		}

		// Set file modification time
		if !f.Modified.IsZero() {
			if err := os.Chtimes(outputPath, f.Modified, f.Modified); err != nil {
				return fmt.Errorf("failed to set modification time for %s: %v", outputPath, err)
			}
		}
	}

	return nil
}

// pcapWriters holds the PCAP writers and their associated file handles and buffers
type pcapWriters struct {
	http      *pcapgo.Writer
	https     *pcapgo.Writer
	httpFile  *os.File
	httpsFile *os.File
	httpBuf   *bufio.Writer
	httpsBuf  *bufio.Writer
}

// cleanup flushes and closes all writers and files
func (w *pcapWriters) cleanup() {
	// Flush and close HTTP buffer and file
	if w.httpBuf != nil {
		if err := w.httpBuf.Flush(); err != nil {
			log.Printf("Error flushing HTTP buffer: %v", err)
		}
	}
	if w.httpsBuf != nil {
		if err := w.httpsBuf.Flush(); err != nil {
			log.Printf("Error flushing HTTPS buffer: %v", err)
		}
	}

	// Close files
	if w.httpFile != nil {
		if err := w.httpFile.Sync(); err != nil {
			log.Printf("Error syncing HTTP file: %v", err)
		}
		if err := w.httpFile.Close(); err != nil {
			log.Printf("Error closing HTTP file: %v", err)
		}
	}

	if w.httpsFile != nil && w.httpsFile != w.httpFile { // Only close HTTPS file if it's different from HTTP file
		if err := w.httpsFile.Sync(); err != nil {
			log.Printf("Error syncing HTTPS file: %v", err)
		}
		if err := w.httpsFile.Close(); err != nil {
			log.Printf("Error closing HTTPS file: %v", err)
		}
	}
}

// parseMetadata parses the Fiddler session metadata file
type xmlMetadata struct {
	XMLName       xml.Name `xml:"Session"`
	SessionTimers struct {
		ClientBegin string `xml:"ClientBeginRequest,attr"`
		ClientDone  string `xml:"ClientDoneRequest,attr"`
		ServerBegin string `xml:"ServerBeginResponse,attr"`
		ServerDone  string `xml:"ServerDoneResponse,attr"`
	} `xml:"SessionTimers"`
	SessionFlags []struct {
		Name  string `xml:"N,attr"`
		Value string `xml:"V,attr"`
	} `xml:"SessionFlags>SessionFlag"`
}

// parseMetadata extracts metadata from a Fiddler session metadata file
func parseMetadata(metaPath string) (sessionMetadata, error) {
	var meta sessionMetadata
	var xmlMeta xmlMetadata

	// Read and parse the XML file
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return meta, fmt.Errorf("error reading metadata file: %v", err)
	}

	err = xml.Unmarshal(data, &xmlMeta)
	if err != nil {
		return meta, fmt.Errorf("error parsing metadata XML: %v", err)
	}

	// Extract metadata from session flags
	for _, flag := range xmlMeta.SessionFlags {
		switch flag.Name {
		case "x-clientip":
			meta.clientIP = flag.Value
		case "x-hostip":
			meta.hostIP = flag.Value
		case "x-clientport":
			if port, err := strconv.Atoi(flag.Value); err == nil {
				meta.srcPort = port
			}
		case "x-serverport":
			if port, err := strconv.Atoi(flag.Value); err == nil {
				meta.dstPort = port
			}
		}
	}

	return meta, nil
}

// collectSessionData gathers session data for JSON export
func collectSessionData(dirPath, sessionID string, meta sessionMetadata, reqData, respData []byte, xmlMeta xmlMetadata, http11, resolveHosts bool) SessionData {
	session := SessionData{
		RequestHeaders:     make(map[string]string),
		ResponseHeaders:    make(map[string]string),
		IsHTTP11Normalized: http11,
		IsDNSResolved:      resolveHosts,
		Metadata: struct {
			ClientIP   string `json:"client_ip,omitempty"`
			ClientPort int    `json:"client_port,omitempty"`
			ServerIP   string `json:"server_ip,omitempty"`
			ServerPort int    `json:"server_port,omitempty"`
			Protocol   string `json:"protocol,omitempty"`
			Timing     struct {
				ClientBegin string `json:"client_begin,omitempty"`
				ClientDone  string `json:"client_done,omitempty"`
				ServerBegin string `json:"server_begin,omitempty"`
				ServerDone  string `json:"server_done,omitempty"`
			} `json:"timing,omitempty"`
			Flags map[string]string `json:"flags,omitempty"`
		}{
			Flags: make(map[string]string),
		},
	}

	// For backward compatibility
	session.Request = string(reqData)

	// Add session flags to metadata
	for _, flag := range xmlMeta.SessionFlags {
		session.Metadata.Flags[flag.Name] = flag.Value
	}

	// Process request
	if len(reqData) > 0 {
		// Split request into headers and body
		reqHeaders, reqBody := splitHeadersAndBody(reqData)

		// Parse request line
		reqLines := bytes.SplitN(reqHeaders, []byte("\r\n"), 2)
		if len(reqLines) > 0 {
			reqParts := bytes.Fields(reqLines[0])
			if len(reqParts) >= 3 {
				session.Method = string(reqParts[0])
				urlStr := string(reqParts[1])
				session.URL = urlStr // Store the original URL
				session.Protocol = string(reqParts[2])

				// Parse the URL to extract components
				var parsedURL *url.URL
				var err error

				parsedURL, err = url.Parse(urlStr)
				if err != nil {
					// If parsing fails, try with a base URL for relative URLs
					parsedURL, _ = url.Parse("http://example.com" + urlStr)
				}

				// Set host and protocol if they're not set
				if parsedURL.Host != "" {
					session.Host = parsedURL.Host
					session.Metadata.Protocol = parsedURL.Scheme
				}

				// Ensure path starts with a forward slash
				path := parsedURL.Path
				if path == "" {
					path = "/"
				} else if !strings.HasPrefix(path, "/") {
					path = "/" + path
				}
				session.Path = path

				// Build the final URL with path and query
				urlStr = path
				if parsedURL.RawQuery != "" {
					urlStr += "?" + parsedURL.RawQuery
				}

				// Ensure URL starts with a forward slash
				session.URL = "/" + strings.TrimLeft(urlStr, "/")

				// Set protocol from URL if not set
				if session.Metadata.Protocol == "" {
					session.Metadata.Protocol = "http"
				}
			}
		}

		// Parse request headers
		if len(reqLines) > 1 {
			headerLines := bytes.Split(reqLines[1], []byte("\r\n"))
			for _, line := range headerLines {
				if len(line) == 0 {
					continue
				}
				if idx := bytes.IndexByte(line, ':'); idx > 0 {
					header := string(bytes.TrimSpace(line[:idx]))
					value := string(bytes.TrimSpace(line[idx+1:]))
					session.RequestHeaders[header] = value
				}
			}
		}

		// Process request body
		if len(reqBody) > 0 {
			if isBinaryData(reqBody) {
				session.IsReqBinary = true
				session.RequestBody = base64.StdEncoding.EncodeToString(reqBody)
			} else {
				session.RequestBody = string(reqBody)
			}
		}

		// If we still don't have a host, try to get it from Host header
		if session.Host == "" {
			if host, ok := session.RequestHeaders["Host"]; ok {
				session.Host = host
			}
		}
	}

	// Process response
	if len(respData) > 0 {
		// For backward compatibility
		session.Response = string(respData)

		// Split response into headers and body
		respHeaders, respBody := splitHeadersAndBody(respData)

		// Parse status line
		if len(respHeaders) > 0 {
			respLines := bytes.SplitN(respHeaders, []byte("\r\n"), 2)
			if len(respLines) > 0 {
				statusParts := bytes.Fields(respLines[0])
				if len(statusParts) >= 2 {
					if status, err := strconv.Atoi(string(statusParts[1])); err == nil {
						session.Status = status
					}
				}
			}

			// Parse response headers
			if len(respLines) > 1 {
				headerLines := bytes.Split(respLines[1], []byte("\r\n"))
				for _, line := range headerLines {
					if len(line) == 0 {
						continue
					}
					if idx := bytes.IndexByte(line, ':'); idx > 0 {
						header := string(bytes.TrimSpace(line[:idx]))
						value := string(bytes.TrimSpace(line[idx+1:]))
						session.ResponseHeaders[header] = value
					}
				}
			}
		}

		// Process response body
		if len(respBody) > 0 {
			if isBinaryData(respBody) {
				session.IsRespBinary = true
				session.IsBinary = true // For backward compatibility
				session.ResponseBody = base64.StdEncoding.EncodeToString(respBody)
			} else {
				session.ResponseBody = string(respBody)
			}
		}
	}

	// Add metadata
	session.Metadata.ClientIP = meta.clientIP
	session.Metadata.ClientPort = meta.srcPort
	session.Metadata.ServerIP = meta.hostIP
	session.Metadata.ServerPort = meta.dstPort

	// Add timing information if available
	if xmlMeta.SessionTimers.ClientBegin != "" {
		session.Metadata.Timing.ClientBegin = xmlMeta.SessionTimers.ClientBegin
	}
	if xmlMeta.SessionTimers.ClientDone != "" {
		session.Metadata.Timing.ClientDone = xmlMeta.SessionTimers.ClientDone
	}
	if xmlMeta.SessionTimers.ServerBegin != "" {
		session.Metadata.Timing.ServerBegin = xmlMeta.SessionTimers.ServerBegin
	}
	if xmlMeta.SessionTimers.ServerDone != "" {
		session.Metadata.Timing.ServerDone = xmlMeta.SessionTimers.ServerDone
	}

	return session
}

// isBinaryData checks if the given data contains binary content
func isBinaryData(data []byte) bool {
	for _, b := range data {
		if b < 32 && b != '\t' && b != '\n' && b != '\r' {
			return true
		}
	}
	return false
}

// splitHeadersAndBody splits raw HTTP data into headers and body
func splitHeadersAndBody(data []byte) ([]byte, []byte) {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return data, nil
	}
	headers := data[:headerEnd+2] // Include the first \r\n
	body := data[headerEnd+4:]    // Skip the \r\n\r\n
	return headers, body
}
