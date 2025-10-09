# GoGoRoboCap https://suno.com/s/htoKG4s1YYRrvjzk
Go Based Conversion From HAR/SAZ files to PCAP. It should be faster than Scapy-based tools of the past.
<img width="1024" height="1024" alt="robocap2" src="https://github.com/user-attachments/assets/1a3143fb-ef8e-4797-82af-6e156a7fb6dc" />

## Features

- Convert HAR (HTTP Archive) and SAZ (Fiddler) files to PCAP format
- Automatic file type detection
- De-proxy URLs to convert proxy-style requests to standard HTTP requests
- Optional DNS hostname resolution for accurate destination IPs
- HTTP/2 to HTTP/1.1 normalization for compatibility
- Split HTTP and HTTPS traffic into separate PCAP files
- JSON metadata export for session analysis
- Debug mode for troubleshooting conversions

## Usage

```
Usage of gogorobocap:
  -debug
    	Enable debug logging
  -deproxy
    	Remove proxy information from URLs
  -dip string
    	Destination IP address (default "10.0.0.1")
  -dp int
    	Destination port (default 80)
  -gz
    	Input is a gzipped file (auto-detected if not specified)
  -har
    	Input is a HAR file (auto-detected if not specified)
  -http11
    	Normalize HTTP/2 to HTTP/1.1 and add Content-Length headers
  -i string
    	Input directory, SAZ, or HAR file (required)
  -json
    	Output session data as JSON
  -o string
    	Output PCAP file path (default "output.pcap")
  -resolve
    	Resolve hostnames to IP addresses via DNS (only applies when -deproxy is used)
  -saz
    	Input is a SAZ file (auto-detected if not specified)
  -sip string
    	Source IP address (default "192.168.1.1")
  -sp int
    	Source port (default 12345)
  -split
    	Split output into separate files for HTTP and HTTPS
```

## Examples

### Basic HAR Conversion
Convert a HAR file to PCAP with automatic detection:
```bash
./gogorobocap-linux-amd64 -i recording.har
```

Output:
```
Auto-detected file type: har
Processing HAR file: recording.har
Created: output.pcap
Processed 88 sessions
```

### SAZ (Fiddler) Conversion
Convert a Fiddler SAZ file to PCAP:
```bash
./gogorobocap-linux-amd64 -i capture.saz -o output.pcap
```

### Gzipped File Conversion
Process gzipped HAR or SAZ files (auto-detection):
```bash
./gogorobocap-linux-amd64 -i recording.har.gz
```

With explicit type specification:
```bash
./gogorobocap-linux-amd64 -i recording.har.gz --gz --har
./gogorobocap-linux-amd64 -i capture.saz.gz --gz --saz
```

### De-proxying URLs
Remove proxy information from URLs (convert `GET http://example.com/path` to `GET /path`):
```bash
./gogorobocap-linux-amd64 -i recording.har --deproxy
```

### HTTP/1.1 Normalization
Normalize HTTP/2 requests to HTTP/1.1 and ensure Content-Length headers are present:
```bash
./gogorobocap-linux-amd64 -i recording.har --http11
```

This is useful for:
- Tools that don't support HTTP/2
- Handling fake HTTP/2 requests in HAR files that lack proper headers

### DNS Resolution
By default, the tool uses data from the HAR/SAZ file or the default destination IP. To enable DNS resolution of hostnames to actual IP addresses:
```bash
./gogorobocap-linux-amd64 -i recording.har --deproxy --resolve
```

Without the `--resolve` flag (default behavior - uses HAR/SAZ data):
```bash
./gogorobocap-linux-amd64 -i recording.har --deproxy
```

### Custom IP and Port Configuration
Specify custom source and destination IPs/ports:
```bash
./gogorobocap-linux-amd64 -i recording.har \
  -sip 192.168.100.50 \
  -dip 10.20.30.40 \
  -sp 54321 \
  -dp 443
```

### Split HTTP and HTTPS Traffic
Create separate PCAP files for HTTP and HTTPS traffic:
```bash
./gogorobocap-linux-amd64 -i recording.har -split
```

This creates:
- `output.pcap.http.pcap` - HTTP traffic only
- `output.pcap.https.pcap` - HTTPS traffic only

### JSON Metadata Export
Export session metadata to JSON for analysis:
```bash
./gogorobocap-linux-amd64 -i recording.har -json
```

This creates:
- `output.pcap` - The PCAP file
- `output.pcap.json` - JSON metadata with request/response details

### Debug Mode
Enable detailed logging to troubleshoot conversion issues:
```bash
./gogorobocap-linux-amd64 -i recording.har --debug
```

### Complete Example
Convert a HAR file with all common options:
```bash
./gogorobocap-linux-amd64 \
  -i recording.har \
  -o traffic.pcap \
  --deproxy \
  --http11 \
  -json \
  -sip 192.168.1.100 \
  -dip 10.0.0.50
```

This will:
- Convert `recording.har` to PCAP
- Remove proxy information from URLs
- Normalize HTTP/2 to HTTP/1.1
- Use data from the HAR file (no DNS resolution)
- Export JSON metadata
- Use custom source/destination IPs
- Create `traffic.pcap` and `traffic.pcap.json`

## Installation

Download the appropriate build for your system:
- `gogorobocap-linux-amd64` - Linux (Intel/AMD)
- `gogorobocap-darwin-amd64` - macOS (Intel)
- `gogorobocap-darwin-arm64` - macOS (Apple Silicon)
- `gogorobocap-windows-amd64.exe` - Windows

Make it executable (Linux/macOS):
```bash
chmod +x gogorobocap-linux-amd64
```

## Building from Source

```bash
go build -o gogorobocap
```
