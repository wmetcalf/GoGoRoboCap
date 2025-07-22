# GoGoRoboCap https://suno.com/s/htoKG4s1YYRrvjzk
Go Based Conversion From HAR/SAZ files to PCAP. It should be faster than Scapy-based tools of the past. 
<img width="1024" height="1024" alt="robocap2" src="https://github.com/user-attachments/assets/1a3143fb-ef8e-4797-82af-6e156a7fb6dc" />

```
./builds/gogorobocap-linux-amd64 -i '/home/coz/Downloads/recording (28).har'  --deproxy 
2025/07/21 23:22:27.971822 Auto-detected file type: har
2025/07/21 23:22:27.971906 Processing HAR file: /home/coz/Downloads/recording (28).har
Created: output.pcap
Processed 88 sessions
coz@genesis:~/GoGoRoboCap$ ./builds/gogorobocap-linux-amd64 --help
Usage of ./builds/gogorobocap-linux-amd64:
  -debug
    	Enable debug logging
  -deproxy
    	Remove proxy information from URLs
  -dip string
    	Destination IP address (default "10.0.0.1")
  -dp int
    	Destination port (default 80)
  -har
    	Input is a HAR file (auto-detected if not specified)
  -i string
    	Input directory, SAZ, or HAR file
  -json
    	Output session data as JSON
  -o string
    	Output PCAP file path (default "output.pcap")
  -saz
    	Input is a SAZ file (auto-detected if not specified)
  -sip string
    	Source IP address (default "192.168.1.1")
  -sp int
    	Source port (default 12345)
  -split
    	Split output into separate files for HTTP and HTTPS
```
