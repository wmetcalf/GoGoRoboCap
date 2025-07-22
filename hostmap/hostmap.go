package hostmap

import (
	"strings"
	"sync"
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
