package enclave

// Config holds enclave configuration.
type Config struct {
	SocketPath     string  // Default: /tmp/codoh-enclave.sock
	CacheSize      int     // Default: 10000 entries
	UseORAMCache   bool    // Use ORAM-backed cache (default: false)
	ORAMBlockSize  int     // ORAM block size in bytes (default: 4096)
	DefaultPadSize int     // Default dummy response size (default: 512)
	ReplayDelta    float64 // δ in seconds for replay protection (default: 3.0)

	// Defensive mode configuration
	WarmupThreshold    int     // Cache entries needed to exit defensive mode (default: 100)
	OmissionThreshold  int     // Outstanding queries to trigger defensive mode (default: 50)
	OutstandingTTLSecs int // Logical-time window in seconds for outstanding entry eviction (default: 300)
}

// DefaultConfig returns configuration with default values.
func DefaultConfig() *Config {
	return &Config{
		SocketPath:         "/tmp/codoh-enclave.sock",
		CacheSize:          10000,
		UseORAMCache:       false,
		ORAMBlockSize:      4096,
		DefaultPadSize:     512,
		ReplayDelta:        3.0,
		WarmupThreshold:    100,
		OmissionThreshold:  50,
		OutstandingTTLSecs: 300,
	}
}

