package enclave

// Config holds enclave configuration.
type Config struct {
	SocketPath     string // Default: /tmp/codoh-enclave.sock
	CacheSize      int    // Default: 10000 entries
	UseORAMCache   bool   // Use ORAM-backed cache (default: false)
	ORAMBlockSize  int    // ORAM block size in bytes (default: 4096)
	DefaultPadSize int    // Default dummy response size (default: 512)
}

// DefaultConfig returns configuration with default values.
func DefaultConfig() *Config {
	return &Config{
		SocketPath:     "/tmp/codoh-enclave.sock",
		CacheSize:      10000,
		UseORAMCache:   false,
		ORAMBlockSize:  4096,
		DefaultPadSize: 512,
	}
}

