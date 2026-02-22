package enclave

// Config holds enclave configuration.
type Config struct {
	SocketPath     string  // Default: /tmp/codoh-enclave.sock
	CacheSize      int     // Default: 10000 entries
	UseORAMCache  bool    // Use ORAM-backed cache (default: false)
	ORAMBlockSize int     // ORAM block size in bytes (default: 4096)
	PadBuckets    []int   // Padding bucket sizes in bytes (default: [16384])
	ReplayDelta   float64 // δ in seconds for replay protection (default: 3.0)

	// Defensive mode configuration
	WarmupThreshold    int     // Cache entries needed to exit defensive mode (default: 100)
	OmissionThreshold  int     // Outstanding queries to trigger defensive mode (default: 50)
	OutstandingTTLSecs int // Logical-time window in seconds for outstanding entry eviction (default: 300)

	// Batched cache updates (Sprint 4)
	BatchSize       int     // Entries per batch commit (default: 10)
	BatchCommitProb float64 // Probability of commit per HandleProcess (default: 0.1)
	QueueMaxSize    int     // Max pending inserts in queue (default: 1000)
}

// DefaultConfig returns configuration with default values.
func DefaultConfig() *Config {
	return &Config{
		SocketPath:         "/tmp/codoh-enclave.sock",
		CacheSize:          10000,
		UseORAMCache:       false,
		ORAMBlockSize:      4096,
		PadBuckets:         []int{16384},
		ReplayDelta:        3.0,
		WarmupThreshold:    100,
		OmissionThreshold:  50,
		OutstandingTTLSecs: 300,
		BatchSize:          10,
		BatchCommitProb:    0.1,
		QueueMaxSize:       1000,
	}
}

