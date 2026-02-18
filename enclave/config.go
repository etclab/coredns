package enclave

import (
	"os"
	"strconv"
	"time"
)

// Config holds enclave configuration.
type Config struct {
	SocketPath    string // Default: /tmp/codoh-enclave.sock
	CacheSize     int    // Default: 10000 entries
	UseORAMCache  bool   // Use ORAM-backed cache (default: false)
	ORAMBlockSize int    // ORAM block size in bytes (default: 4096)
	DefaultPadSize int   // Default dummy response size (default: 512)

	// Churn defense (orthogonal to batching)
	ChurnInterval time.Duration
	ChurnEnabled  bool
}

// DefaultConfig returns configuration with default values.
func DefaultConfig() *Config {
	return &Config{
		SocketPath:     "/tmp/codoh-enclave.sock",
		CacheSize:      10000,
		UseORAMCache:   false,
		ORAMBlockSize:  4096,
		DefaultPadSize: 512,
		ChurnInterval:  0,
		ChurnEnabled:   false,
	}
}

// LoadConfigFromEnv loads configuration from environment variables.
func LoadConfigFromEnv() (*Config, error) {
	cfg := DefaultConfig()

	if path := os.Getenv("CODOH_SOCKET_PATH"); path != "" {
		cfg.SocketPath = path
	}

	if size := os.Getenv("CODOH_CACHE_SIZE"); size != "" {
		n, err := strconv.Atoi(size)
		if err != nil {
			return nil, err
		}
		cfg.CacheSize = n
	}

	if useORAM := os.Getenv("CODOH_USE_ORAM"); useORAM != "" {
		cfg.UseORAMCache = useORAM == "true" || useORAM == "1"
	}

	if blockSize := os.Getenv("CODOH_ORAM_BLOCK_SIZE"); blockSize != "" {
		n, err := strconv.Atoi(blockSize)
		if err != nil {
			return nil, err
		}
		cfg.ORAMBlockSize = n
	}

	if padSize := os.Getenv("CODOH_DEFAULT_PAD_SIZE"); padSize != "" {
		n, err := strconv.Atoi(padSize)
		if err != nil {
			return nil, err
		}
		cfg.DefaultPadSize = n
	}

	if interval := os.Getenv("CODOH_CHURN_INTERVAL_SECS"); interval != "" {
		secs, err := strconv.Atoi(interval)
		if err != nil {
			return nil, err
		}
		cfg.ChurnInterval = time.Duration(secs) * time.Second
	}

	if churn := os.Getenv("CODOH_CHURN_ENABLED"); churn != "" {
		cfg.ChurnEnabled = churn == "true" || churn == "1"
	}

	return cfg, nil
}
