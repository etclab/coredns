package enclave

import (
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"time"
)

// Config holds enclave configuration.
type Config struct {
	MasterSecret   []byte        // Shared with target (32 bytes)
	EpochDuration  time.Duration // Default: 1 hour
	SocketPath     string        // Default: /tmp/codoh-enclave.sock
	CacheSize      int           // Default: 10000 entries
	UseORAMCache   bool          // Use ORAM-backed cache (default: false)
	ORAMBlockSize  int           // ORAM block size in bytes (default: 4096)

	// Stochastic cache defenses
	HitSuppressionProb float64       // Probability of suppressing cache hits [0.0, 1.0]
	InsertProb         float64       // Probability of inserting into cache [0.0, 1.0]
	ChurnInterval      time.Duration // Interval for random churn
	ChurnEnabled       bool          // Whether churn is enabled
}

// DefaultConfig returns configuration with default values.
func DefaultConfig() *Config {
	return &Config{
		EpochDuration:      time.Hour,
		SocketPath:         "/tmp/codoh-enclave.sock",
		CacheSize:          10000,
		UseORAMCache:       false,
		ORAMBlockSize:      4096,
		HitSuppressionProb: 0.0,
		InsertProb:         1.0,
		ChurnInterval:      0,
		ChurnEnabled:       false,
	}
}

// LoadConfigFromEnv loads configuration from environment variables.
// Environment variables:
//   - CODOH_MASTER_SECRET: hex-encoded 32-byte master secret (required)
//   - CODOH_EPOCH_DURATION: epoch duration in seconds (default: 3600)
//   - CODOH_SOCKET_PATH: Unix socket path (default: /tmp/codoh-enclave.sock)
//   - CODOH_CACHE_SIZE: cache size in entries (default: 10000)
//   - CODOH_USE_ORAM: use ORAM-backed cache (default: false)
//   - CODOH_ORAM_BLOCK_SIZE: ORAM block size in bytes (default: 4096)
func LoadConfigFromEnv() (*Config, error) {
	cfg := DefaultConfig()

	// Master secret (required)
	secretHex := os.Getenv("CODOH_MASTER_SECRET")
	if secretHex == "" {
		return nil, errors.New("CODOH_MASTER_SECRET environment variable is required")
	}
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, errors.New("CODOH_MASTER_SECRET must be hex-encoded")
	}
	if len(secret) != 32 {
		return nil, errors.New("CODOH_MASTER_SECRET must be 32 bytes")
	}
	cfg.MasterSecret = secret

	// Epoch duration (optional)
	if dur := os.Getenv("CODOH_EPOCH_DURATION"); dur != "" {
		secs, err := strconv.Atoi(dur)
		if err != nil {
			return nil, errors.New("CODOH_EPOCH_DURATION must be an integer (seconds)")
		}
		cfg.EpochDuration = time.Duration(secs) * time.Second
	}

	// Socket path (optional)
	if path := os.Getenv("CODOH_SOCKET_PATH"); path != "" {
		cfg.SocketPath = path
	}

	// Cache size (optional)
	if size := os.Getenv("CODOH_CACHE_SIZE"); size != "" {
		n, err := strconv.Atoi(size)
		if err != nil {
			return nil, errors.New("CODOH_CACHE_SIZE must be an integer")
		}
		cfg.CacheSize = n
	}

	// Use ORAM cache (optional)
	if useORAM := os.Getenv("CODOH_USE_ORAM"); useORAM != "" {
		cfg.UseORAMCache = useORAM == "true" || useORAM == "1"
	}

	// ORAM block size (optional)
	if blockSize := os.Getenv("CODOH_ORAM_BLOCK_SIZE"); blockSize != "" {
		n, err := strconv.Atoi(blockSize)
		if err != nil {
			return nil, errors.New("CODOH_ORAM_BLOCK_SIZE must be an integer")
		}
		cfg.ORAMBlockSize = n
	}

	// Stochastic cache defenses
	if p := os.Getenv("CODOH_HIT_SUPPRESSION_PROB"); p != "" {
		prob, err := strconv.ParseFloat(p, 64)
		if err != nil || prob < 0.0 || prob > 1.0 {
			return nil, errors.New("CODOH_HIT_SUPPRESSION_PROB must be float [0.0, 1.0]")
		}
		cfg.HitSuppressionProb = prob
	}

	if p := os.Getenv("CODOH_INSERT_PROB"); p != "" {
		prob, err := strconv.ParseFloat(p, 64)
		if err != nil || prob < 0.0 || prob > 1.0 {
			return nil, errors.New("CODOH_INSERT_PROB must be float [0.0, 1.0]")
		}
		cfg.InsertProb = prob
	}

	if interval := os.Getenv("CODOH_CHURN_INTERVAL_SECS"); interval != "" {
		secs, err := strconv.Atoi(interval)
		if err != nil {
			return nil, errors.New("CODOH_CHURN_INTERVAL_SECS must be integer")
		}
		cfg.ChurnInterval = time.Duration(secs) * time.Second
	}

	if churn := os.Getenv("CODOH_CHURN_ENABLED"); churn != "" {
		cfg.ChurnEnabled = churn == "true" || churn == "1"
	}

	return cfg, nil
}

// LoadConfigFromFile loads master secret from a file.
// File format: hex-encoded 32-byte secret (64 characters).
func LoadMasterSecretFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Trim whitespace
	secretHex := string(data)
	for len(secretHex) > 0 && (secretHex[len(secretHex)-1] == '\n' || secretHex[len(secretHex)-1] == '\r') {
		secretHex = secretHex[:len(secretHex)-1]
	}

	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, errors.New("master secret file must contain hex-encoded data")
	}
	if len(secret) != 32 {
		return nil, errors.New("master secret must be 32 bytes")
	}

	return secret, nil
}
