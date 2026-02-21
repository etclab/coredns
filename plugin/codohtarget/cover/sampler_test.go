package cover

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func writeTestCSV(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.csv")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := 1; i <= n; i++ {
		_, _ = f.WriteString(fmt.Sprintf("%d,domain%d.com\n", i, i))
	}
	return path
}

func TestSampler_PopularRatio(t *testing.T) {
	path := writeTestCSV(t, 20000)
	s, err := NewSampler(path, 10000, 0.8)
	if err != nil {
		t.Fatal(err)
	}

	popularSet := make(map[string]struct{}, 10000)
	for _, d := range s.popular {
		popularSet[d] = struct{}{}
	}

	popularCount := 0
	total := 10000
	for i := 0; i < total; i++ {
		samples := s.Sample(1, "")
		if len(samples) != 1 {
			t.Fatalf("expected 1 sample, got %d", len(samples))
		}
		if _, ok := popularSet[samples[0]]; ok {
			popularCount++
		}
	}

	ratio := float64(popularCount) / float64(total)
	// 80% ± 3% (binomial 99% CI for n=10000, p=0.8)
	if math.Abs(ratio-0.8) > 0.03 {
		t.Errorf("popular ratio %.4f outside 0.77-0.83", ratio)
	}
}

func TestSampler_NoDuplicates(t *testing.T) {
	path := writeTestCSV(t, 1000)
	s, err := NewSampler(path, 500, 0.5)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		samples := s.Sample(10, "")
		seen := make(map[string]struct{})
		for _, d := range samples {
			if _, ok := seen[d]; ok {
				t.Fatalf("duplicate domain: %s", d)
			}
			seen[d] = struct{}{}
		}
	}
}

func TestSampler_ExcludeDomain(t *testing.T) {
	path := writeTestCSV(t, 100)
	s, err := NewSampler(path, 50, 0.5)
	if err != nil {
		t.Fatal(err)
	}

	exclude := "domain1.com"
	for i := 0; i < 200; i++ {
		samples := s.Sample(10, exclude)
		for _, d := range samples {
			if d == exclude {
				t.Fatalf("excluded domain %q appeared in sample", exclude)
			}
		}
	}
}

func TestSampler_EmptyLongTail(t *testing.T) {
	path := writeTestCSV(t, 50)
	// cutoff >= list length → all popular
	s, err := NewSampler(path, 100, 0.8)
	if err != nil {
		t.Fatal(err)
	}

	if len(s.longTail) != 0 {
		t.Errorf("expected empty long-tail, got %d", len(s.longTail))
	}

	// Should still sample without panic
	samples := s.Sample(5, "")
	if len(samples) != 5 {
		t.Errorf("expected 5 samples, got %d", len(samples))
	}
}

func TestSampler_KExceedsAvailable(t *testing.T) {
	path := writeTestCSV(t, 5)
	s, err := NewSampler(path, 3, 0.5)
	if err != nil {
		t.Fatal(err)
	}

	// k=10 but only 5 domains available
	samples := s.Sample(10, "")
	if len(samples) != 5 {
		t.Errorf("expected 5 samples (capped), got %d", len(samples))
	}

	// k=10 with exclude, only 4 available
	samples = s.Sample(10, "domain1.com")
	if len(samples) != 4 {
		t.Errorf("expected 4 samples (capped with exclude), got %d", len(samples))
	}
}
