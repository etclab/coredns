package enclave

import (
	"fmt"
	"sync"
	"testing"
)

func TestInsertionQueue_EnqueueDrainFIFO(t *testing.T) {
	q := NewInsertionQueue(100)

	for i := 0; i < 10; i++ {
		q.Enqueue(PendingInsert{Query: fmt.Sprintf("q%d", i), InsertedAt: int64(i)})
	}
	if q.Len() != 10 {
		t.Fatalf("expected len=10, got %d", q.Len())
	}

	batch := q.DrainBatch(5)
	if len(batch) != 5 {
		t.Fatalf("expected 5 drained, got %d", len(batch))
	}
	// First 5 returned in FIFO order
	for i := 0; i < 5; i++ {
		expected := fmt.Sprintf("q%d", i)
		if batch[i].Query != expected {
			t.Fatalf("batch[%d].Query=%s, want %s", i, batch[i].Query, expected)
		}
	}
	// 5 remain
	if q.Len() != 5 {
		t.Fatalf("expected 5 remaining, got %d", q.Len())
	}
}

func TestInsertionQueue_HeadDropOnOverflow(t *testing.T) {
	q := NewInsertionQueue(5)

	for i := 0; i < 5; i++ {
		evicted := q.Enqueue(PendingInsert{Query: fmt.Sprintf("q%d", i)})
		if evicted {
			t.Fatalf("should not evict when not full (i=%d)", i)
		}
	}

	// 6th entry → evicts oldest (q0)
	evicted := q.Enqueue(PendingInsert{Query: "q5"})
	if !evicted {
		t.Fatal("expected eviction on overflow")
	}
	if q.Len() != 5 {
		t.Fatalf("expected len=5 after overflow, got %d", q.Len())
	}

	// Drain all — should be q1..q5 (q0 evicted)
	batch := q.DrainBatch(10)
	if len(batch) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(batch))
	}
	if batch[0].Query != "q1" {
		t.Fatalf("oldest should be q1 after eviction, got %s", batch[0].Query)
	}
	if batch[4].Query != "q5" {
		t.Fatalf("newest should be q5, got %s", batch[4].Query)
	}
}

func TestInsertionQueue_DrainMoreThanLen(t *testing.T) {
	q := NewInsertionQueue(100)

	q.Enqueue(PendingInsert{Query: "only"})
	batch := q.DrainBatch(50)
	if len(batch) != 1 {
		t.Fatalf("expected 1, got %d", len(batch))
	}
	if batch[0].Query != "only" {
		t.Fatalf("expected 'only', got %s", batch[0].Query)
	}
	if q.Len() != 0 {
		t.Fatalf("expected empty after drain, got %d", q.Len())
	}
}

func TestInsertionQueue_DrainEmpty(t *testing.T) {
	q := NewInsertionQueue(100)
	batch := q.DrainBatch(10)
	if batch != nil {
		t.Fatalf("expected nil from empty queue, got %v", batch)
	}
}

func TestInsertionQueue_ConcurrentAccess(t *testing.T) {
	q := NewInsertionQueue(1000)
	var wg sync.WaitGroup

	// 50 goroutines enqueue
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				q.Enqueue(PendingInsert{Query: fmt.Sprintf("g%d-q%d", idx, j)})
			}
		}(i)
	}

	// 10 goroutines drain
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				q.DrainBatch(5)
			}
		}()
	}

	wg.Wait()
	// No panic, no race → pass. Queue state is indeterminate but valid.
	t.Logf("final queue length: %d", q.Len())
}
