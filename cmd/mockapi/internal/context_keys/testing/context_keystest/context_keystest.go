package context_keystest

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
)

type Events []*Event

type Event struct {
	raw        string
	attributes map[string]any
}

type Harness struct {
	mx  sync.RWMutex
	buf []byte
	cnt int
}

func New() *Harness {
	return &Harness{
		buf: []byte{},
	}
}

func (h *Harness) Reset() {
	h.mx.Lock()
	defer h.mx.Unlock()

	h.cnt = 0
	h.buf = []byte{}
}

func (h *Harness) Write(p []byte) (n int, err error) {
	h.mx.Lock()
	defer h.mx.Unlock()

	h.cnt++
	h.buf = append(h.buf, p...)
	return len(p), nil
}

// Len returns number of log messages written to the Harness.
func (h *Harness) Len() int {
	return h.cnt
}

// Events returns number of log messages written to the Harness.
func (h *Harness) Events(t *testing.T) Events {
	t.Helper()
	h.mx.RLock()
	defer h.mx.RUnlock()

	ets := make([]*Event, 0, h.cnt)

	var off int64
	dec := json.NewDecoder(bytes.NewReader(h.buf))
	dec.DisallowUnknownFields()
	for dec.More() {
		m := make(map[string]any)
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
			return Events{}
		}

		tmp := h.buf[off:dec.InputOffset()]
		off = dec.InputOffset()
		ets = append(ets, &Event{
			raw:        string(bytes.TrimSpace(tmp)),
			attributes: m,
		})
	}

	return ets
}

// AssertKey checks for the existence of a given key within the log
// if the key is not found errors on the *testing.T and logs the entry
func (e *Event) AssertKey(t *testing.T, key string) {
	t.Helper()
	if _, ok := e.attributes[key]; !ok {
		t.Errorf("key: %s not found", key)
	}
}

// AssertKeyValue checks for the existence of a given key within the log
// and that the key value matches for the log entry
func (e *Event) AssertKeyValue(t *testing.T, key string, value any) {
	t.Helper()
	if _, ok := e.attributes[key]; !ok {
		t.Fatalf("key: %s not found", key)
	}
	val := e.attributes[key]
	if val != value {
		t.Errorf("found value %v does not match expected value of %v", val, value)
	}
}

// String returns the raw message
func (e *Event) String() string {
	return e.raw
}

// Key returns the value of a given key
func (e *Event) Key(t *testing.T, key string) any {
	t.Helper()
	if value, ok := e.attributes[key]; ok {
		return value
	}
	t.Fatalf("key %s not found", key)
	return nil
}
