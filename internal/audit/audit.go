package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Record is one append-only JSONL audit event.
type Record struct {
	Event       string `json:"event"`
	At          string `json:"at"`
	RequestID   string `json:"request_id,omitempty"`
	RequestHash string `json:"request_hash,omitempty"`
	Actor       string `json:"actor,omitempty"`
	Status      string `json:"status,omitempty"`
	Details     any    `json:"details,omitempty"`
}

// Logger appends audit records to a local trusted file.
type Logger struct {
	Path string
}

// Append writes one JSON line. It creates the parent directory with owner-only
// permissions; deployment should still ensure Donna cannot write this path.
func (l Logger) Append(record Record) error {
	if l.Path == "" {
		return nil
	}
	if record.At == "" {
		record.At = time.Now().UTC().Format(time.RFC3339)
	}
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return fmt.Errorf("create audit dir: %w", err)
	}
	f, err := os.OpenFile(l.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal audit record: %w", err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}
