package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// RecordEntry is one replayed provider outcome. `assistant_content` is the
// model text returned on a 2xx; `http_status` and `error_class` select a
// failure. `command` matches a request; an entry without a command is used in
// file order.
type RecordEntry struct {
	Command          string `json:"command,omitempty"`
	HTTPStatus       int    `json:"http_status,omitempty"`
	AssistantContent string `json:"assistant_content,omitempty"`
	Body             string `json:"body,omitempty"`
	Refusal          bool   `json:"refusal,omitempty"`
	ErrorClass       string `json:"error_class,omitempty"`
	ErrorMessage     string `json:"error_message,omitempty"`
	Retryable        *bool  `json:"retryable,omitempty"`
	Usage            *Usage `json:"usage,omitempty"`
}

// Record replays recorded provider outcomes. It is the offline parity path:
// record live 2xx/assistant bodies once, then rerun the corpus without a model.
type Record struct {
	mu      sync.Mutex
	entries []RecordEntry
	used    []bool
}

// LoadRecord reads JSONL entries from r.
func LoadRecord(r *os.File) (*Record, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var entries []RecordEntry
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var entry RecordEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, fmt.Errorf("record line %d: %w", line, err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("record file %s has no entries", r.Name())
	}
	return &Record{entries: entries, used: make([]bool, len(entries))}, nil
}

// LoadRecordFile opens and loads a record file.
func LoadRecordFile(path string) (*Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return LoadRecord(file)
}

// Complete implements Provider.
func (r *Record) Complete(_ context.Context, req Request) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	index := -1
	if req.Command != "" {
		for i, entry := range r.entries {
			if !r.used[i] && entry.Command == req.Command {
				index = i
				break
			}
		}
	}
	if index == -1 {
		for i := range r.entries {
			if !r.used[i] {
				index = i
				break
			}
		}
	}
	if index == -1 {
		return Result{}, &Error{
			Class:   "internal",
			Message: fmt.Sprintf("no recorded response left for command %q", req.Command),
		}
	}
	r.used[index] = true
	entry := r.entries[index]

	if entry.ErrorClass != "" {
		retryable := false
		if entry.Retryable != nil {
			retryable = *entry.Retryable
		}
		return Result{}, &Error{
			Class:     entry.ErrorClass,
			Message:   entry.ErrorMessage,
			Retryable: retryable,
		}
	}
	if entry.HTTPStatus >= 400 {
		return Result{}, classifyStatus(entry.HTTPStatus)
	}
	if entry.Refusal {
		return Result{Refusal: true}, nil
	}
	content := entry.AssistantContent
	if content == "" {
		content = entry.Body
	}
	result := Result{Content: content}
	if entry.Usage != nil {
		result.Usage = *entry.Usage
	}
	return result, nil
}
