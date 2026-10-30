package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Recorder wraps a provider and writes each outcome as a RecordEntry JSONL
// line. A recorded live run can then be replayed offline with Record.
type Recorder struct {
	Inner  Provider
	Writer io.Writer
	mu     sync.Mutex
}

// NewRecorder returns a recording wrapper.
func NewRecorder(inner Provider, writer io.Writer) *Recorder {
	return &Recorder{Inner: inner, Writer: writer}
}

// Complete implements Provider.
func (r *Recorder) Complete(ctx context.Context, req Request) (Result, error) {
	result, err := r.Inner.Complete(ctx, req)
	entry := RecordEntry{Command: req.Command}
	if err != nil {
		classified := ClassifyError(err)
		entry.ErrorClass = classified.Class
		entry.ErrorMessage = classified.Message
		retryable := classified.Retryable
		entry.Retryable = &retryable
		entry.HTTPStatus = classified.Status
	} else if result.Refusal {
		entry.Refusal = true
	} else {
		entry.AssistantContent = result.Content
		if result.Usage != (Usage{}) {
			usage := result.Usage
			entry.Usage = &usage
		}
	}
	raw, marshalErr := json.Marshal(entry)
	if marshalErr != nil {
		return result, fmt.Errorf("record provider outcome: %w", marshalErr)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, writeErr := r.Writer.Write(append(raw, '\n')); writeErr != nil {
		return result, fmt.Errorf("write record: %w", writeErr)
	}
	return result, err
}
