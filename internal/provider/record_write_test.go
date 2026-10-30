package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
)

type staticProvider struct {
	result Result
	err    error
}

func (p staticProvider) Complete(context.Context, Request) (Result, error) {
	return p.result, p.err
}

func TestRecorderWritesSuccessRefusalAndError(t *testing.T) {
	t.Parallel()
	var buffer bytes.Buffer
	recorder := NewRecorder(staticProvider{result: Result{
		Content: `{"verdict":"allow","message":"ok"}`,
		Usage:   Usage{InputTokens: 10, OutputTokens: 2, TotalTokens: 12},
	}}, &buffer)
	if _, err := recorder.Complete(context.Background(), Request{Command: "git status"}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if _, err := recorder.Complete(context.Background(), Request{Command: "opaque"}); err != nil {
		t.Fatalf("complete: %v", err)
	}

	refusalRecorder := NewRecorder(staticProvider{result: Result{Refusal: true}}, &buffer)
	if _, err := refusalRecorder.Complete(context.Background(), Request{Command: "refuse"}); err != nil {
		t.Fatalf("complete: %v", err)
	}

	errorRecorder := NewRecorder(staticProvider{err: &Error{Class: "timeout", Message: "slow", Retryable: true, Status: 408}}, &buffer)
	if _, err := errorRecorder.Complete(context.Background(), Request{Command: "slow"}); err == nil {
		t.Fatal("want error")
	}

	scanner := bytes.NewReader(buffer.Bytes())
	entries := make([]RecordEntry, 0, 4)
	decoder := json.NewDecoder(scanner)
	for {
		var entry RecordEntry
		if err := decoder.Decode(&entry); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode: %v", err)
		}
		entries = append(entries, entry)
	}
	if len(entries) != 4 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Command != "git status" || entries[0].AssistantContent == "" || entries[0].Usage == nil {
		t.Fatalf("success entry = %+v", entries[0])
	}
	if !entries[2].Refusal {
		t.Fatalf("refusal entry = %+v", entries[2])
	}
	if entries[3].ErrorClass != "timeout" || entries[3].Retryable == nil || !*entries[3].Retryable || entries[3].HTTPStatus != 408 {
		t.Fatalf("error entry = %+v", entries[3])
	}
}
