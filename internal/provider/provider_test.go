package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestChatCompletionsSuccess(t *testing.T) {
	t.Parallel()
	temp := 0.2
	var sawAuth, sawReferer, sawPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawReferer = r.Header.Get("HTTP-Referer")
		sawPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		var request map[string]any
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("request body: %v", err)
		}
		if request["model"] != "judge-model" {
			t.Errorf("model = %v", request["model"])
		}
		messages, _ := request["messages"].([]any)
		if len(messages) != 2 {
			t.Errorf("messages = %v", messages)
		}
		if request["temperature"] != 0.2 {
			t.Errorf("temperature = %v", request["temperature"])
		}
		_, _ = w.Write([]byte(`{
			"id":"resp-1","model":"judge-model",
			"choices":[{"message":{"content":"{\"verdict\":\"allow\",\"message\":\"ok\"}"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}
		}`))
	}))
	defer server.Close()

	live := NewLive()
	result, err := live.Complete(context.Background(), Request{
		System: "system", User: "user", APIKey: "secret",
		Descriptor: Descriptor{
			BaseURL: server.URL, APIType: "chat_completions", Model: "judge-model",
			HTTPReferer: "https://example.test", Temperature: &temp,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sawPath != "/chat/completions" {
		t.Fatalf("path = %q", sawPath)
	}
	if sawAuth != "Bearer secret" || sawReferer != "https://example.test" {
		t.Fatalf("auth=%q referer=%q", sawAuth, sawReferer)
	}
	if result.Content != `{"verdict":"allow","message":"ok"}` || result.Usage.TotalTokens != 15 {
		t.Fatalf("result = %+v", result)
	}
}

func TestChatCompletionsFailureModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		body       string
		finish     string
		refusal    string
		wantClass  string
		wantRefuse bool
	}{
		{"refusal field", `{"choices":[{"message":{"content":null,"refusal":"no"},"finish_reason":"stop"}]}`, "", "no", "", true},
		{"content filter", `{"choices":[{"message":{"content":""},"finish_reason":"content_filter"}]}`, "", "", "", true},
		{"malformed envelope", `not json`, "", "", "malformed", false},
		{"no choices", `{"choices":[]}`, "", "", "malformed", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			live := NewLive()
			result, err := live.Complete(context.Background(), Request{
				Descriptor: Descriptor{BaseURL: server.URL, APIType: "chat_completions", Model: "m"},
			})
			if tc.wantRefuse {
				if err != nil || !result.Refusal {
					t.Fatalf("want refusal, result=%+v err=%v", result, err)
				}
				return
			}
			if err == nil {
				t.Fatal("want error")
			}
			providerError, ok := err.(*Error)
			if !ok || providerError.Class != tc.wantClass {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestStatusClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status    int
		class     string
		retryable bool
	}{
		{401, "auth", false},
		{403, "auth", false},
		{408, "timeout", true},
		{429, "rate_limit", true},
		{500, "transport", true},
		{503, "transport", true},
		{529, "transport", true},
		{400, "transport", false},
	}
	for _, tc := range tests {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte("nope"))
		}))
		live := NewLive()
		_, err := live.Complete(context.Background(), Request{
			Descriptor: Descriptor{BaseURL: server.URL, APIType: "chat_completions", Model: "m"},
		})
		server.Close()
		providerError, ok := err.(*Error)
		if !ok || providerError.Class != tc.class || providerError.Retryable != tc.retryable {
			t.Fatalf("status %d: error = %#v", tc.status, err)
		}
	}
}

func TestResponsesSuccess(t *testing.T) {
	t.Parallel()
	var sawInstructions string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &request)
		sawInstructions, _ = request["instructions"].(string)
		if r.URL.Path != "/responses" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"id":"resp-1","model":"judge-model","status":"completed",
			"output":[
				{"type":"reasoning"},
				{"type":"message","content":[{"type":"output_text","text":"{\"verdict\":\"allow\",\"message\":\"ok\"}"}]}
			],
			"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}
		}`))
	}))
	defer server.Close()

	result, err := NewLive().Complete(context.Background(), Request{
		System: "system", User: "user",
		Descriptor: Descriptor{BaseURL: server.URL, APIType: "responses", Model: "judge-model"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sawInstructions != "system" {
		t.Fatalf("instructions = %q", sawInstructions)
	}
	if result.Content != `{"verdict":"allow","message":"ok"}` || result.Usage.InputTokens != 10 {
		t.Fatalf("result = %+v", result)
	}
}

func TestResponsesFailureModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		body       string
		wantRefuse bool
	}{
		{"content filter", `{"status":"incomplete","incomplete_details":{"reason":"content_filter"},"output":[]}`, true},
		{"failed no text", `{"status":"failed","error":{"code":"server_error"},"output":[]}`, true},
		{"failed with text", `{"status":"failed","output":[{"type":"message","content":[{"type":"output_text","text":"{\"verdict\":\"block\",\"code\":\"unknown-destructive\",\"message\":\"no\"}"}]}]}`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			result, err := NewLive().Complete(context.Background(), Request{
				Descriptor: Descriptor{BaseURL: server.URL, APIType: "responses", Model: "m"},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantRefuse {
				if !result.Refusal {
					t.Fatalf("want refusal, got %+v", result)
				}
				return
			}
			if result.Refusal || result.Content == "" {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestFakeProvider(t *testing.T) {
	t.Parallel()
	confidence := 0.75
	fake := &Fake{}
	result, err := fake.Complete(context.Background(), Request{Expected: &Expected{
		Decision: "block", Code: "unknown-destructive", Confidence: &confidence,
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var verdict map[string]any
	if err := json.Unmarshal([]byte(result.Content), &verdict); err != nil {
		t.Fatalf("content: %v", err)
	}
	if verdict["verdict"] != "block" || verdict["code"] != "unknown-destructive" {
		t.Fatalf("verdict = %v", verdict)
	}

	configured := &Fake{Decision: "warn", Code: "rg-replace-footgun"}
	result, err = configured.Complete(context.Background(), Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = json.Unmarshal([]byte(result.Content), &verdict)
	if verdict["verdict"] != "warn" {
		t.Fatalf("verdict = %v", verdict)
	}
}

func TestRecordProvider(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "record.jsonl")
	content := `{"command":"git status","assistant_content":"{\"verdict\":\"allow\",\"message\":\"ok\"}"}
{"command":"rm -rf /","http_status":503}
{"refusal":true}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	recorder, err := LoadRecordFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	result, err := recorder.Complete(context.Background(), Request{Command: "git status"})
	if err != nil || result.Content == "" {
		t.Fatalf("first: %+v %v", result, err)
	}
	_, err = recorder.Complete(context.Background(), Request{Command: "rm -rf /"})
	if providerError, ok := err.(*Error); !ok || providerError.Class != "transport" || !providerError.Retryable {
		t.Fatalf("second error = %#v", err)
	}
	result, err = recorder.Complete(context.Background(), Request{})
	if err != nil || !result.Refusal {
		t.Fatalf("third: %+v %v", result, err)
	}
	if _, err := recorder.Complete(context.Background(), Request{}); err == nil {
		t.Fatal("exhausted recorder accepted a fourth call")
	}
}

func TestCompleteHonorsContext(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := NewLive().Complete(ctx, Request{
		Descriptor: Descriptor{BaseURL: server.URL, APIType: "chat_completions", Model: "m"},
	})
	providerError, ok := err.(*Error)
	if !ok || providerError.Class != "timeout" || !providerError.Retryable {
		t.Fatalf("error = %#v", err)
	}
}
