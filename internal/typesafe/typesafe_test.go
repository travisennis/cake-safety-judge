package typesafe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func serverFor(t *testing.T, status int, body string, check func(*http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			check(r)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestObserveSuccess(t *testing.T) {
	t.Parallel()
	var request map[string]any
	server := serverFor(t, http.StatusOK, `{
		"model":"jev-test",
		"answers":{"eligible":{"type":"noul","noul":0.91}},
		"usage":{"input_tokens":10,"output_tokens":2}
	}`, func(r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer key" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &request)
	})
	defer server.Close()

	client := New("key", "jev-test", time.Second, "RUBRIC")
	client.Endpoint = server.URL
	observation := client.Observe(context.Background(), Request{Command: "git status", Cwd: "/work"})
	if observation.FailureClass != "" {
		t.Fatalf("failure = %s", observation.FailureClass)
	}
	if observation.Probability == nil || *observation.Probability != float64(float32(0.91)) {
		t.Fatalf("probability = %v", observation.Probability)
	}
	if request["model"] != "jev-test" {
		t.Fatalf("request = %v", request)
	}
	state, _ := request["state"].(map[string]any)
	if state["command"] != "git status" {
		t.Fatalf("state = %v", state)
	}
	questions, _ := request["questions"].(map[string]any)
	if questions["eligible"] == nil {
		t.Fatalf("questions = %v", questions)
	}
}

func TestObserveFailureModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		status    int
		body      string
		model     string
		noKey     bool
		wantClass string
	}{
		{"missing key", 200, "", "jev-test", true, "missing_credentials"},
		{"http error", 500, "nope", "jev-test", false, "http_error"},
		{"malformed", 200, "not json", "jev-test", false, "malformed_response"},
		{"model mismatch", 200, `{"model":"other","answers":{"eligible":{"type":"noul","noul":0.9}}}`, "jev-test", false, "model_mismatch"},
		{"type mismatch", 200, `{"model":"jev-test","answers":{"eligible":{"type":"boolean","noul":0.9}}}`, "jev-test", false, "answer_type_mismatch"},
		{"range", 200, `{"model":"jev-test","answers":{"eligible":{"type":"noul","noul":1.5}}}`, "jev-test", false, "probability_out_of_range"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := serverFor(t, tc.status, tc.body, nil)
			defer server.Close()
			key := "key"
			if tc.noKey {
				key = ""
			}
			client := New(key, tc.model, time.Second, "RUBRIC")
			client.Endpoint = server.URL
			observation := client.Observe(context.Background(), Request{Command: "git status", Cwd: "/work"})
			if observation.FailureClass != tc.wantClass {
				t.Fatalf("failure = %q, want %q", observation.FailureClass, tc.wantClass)
			}
		})
	}
}

func TestObserveTimeout(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	client := New("key", "jev-test", 20*time.Millisecond, "RUBRIC")
	client.Endpoint = server.URL
	observation := client.Observe(context.Background(), Request{Command: "git status", Cwd: "/work"})
	if observation.FailureClass != "timeout" {
		t.Fatalf("failure = %q", observation.FailureClass)
	}
}
