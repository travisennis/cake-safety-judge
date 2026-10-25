package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model               string        `json:"model"`
	Messages            []chatMessage `json:"messages"`
	Temperature         *float64      `json:"temperature,omitempty"`
	TopP                *float64      `json:"top_p,omitempty"`
	MaxCompletionTokens *int          `json:"max_completion_tokens,omitempty"`
	ReasoningEffort     string        `json:"reasoning_effort,omitempty"`
}

type chatResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content *string `json:"content"`
			Refusal *string `json:"refusal"`
		} `json:"message"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     *int64 `json:"prompt_tokens"`
		CompletionTokens *int64 `json:"completion_tokens"`
		TotalTokens      *int64 `json:"total_tokens"`
	} `json:"usage"`
}

func completeChat(ctx context.Context, client *http.Client, req Request) (Result, error) {
	body, err := json.Marshal(chatRequest{
		Model: req.Descriptor.Model,
		Messages: []chatMessage{
			{Role: "system", Content: req.System},
			{Role: "user", Content: req.User},
		},
		Temperature:         req.Descriptor.Temperature,
		TopP:                req.Descriptor.TopP,
		MaxCompletionTokens: req.Descriptor.MaxOutputTokens,
		ReasoningEffort:     req.Descriptor.ReasoningEffort,
	})
	if err != nil {
		return Result{}, &Error{Class: "internal", Message: "encode chat completions request: " + err.Error()}
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint(req.Descriptor.BaseURL, "/chat/completions"), bytes.NewReader(body))
	if err != nil {
		return Result{}, &Error{Class: "config", Message: "build chat completions request: " + err.Error()}
	}
	applyHeaders(httpRequest, req)

	response, err := client.Do(httpRequest)
	if err != nil {
		return Result{}, timeoutOr(ctx, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = readBody(response)
		return Result{}, classifyStatus(response.StatusCode)
	}
	raw, err := readBody(response)
	if err != nil {
		return Result{}, err
	}
	var decoded chatResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return Result{}, &Error{
			Class:     "malformed",
			Message:   "provider 2xx body is not a chat completions response",
			Retryable: true,
		}
	}
	if len(decoded.Choices) == 0 {
		return Result{}, &Error{
			Class:     "malformed",
			Message:   "chat completions response has no choices",
			Retryable: true,
		}
	}
	choice := decoded.Choices[0]
	if choice.Message.Refusal != nil && *choice.Message.Refusal != "" {
		return Result{Refusal: true, RequestID: decoded.ID, Model: decoded.Model}, nil
	}
	if choice.FinishReason != nil {
		switch *choice.FinishReason {
		case "content_filter", "refusal", "refused":
			return Result{Refusal: true, RequestID: decoded.ID, Model: decoded.Model}, nil
		}
	}
	content := ""
	if choice.Message.Content != nil {
		content = *choice.Message.Content
	}
	result := Result{Content: content, RequestID: decoded.ID, Model: decoded.Model}
	if decoded.Usage != nil {
		if decoded.Usage.PromptTokens != nil {
			result.Usage.InputTokens = *decoded.Usage.PromptTokens
		}
		if decoded.Usage.CompletionTokens != nil {
			result.Usage.OutputTokens = *decoded.Usage.CompletionTokens
		}
		if decoded.Usage.TotalTokens != nil {
			result.Usage.TotalTokens = *decoded.Usage.TotalTokens
		}
	}
	return result, nil
}
