package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type responsesContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type responsesInput struct {
	Role    string             `json:"role"`
	Content []responsesContent `json:"content"`
}

type responsesReasoning struct {
	Effort   string `json:"effort,omitempty"`
	Summary  string `json:"summary,omitempty"`
	MaxToken *int   `json:"max_tokens,omitempty"`
}

type responsesRequest struct {
	Model           string              `json:"model"`
	Instructions    string              `json:"instructions,omitempty"`
	Input           []responsesInput    `json:"input"`
	Temperature     *float64            `json:"temperature,omitempty"`
	TopP            *float64            `json:"top_p,omitempty"`
	MaxOutputTokens *int                `json:"max_output_tokens,omitempty"`
	Reasoning       *responsesReasoning `json:"reasoning,omitempty"`
}

type responsesResponse struct {
	ID                string `json:"id"`
	Model             string `json:"model"`
	Status            string `json:"status"`
	IncompleteDetails *struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Output []struct {
		Type    string             `json:"type"`
		Content []responsesContent `json:"content"`
	} `json:"output"`
	Usage *struct {
		InputTokens  *int64 `json:"input_tokens"`
		OutputTokens *int64 `json:"output_tokens"`
		TotalTokens  *int64 `json:"total_tokens"`
	} `json:"usage"`
}

func completeResponses(ctx context.Context, client *http.Client, req Request) (Result, error) {
	var reasoning *responsesReasoning
	if req.Descriptor.ReasoningEffort != "" || req.Descriptor.ReasoningSummary != "" ||
		req.Descriptor.ReasoningMax != nil {
		reasoning = &responsesReasoning{
			Effort:   req.Descriptor.ReasoningEffort,
			Summary:  req.Descriptor.ReasoningSummary,
			MaxToken: req.Descriptor.ReasoningMax,
		}
	}
	body, err := json.Marshal(responsesRequest{
		Model:        req.Descriptor.Model,
		Instructions: req.System,
		Input: []responsesInput{{
			Role:    "user",
			Content: []responsesContent{{Type: "input_text", Text: req.User}},
		}},
		Temperature:     req.Descriptor.Temperature,
		TopP:            req.Descriptor.TopP,
		MaxOutputTokens: req.Descriptor.MaxOutputTokens,
		Reasoning:       reasoning,
	})
	if err != nil {
		return Result{}, &Error{Class: "internal", Message: "encode responses request: " + err.Error()}
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint(req.Descriptor.BaseURL, "/responses"), bytes.NewReader(body))
	if err != nil {
		return Result{}, &Error{Class: "config", Message: "build responses request: " + err.Error()}
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
	var decoded responsesResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return Result{}, &Error{
			Class:     "malformed",
			Message:   "provider 2xx body is not a responses response",
			Retryable: true,
		}
	}

	var text strings.Builder
	for _, item := range decoded.Output {
		if item.Type != "message" {
			continue
		}
		for _, content := range item.Content {
			if content.Type == "output_text" || content.Type == "text" {
				text.WriteString(content.Text)
			}
		}
	}

	if decoded.Status == "failed" {
		reason := ""
		if decoded.Error != nil {
			reason = decoded.Error.Code
		}
		if text.Len() == 0 || strings.Contains(strings.ToLower(reason), "refus") {
			return Result{Refusal: true, RequestID: decoded.ID, Model: decoded.Model}, nil
		}
	}
	if decoded.Status == "incomplete" && decoded.IncompleteDetails != nil &&
		decoded.IncompleteDetails.Reason == "content_filter" {
		return Result{Refusal: true, RequestID: decoded.ID, Model: decoded.Model}, nil
	}

	result := Result{Content: text.String(), RequestID: decoded.ID, Model: decoded.Model}
	if decoded.Usage != nil {
		if decoded.Usage.InputTokens != nil {
			result.Usage.InputTokens = *decoded.Usage.InputTokens
		}
		if decoded.Usage.OutputTokens != nil {
			result.Usage.OutputTokens = *decoded.Usage.OutputTokens
		}
		if decoded.Usage.TotalTokens != nil {
			result.Usage.TotalTokens = *decoded.Usage.TotalTokens
		}
	}
	return result, nil
}
