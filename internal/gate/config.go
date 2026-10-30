// Package gate implements the cake-safety-judge executable: describe, check,
// serve, and the engine shared by both check paths.
package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/travisennis/cake-safety-judge/internal/judge"
	"github.com/travisennis/cake-safety-judge/internal/protocol"
	"github.com/travisennis/cake-safety-judge/internal/provider"
	"github.com/travisennis/cake-safety-judge/internal/rubric"
	"github.com/travisennis/cake-safety-judge/internal/typesafe"
)

const (
	defaultTimeout     = 30 * time.Second
	defaultRetryBudget = 15 * time.Second
	defaultTypesafe    = "jev-1.13.0"
	defaultTypesafeMS  = 1000
	maxRubricBytes     = 1 << 20
)

// Config is the gate-defined `[gates.safety].config` table.
type Config struct {
	// Model selects a descriptor name from init.models. Empty prefers
	// "default", then a single descriptor.
	Model string `json:"model,omitempty"`
	// RubricFile appends user guidance to the embedded rubric. Relative paths
	// resolve from the gate's invocation directory (process cwd), never from
	// input.cwd.
	RubricFile      string          `json:"rubric_file,omitempty"`
	TimeoutSecs     *float64        `json:"timeout_secs,omitempty"`
	RetryBudgetSecs *float64        `json:"retry_budget_secs,omitempty"`
	Endpoint        *EndpointConfig `json:"endpoint,omitempty"`
	Typesafe        *TypesafeConfig `json:"typesafe,omitempty"`
}

// EndpointConfig describes a keyless or explicitly configured endpoint. It is
// the documented escape hatch for local models, which Cake cannot supply as a
// descriptor with an API key.
type EndpointConfig struct {
	BaseURL            string   `json:"base_url"`
	APIType            string   `json:"api_type"`
	Model              string   `json:"model"`
	APIKeyEnv          string   `json:"api_key_env,omitempty"`
	HTTPReferer        string   `json:"http_referer,omitempty"`
	XTitle             string   `json:"x_title,omitempty"`
	Temperature        *float64 `json:"temperature,omitempty"`
	TopP               *float64 `json:"top_p,omitempty"`
	MaxOutputTokens    *int     `json:"max_output_tokens,omitempty"`
	ReasoningEffort    string   `json:"reasoning_effort,omitempty"`
	ReasoningSummary   string   `json:"reasoning_summary,omitempty"`
	ReasoningMaxTokens *int     `json:"reasoning_max_tokens,omitempty"`
}

// TypesafeConfig selects off, shadow, or cascade.
type TypesafeConfig struct {
	Mode      string `json:"mode,omitempty"`
	Model     string `json:"model,omitempty"`
	TimeoutMS *int   `json:"timeout_ms,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
}

// DecodeConfig strictly decodes the init config table. Unknown keys are an
// error: a misspelled rubric_file or timeout must be visible, not ignored.
func DecodeConfig(raw json.RawMessage) (Config, error) {
	var config Config
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return config, nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("gate config: %w", err)
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c *Config) validate() error {
	if c.TimeoutSecs != nil && *c.TimeoutSecs <= 0 {
		return errors.New("config timeout_secs must be positive")
	}
	if c.RetryBudgetSecs != nil && *c.RetryBudgetSecs < 0 {
		return errors.New("config retry_budget_secs must not be negative")
	}
	if c.Endpoint != nil {
		if c.Endpoint.BaseURL == "" {
			return errors.New("config endpoint.base_url is required")
		}
		switch c.Endpoint.APIType {
		case "chat_completions", "responses":
		case "":
			c.Endpoint.APIType = "chat_completions"
		default:
			return fmt.Errorf("config endpoint.api_type %q is invalid", c.Endpoint.APIType)
		}
		if c.Endpoint.Model == "" {
			return errors.New("config endpoint.model is required")
		}
	}
	if c.Typesafe != nil {
		switch c.Typesafe.Mode {
		case "", "off", "shadow", "cascade":
		default:
			return fmt.Errorf("config typesafe.mode %q is invalid", c.Typesafe.Mode)
		}
		if c.Typesafe.TimeoutMS != nil && *c.Typesafe.TimeoutMS <= 0 {
			return errors.New("config typesafe.timeout_ms must be positive")
		}
	}
	return nil
}

func (c *Config) timeout() time.Duration {
	if c.TimeoutSecs != nil {
		return time.Duration(*c.TimeoutSecs * float64(time.Second))
	}
	return defaultTimeout
}

func (c *Config) retryBudget() time.Duration {
	if c.RetryBudgetSecs != nil {
		return time.Duration(*c.RetryBudgetSecs * float64(time.Second))
	}
	return defaultRetryBudget
}

// Dependencies lets tests inject a provider or clock.
type Dependencies struct {
	Provider provider.Provider
	Now      func() time.Time
}

// Engine is one initialized gate instance.
type Engine struct {
	Config           Config
	Descriptor       provider.Descriptor
	Judge            *judge.Client
	Typesafe         *typesafe.Client
	TypesafeMode     string
	TypesafeIdentity *typesafe.Identity
	TypesafeRecord   *typesafe.Record
	Warnings         []string
	Now              func() time.Time
	Log              io.Writer
}

// Build initializes the gate from an init frame.
func Build(init protocol.InitFrame) (*Engine, error) {
	return BuildWith(init, Dependencies{})
}

// BuildWith initializes the gate, optionally with injected dependencies.
func BuildWith(init protocol.InitFrame, deps Dependencies) (*Engine, error) {
	config, err := DecodeConfig(init.Config)
	if err != nil {
		return nil, err
	}
	descriptor, err := resolveDescriptor(config, init.Models)
	if err != nil {
		return nil, err
	}
	if err := validateDescriptor(descriptor); err != nil {
		return nil, err
	}

	userRubric, warning, err := loadRubric(config.RubricFile)
	if err != nil {
		return nil, err
	}
	systemPrompt := rubric.Prompt(userRubric)
	warnings := []string{}
	if warning != "" {
		warnings = append(warnings, warning)
	}

	p := deps.Provider
	if p == nil {
		p = provider.NewLive()
	}
	client := judge.New(p, descriptor, config.timeout(), config.retryBudget())
	client.Rubric = systemPrompt
	client.Now = deps.Now
	if descriptor.APIKeyEnv != "" {
		client.APIKey = os.Getenv(descriptor.APIKeyEnv)
	}

	engine := &Engine{
		Config:       config,
		Descriptor:   descriptor,
		Judge:        client,
		TypesafeMode: "off",
		Warnings:     warnings,
		Now:          deps.Now,
	}
	if engine.Now == nil {
		engine.Now = time.Now
	}
	if config.Typesafe != nil {
		mode := config.Typesafe.Mode
		if mode == "" {
			mode = "off"
		}
		if mode != "off" {
			model := config.Typesafe.Model
			if model == "" {
				model = defaultTypesafe
			}
			identity := typesafe.IdentityFor(model, systemPrompt)
			engine.TypesafeIdentity = &identity
			if mode == "cascade" {
				record, ok := typesafe.RecordedFor(identity)
				if !ok {
					mode = "shadow"
					warnings = append(warnings, fmt.Sprintf(
						"typesafe cascade disabled: calibration identity %s is not recorded for model %s, rubric %s, request %s, context %s, corpus %s/%s; running shadow-only",
						identity.ID, identity.Model, identity.RubricFingerprint,
						identity.RequestSchemaFingerprint, identity.ContextSchemaFingerprint,
						identity.CorpusVersion, identity.CorpusFingerprint))
				} else {
					engine.TypesafeRecord = &record
				}
			}
			apiKey := os.Getenv(typesafe.APIKeyEnv)
			if apiKey == "" {
				warnings = append(warnings,
					"typesafe disabled: TYPESAFE_AI_API_KEY is not set in the gate environment")
			} else {
				timeout := defaultTypesafeMS
				if config.Typesafe.TimeoutMS != nil {
					timeout = *config.Typesafe.TimeoutMS
				}
				typesafeClient := typesafe.New(apiKey, model, time.Duration(timeout)*time.Millisecond, systemPrompt)
				if config.Typesafe.Endpoint != "" {
					typesafeClient.Endpoint = config.Typesafe.Endpoint
				}
				engine.Typesafe = typesafeClient
				engine.TypesafeMode = mode
			}
		}
	}
	engine.Warnings = warnings
	return engine, nil
}

func resolveDescriptor(config Config, models map[string]protocol.ModelDescriptor) (provider.Descriptor, error) {
	if config.Endpoint != nil {
		endpoint := config.Endpoint
		apiKey := ""
		if endpoint.APIKeyEnv != "" {
			apiKey = os.Getenv(endpoint.APIKeyEnv)
			if apiKey == "" {
				return provider.Descriptor{}, fmt.Errorf(
					"config endpoint.api_key_env %q is not set in the gate environment", endpoint.APIKeyEnv)
			}
		}
		return provider.Descriptor{
			BaseURL:          endpoint.BaseURL,
			APIType:          endpoint.APIType,
			Model:            endpoint.Model,
			APIKeyEnv:        endpoint.APIKeyEnv,
			HTTPReferer:      endpoint.HTTPReferer,
			XTitle:           endpoint.XTitle,
			Temperature:      endpoint.Temperature,
			TopP:             endpoint.TopP,
			MaxOutputTokens:  endpoint.MaxOutputTokens,
			ReasoningEffort:  endpoint.ReasoningEffort,
			ReasoningSummary: endpoint.ReasoningSummary,
			ReasoningMax:     endpoint.ReasoningMaxTokens,
		}, nil
	}
	if len(models) == 0 {
		return provider.Descriptor{}, errors.New(
			"no model descriptor: configure [gates.safety].models with an environment-backed model, or set config.endpoint")
	}
	name := config.Model
	if name == "" {
		if _, ok := models["default"]; ok {
			name = "default"
		} else if len(models) == 1 {
			for only := range models {
				name = only
			}
		} else {
			return provider.Descriptor{}, errors.New(
				"config.model is required when more than one model descriptor is supplied")
		}
	}
	model, ok := models[name]
	if !ok {
		return provider.Descriptor{}, fmt.Errorf("config.model %q has no model descriptor", name)
	}
	apiKey := ""
	if model.APIKeyEnv != "" {
		apiKey = os.Getenv(model.APIKeyEnv)
		if apiKey == "" {
			return provider.Descriptor{}, fmt.Errorf(
				"model credential %q is not set in the gate environment", model.APIKeyEnv)
		}
	}
	descriptor := provider.Descriptor{
		Provider:         model.Provider,
		BaseURL:          model.BaseURL,
		APIType:          model.APIType,
		Model:            model.Model,
		APIKeyEnv:        model.APIKeyEnv,
		Temperature:      model.Temperature,
		TopP:             model.TopP,
		MaxOutputTokens:  model.MaxOutputTokens,
		ReasoningEffort:  model.ReasoningEffort,
		ReasoningSummary: model.ReasoningSummary,
		ReasoningMax:     model.ReasoningMax,
	}
	if model.ProviderHeaders != nil {
		descriptor.HTTPReferer = model.ProviderHeaders.HTTPReferer
		descriptor.XTitle = model.ProviderHeaders.XTitle
	}
	return descriptor, nil
}

func validateDescriptor(descriptor provider.Descriptor) error {
	if descriptor.BaseURL == "" {
		return errors.New("resolved model has no base_url")
	}
	if descriptor.Model == "" {
		return errors.New("resolved model has no model name")
	}
	if descriptor.APIType != "chat_completions" && descriptor.APIType != "responses" {
		return fmt.Errorf("resolved model api_type %q is invalid", descriptor.APIType)
	}
	return nil
}

// LoadRubricPrompt returns the effective system prompt for an optional user
// rubric file. It uses the same resolution and size limit as initialization.
func LoadRubricPrompt(path string) (string, error) {
	user, _, err := loadRubric(path)
	if err != nil {
		return "", err
	}
	return rubric.Prompt(user), nil
}

func loadRubric(path string) (string, string, error) {
	if path == "" {
		return "", "", nil
	}
	resolved := path
	if !filepath.IsAbs(resolved) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", "", fmt.Errorf("resolve rubric_file: %w", err)
		}
		resolved = filepath.Join(cwd, resolved)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", "", fmt.Errorf("rubric_file %s: %w", path, err)
	}
	if info.Size() > maxRubricBytes {
		return "", "", fmt.Errorf("rubric_file %s is %d bytes, limit is %d", path, info.Size(), maxRubricBytes)
	}
	raw, err := os.ReadFile(resolved)
	if err != nil {
		return "", "", fmt.Errorf("rubric_file %s: %w", path, err)
	}
	return string(raw), fmt.Sprintf("loaded user rubric from %s", path), nil
}

// DefaultDescriptor is the descriptor used by the offline check path.
func DefaultDescriptor(model string) provider.Descriptor {
	if model == "" {
		model = "offline"
	}
	return provider.Descriptor{
		APIType: "chat_completions",
		Model:   model,
		BaseURL: "offline://fake",
	}
}
