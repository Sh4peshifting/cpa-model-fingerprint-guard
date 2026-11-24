package guard

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Policy contains the resolved settings for one credential.
type Policy struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Idle    bool   `json:"idle" yaml:"idle"`
	Trigger bool   `json:"trigger" yaml:"trigger"`
	Model   string `json:"model" yaml:"model"`
	Expect  string `json:"expected" yaml:"expected"`
}

// Override distinguishes an inherited value from an explicit false or empty string.
type Override struct {
	Enabled *bool   `json:"enabled,omitempty" yaml:"enabled"`
	Idle    *bool   `json:"idle,omitempty" yaml:"idle"`
	Trigger *bool   `json:"trigger,omitempty" yaml:"trigger"`
	Model   *string `json:"model,omitempty" yaml:"model"`
	Expect  *string `json:"expected,omitempty" yaml:"expected"`
}

func (o Override) apply(p Policy) Policy {
	if o.Enabled != nil {
		p.Enabled = *o.Enabled
	}
	if o.Idle != nil {
		p.Idle = *o.Idle
	}
	if o.Trigger != nil {
		p.Trigger = *o.Trigger
	}
	if o.Model != nil {
		p.Model = *o.Model
	}
	if o.Expect != nil {
		p.Expect = *o.Expect
	}
	return p
}

type Config struct {
	Enabled         bool                `json:"enabled" yaml:"enabled"`
	Default         Policy              `json:"default" yaml:"default"`
	Providers       map[string]Override `json:"providers" yaml:"providers"`
	Auths           map[string]Override `json:"auths" yaml:"auths"`
	ExpectedModels  map[string]string   `json:"expected_models" yaml:"expected_models"`
	PreferFailed    bool                `json:"prefer_failed_model" yaml:"prefer_failed_model"`
	ScanSeconds     int                 `json:"scan_seconds" yaml:"scan_seconds"`
	IdleSeconds     int                 `json:"idle_seconds" yaml:"idle_seconds"`
	IntervalSeconds int                 `json:"interval_seconds" yaml:"interval_seconds"`
	TimeoutSeconds  int                 `json:"timeout_seconds" yaml:"timeout_seconds"`
	JitterSeconds   int                 `json:"jitter_seconds" yaml:"jitter_seconds"`
	DedupeSeconds   int                 `json:"dedupe_seconds" yaml:"dedupe_seconds"`
	TriggerCount    int                 `json:"trigger_count" yaml:"trigger_count"`
	HTTPStatuses    []int               `json:"http_statuses" yaml:"http_statuses"`
	ErrorCodes      []string            `json:"error_codes" yaml:"error_codes"`
	ErrorTexts      []string            `json:"error_texts" yaml:"error_texts"`
	MinProbability  float64             `json:"min_probability" yaml:"min_probability"`
	ConfirmRounds   int                 `json:"confirm_rounds" yaml:"confirm_rounds"`
	AutoDisable     bool                `json:"auto_disable" yaml:"auto_disable"`
	MaxConcurrent   int                 `json:"max_concurrent" yaml:"max_concurrent"`
	PerProvider     int                 `json:"per_provider" yaml:"per_provider"`
	RetrySeconds    int                 `json:"retry_seconds" yaml:"retry_seconds"`
	MaxRetrySeconds int                 `json:"max_retry_seconds" yaml:"max_retry_seconds"`
	MaxRetries      int                 `json:"max_retries" yaml:"max_retries"`
	MaxIsolation    int                 `json:"max_isolation_seconds" yaml:"max_isolation_seconds"`
	Expiry          string              `json:"expiry" yaml:"expiry"`
	OverloadLimit   int                 `json:"overload_limit" yaml:"overload_limit"`
	OverloadPause   int                 `json:"overload_pause_seconds" yaml:"overload_pause_seconds"`
	HistoryLimit    int                 `json:"history_limit" yaml:"history_limit"`

	MismatchRecheckSeconds int `json:"mismatch_recheck_seconds" yaml:"mismatch_recheck_seconds"`
}

func DefaultConfig() Config {
	return Config{
		Default: Policy{Enabled: true, Idle: true, Trigger: true}, PreferFailed: true,
		Providers: map[string]Override{}, Auths: map[string]Override{}, ExpectedModels: map[string]string{},
		ScanSeconds: 60, IdleSeconds: 1800, IntervalSeconds: 21600, TimeoutSeconds: 90,
		MismatchRecheckSeconds: 2 * 24 * 60 * 60,
		JitterSeconds:          10, DedupeSeconds: 10, TriggerCount: 1, HTTPStatuses: []int{502, 503},
		ErrorCodes:     []string{"server_is_overloaded"},
		ErrorTexts:     []string{"Our servers are currently overloaded. Please try again later."},
		MinProbability: .9, ConfirmRounds: 2, AutoDisable: true,
		MaxConcurrent: 2, PerProvider: 1, RetrySeconds: 60, MaxRetrySeconds: 900, MaxRetries: 5,
		MaxIsolation: 7200, Expiry: "hold", OverloadLimit: 3, OverloadPause: 120, HistoryLimit: 500,
	}
}

func (c Config) Policy(id, provider string) Policy {
	p := c.Providers[strings.ToLower(provider)].apply(c.Default)
	p = c.Auths[id].apply(p)
	p.Enabled = c.Enabled && p.Enabled
	return p
}

func (c Config) Target(p Policy, failedModel string) (request, expected string) {
	if c.PreferFailed && failedModel != "" {
		if mapped := c.ExpectedModels[failedModel]; mapped != "" {
			return failedModel, mapped
		}
	}
	expected = p.Expect
	if expected == "" {
		expected = c.ExpectedModels[p.Model]
	}
	if expected == "" {
		expected = p.Model
	}
	return p.Model, expected
}

func (c Config) Validate() error {
	ranges := []struct {
		name        string
		n, min, max int
	}{
		{"scan_seconds", c.ScanSeconds, 1, 86400},
		{"idle_seconds", c.IdleSeconds, 1, 2592000},
		{"interval_seconds", c.IntervalSeconds, 1, 2592000},
		{"mismatch_recheck_seconds", c.MismatchRecheckSeconds, 1, 2592000},
		{"timeout_seconds", c.TimeoutSeconds, 1, 600},
		{"jitter_seconds", c.JitterSeconds, 0, 3600},
		{"dedupe_seconds", c.DedupeSeconds, 0, 3600},
		{"trigger_count", c.TriggerCount, 1, 100},
		{"confirm_rounds", c.ConfirmRounds, 1, 20},
		{"max_concurrent", c.MaxConcurrent, 1, 32},
		{"per_provider", c.PerProvider, 1, c.MaxConcurrent},
		{"retry_seconds", c.RetrySeconds, 1, 86400},
		{"max_retry_seconds", c.MaxRetrySeconds, c.RetrySeconds, 86400},
		{"max_retries", c.MaxRetries, 0, 100},
		{"max_isolation_seconds", c.MaxIsolation, 1, 2592000},
		{"overload_limit", c.OverloadLimit, 1, 100},
		{"overload_pause_seconds", c.OverloadPause, 1, 86400},
		{"history_limit", c.HistoryLimit, 1, 10000},
	}
	for _, v := range ranges {
		if v.n < v.min || v.n > v.max {
			return fmt.Errorf("%s 必须介于 %d 和 %d 之间", v.name, v.min, v.max)
		}
	}
	if !(c.MinProbability > 0 && c.MinProbability <= 1) {
		return errors.New("min_probability 必须大于 0 且不超过 1")
	}
	if c.Expiry != "hold" && c.Expiry != "release" {
		return errors.New("expiry 必须为 hold 或 release")
	}
	for _, status := range c.HTTPStatuses {
		if status < 400 || status > 599 {
			return errors.New("http_statuses 必须使用 400 到 599 的状态码")
		}
	}
	for _, list := range [][]string{c.ErrorCodes, c.ErrorTexts} {
		for _, s := range list {
			if !validText(s) || s == "" {
				return errors.New("错误规则不能为空或超过 256 字节")
			}
		}
	}
	for k, v := range c.ExpectedModels {
		if !validText(k) || !validText(v) || k == "" || v == "" {
			return errors.New("模型映射必须包含有效的请求模型和预期模型")
		}
	}
	if !validText(c.Default.Model) || !validText(c.Default.Expect) {
		return errors.New("默认模型名称无效")
	}
	for _, group := range []map[string]Override{c.Providers, c.Auths} {
		for k, o := range group {
			if k == "" || !validText(k) || o.Model != nil && !validText(*o.Model) || o.Expect != nil && !validText(*o.Expect) {
				return errors.New("提供商或认证覆盖设置无效")
			}
		}
	}
	for provider := range c.Providers {
		if provider != strings.ToLower(provider) {
			return errors.New("提供商 ID 必须使用小写")
		}
	}
	return nil
}

func validText(s string) bool {
	return len(s) <= 256 && s == strings.TrimSpace(s) && !strings.ContainsAny(s, "\r\n\x00")
}

func seconds(n int) time.Duration {
	return time.Duration(n) * time.Second
}
