package guard

import (
	"regexp"
	"slices"
	"strings"
	"time"
)

var errorCode = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,79}$`)

func (g *Guard) Observe(request, id, model string, status int, code, text string, correlations ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Only post-selection business attempts supply this correlation. This also
	// discards usage reports from the plugin's own internal host calls.
	if g.ctx.Err() != nil {
		return
	}
	r := g.requests[request]
	for _, key := range correlations {
		if r == nil {
			r = g.correlations[key]
		}
	}
	if r == nil {
		return
	}
	if _, tried := r.auths[id]; !tried {
		return
	}
	a, ok := g.inventory[id]
	if !ok || a.Disabled {
		return
	}
	cfg := g.state.Config
	p := cfg.Policy(id, a.Provider)
	s := g.state.Auths[id]
	if !p.Enabled || !p.Trigger || s.Isolated {
		return
	}
	reason := matchFailure(cfg, status, code, text)
	if reason == "" {
		return
	}
	if _, seen := r.failed[id]; seen {
		return
	}
	if r.failed == nil {
		r.failed = map[string]struct{}{}
	}
	r.failed[id] = struct{}{}
	now := g.now().UTC()
	window := g.failures[id]
	if !window.last.IsZero() && now.Sub(window.last) < seconds(cfg.DedupeSeconds) {
		return
	}
	if !errorCode.MatchString(code) {
		code = ""
	}
	if !validText(model) {
		model = ""
	}
	if window.first.At.IsZero() || now.Sub(window.last) > max(time.Minute, seconds(cfg.DedupeSeconds)*2) {
		window = failureWindow{first: Trigger{Reason: reason, Model: model, Status: status, Code: code, At: now}}
	}
	window.last = now
	window.count++
	g.failures[id] = window
	if window.count < cfg.TriggerCount {
		return
	}
	delete(g.failures, id)
	if j := g.running[id]; j != nil {
		j.cancel()
	}
	s.Isolated, s.Held, s.Trigger = true, false, window.first
	s.Pending, s.Due, s.Retries, s.Consecutive, s.GatewayFailures = "error", now, 0, 0, 0
	g.save()
	g.signal()
}

func matchFailure(c Config, status int, code, text string) string {
	if slices.Contains(c.HTTPStatuses, status) {
		return "http_status"
	}
	for _, rule := range c.ErrorCodes {
		if strings.EqualFold(rule, code) {
			return "error_code"
		}
	}
	if len(text) > 16<<10 {
		text = text[:16<<10]
	}
	text = strings.ToLower(text)
	for _, rule := range c.ErrorTexts {
		if strings.Contains(text, strings.ToLower(rule)) {
			return "error_text"
		}
	}
	return ""
}
