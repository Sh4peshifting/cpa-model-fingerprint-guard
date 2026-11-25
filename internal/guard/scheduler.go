package guard

import (
	"context"
	"net/http"
	"sort"
	"time"
)

const (
	mismatchRecheck = "recheck"
	gatewayRecheck  = "gateway_recheck"
)

func (g *Guard) schedule(now time.Time, scan bool) {
	cfg := g.state.Config
	type candidate struct {
		auth  Auth
		state *AuthState
	}
	var ready []candidate
	for id, a := range g.inventory {
		s := g.state.Auths[id]
		p := cfg.Policy(id, a.Provider)
		if !p.Enabled || a.Disabled || g.listErr || g.running[id] != nil {
			continue
		}
		triggerDisabled := s.Isolated && s.Trigger.Reason != "manual" && !p.Trigger
		if s.CancelledRecheck != "" && s.Pending != "manual" {
			continue
		}
		if scan && (s.Pending == "" || triggerDisabled && s.Pending == "confirm") {
			if due := mismatchRecheckDue(a, s, p, cfg); !due.IsZero() && !now.Before(due) {
				s.Pending, s.Due, s.Retries = mismatchRecheck, due, 0
				g.dirty = true
			} else if p.Idle && !s.Isolated && g.idle(now, id, s, cfg) {
				s.Pending = "idle"
				s.Due = now.Add(g.jitter(cfg.JitterSeconds))
				g.dirty = true
			}
		}
		if s.Pending == mismatchRecheck {
			due := mismatchRecheckDue(a, s, p, cfg)
			if due.IsZero() || now.Before(due) {
				s.Pending, s.Due = "", time.Time{}
				g.dirty = true
				continue
			}
		}
		if s.Pending == "" || now.Before(s.probeDue(a)) || now.Before(g.pauses[""]) || now.Before(g.pauses[a.Provider]) {
			continue
		}
		if s.Pending == "idle" && (!p.Idle || !g.idle(now, id, s, cfg)) {
			s.Pending, s.Due = "", time.Time{}
			g.dirty = true
			continue
		}
		if triggerDisabled && s.Pending != "manual" && s.Pending != mismatchRecheck && s.Pending != gatewayRecheck {
			continue
		}
		if s.Pending == gatewayRecheck && !a.Probeable {
			continue
		}
		ready = append(ready, candidate{a, s})
	}

	priority := map[string]int{"error": 0, "manual": 1, "confirm": 2, mismatchRecheck: 3, gatewayRecheck: 4, "idle": 5}
	sort.Slice(ready, func(i, j int) bool {
		a, b := ready[i], ready[j]
		if ap, bp := priority[a.state.Pending], priority[b.state.Pending]; ap != bp {
			return ap < bp
		}
		if a.state.Due.Equal(b.state.Due) {
			return a.auth.ID < b.auth.ID
		}
		return a.state.Due.Before(b.state.Due)
	})
	counts := map[string]int{}
	for _, job := range g.running {
		counts[job.Provider]++
	}
	for _, c := range ready {
		if len(g.running) >= cfg.MaxConcurrent {
			break
		}
		if counts[c.auth.Provider] >= cfg.PerProvider {
			continue
		}
		g.launch(c.auth, c.state, cfg)
		counts[c.auth.Provider]++
	}
}

func (s *AuthState) probeDue(a Auth) time.Time {
	due := s.Due
	if s.Isolated && s.Trigger.isBusiness() && s.Pending != mismatchRecheck {
		for _, deadline := range []time.Time{s.ProbeCooldown, a.CooldownUntil} {
			if deadline.After(due) {
				due = deadline
			}
		}
	}
	return due
}

func (g *Guard) idle(now time.Time, id string, s *AuthState, cfg Config) bool {
	last := s.LastCheck
	if s.IdleSkippedAt.After(last) {
		last = s.IdleSkippedAt
	}
	return g.active[id] == 0 && !now.Before(s.WatchUntil) &&
		now.Sub(s.LastBusiness) >= seconds(cfg.IdleSeconds) &&
		now.Sub(last) >= seconds(cfg.IntervalSeconds)
}

func mismatchRecheckDue(a Auth, s *AuthState, p Policy, cfg Config) time.Time {
	fault := s.Abnormal
	if !p.Enabled || a.Disabled || !a.Probeable || !s.Isolated || fault == nil || s.CancelledRecheck != "" ||
		fault.PluginDisabled || fault.Confirmed.IsZero() || s.Trigger.At.After(fault.Confirmed) ||
		fault.RequestModel == "" || fault.Expected == "" {
		return time.Time{}
	}
	last := fault.Confirmed
	if s.LastCheck.After(last) {
		last = s.LastCheck
	}
	return last.Add(seconds(cfg.MismatchRecheckSeconds))
}

func (g *Guard) launch(a Auth, s *AuthState, cfg Config) {
	p := cfg.Policy(a.ID, a.Provider)
	model, expect := cfg.Target(p, s.Trigger.Model)
	target := s.Pending
	if target == "manual" && s.CancelledRecheck != "" {
		target = s.CancelledRecheck
	}
	switch target {
	case mismatchRecheck:
		if s.Abnormal != nil {
			model, expect = s.Abnormal.RequestModel, s.Abnormal.Expected
		}
	case gatewayRecheck:
		model = s.Trigger.Model
		expect = cfg.ExpectedModels[model]
		if expect == "" {
			expect = model
			if p.Model == model && p.Expect != "" {
				expect = p.Expect
			}
		}
	}
	ctx, cancel := context.WithCancel(g.ctx)
	j := &job{
		Probe:  Probe{Auth: a, Model: model, Expected: expect, Probability: cfg.MinProbability, Timeout: seconds(cfg.TimeoutSeconds), ParallelChallenges: cfg.ParallelChallenges},
		reason: s.Pending, trigger: s.Trigger, revision: g.state.Revision, cancel: cancel,
	}
	g.running[a.ID] = j
	g.wg.Go(func() {
		defer cancel()
		start := g.now().UTC()
		var r Result
		if !a.Probeable || model == "" || expect == "" {
			r = Result{Status: Unsupported, Reason: "unsupported_route"}
		} else {
			r = g.detector.Check(ctx, j.Probe)
		}
		verifyCtx, verifyCancel := context.WithTimeout(ctx, 10*time.Second)
		var current Auth
		var verifyErr error
		if ctx.Err() == nil {
			var auths []Auth
			auths, verifyErr = g.host.List(verifyCtx)
			for _, item := range auths {
				if item.ID == a.ID {
					current = item
					break
				}
			}
		}
		verifyCancel()
		g.finish(ctx, start, j, current, verifyErr, r)
	})
}

func (g *Guard) finish(ctx context.Context, start time.Time, j *job, current Auth, verifyErr error, r Result) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.running, j.ID)
	defer g.signal()
	if g.ctx.Err() != nil {
		return
	}
	s := g.state.Auths[j.ID]
	if s == nil || ctx.Err() != nil || j.revision != g.state.Revision || s.Version != j.Version {
		return
	}
	now := g.now().UTC()
	if verifyErr != nil {
		r = Result{Status: Transient, Reason: "inventory_unavailable"}
	} else if current.ID == "" || current.Disabled || current.Version != j.Version {
		if !s.Isolated || !s.Trigger.isBusiness() {
			s.Pending, s.Due = "", time.Time{}
		}
		s.Consecutive, s.GatewayFailures = 0, 0
		if s.Isolated {
			s.Held = true
		}
		g.nextScan = time.Time{}
		g.save()
		return
	}
	trigger := j.trigger
	if trigger.At.IsZero() {
		trigger = Trigger{Reason: j.reason, At: start}
	}
	if j.reason == mismatchRecheck || s.LastModel != j.Model || s.LastExpected != j.Expected || s.LastResult.ReferenceBuild != r.ReferenceBuild || r.Status != Mismatch {
		s.Consecutive = 0
	}
	if s.LastModel != j.Model {
		s.GatewayFailures = 0
	}
	if r.Status == Transient && current.CooldownUntil.After(r.CooldownUntil) {
		r.CooldownUntil = current.CooldownUntil
	}
	s.LastCheck, s.LastModel, s.LastExpected, s.LastResult = now, j.Model, j.Expected, r
	s.Pending, s.Due = "", time.Time{}
	action := g.applyResult(now, j, s, trigger, r)
	if action != "cooldown_wait" {
		g.recordOverload(now, j.Provider, r.Overloaded)
	}
	if j.reason == mismatchRecheck {
		trigger = Trigger{Reason: mismatchRecheck, At: start}
	} else if j.reason == gatewayRecheck {
		trigger.Reason, trigger.At = j.reason, start
	}
	g.state.History = append(g.state.History, Record{
		At: start, AuthID: j.ID, Name: j.Name, Trigger: trigger,
		Model: j.Model, Expect: j.Expected, Result: r, Millis: now.Sub(start).Milliseconds(), Action: action,
	})
	g.trimHistory()
	g.save()
}

func (g *Guard) applyResult(now time.Time, j *job, s *AuthState, trigger Trigger, r Result) string {
	cfg := g.state.Config
	if (j.reason == mismatchRecheck || s.CancelledRecheck != "") && r.Status != Match {
		s.Held = true
		if s.CancelledRecheck != "" && r.CooldownUntil.After(now) {
			s.ProbeCooldown = r.CooldownUntil
		}
		return "recheck_kept_isolated"
	}

	business := s.Isolated && trigger.isBusiness()
	s.ProbeCooldown = time.Time{}
	if business && j.reason != mismatchRecheck && r.Status == Transient && r.CooldownUntil.After(now) {
		s.ProbeCooldown = r.CooldownUntil
		if !r.GatewayFailure() {
			s.Pending, s.Due = j.reason, now
			return "cooldown_wait"
		}
	}
	if r.GatewayFailure() {
		s.GatewayFailures++
	} else {
		s.GatewayFailures = 0
	}

	switch r.Status {
	case Match:
		requiresKnownModel := business && j.reason != mismatchRecheck && s.CancelledRecheck != mismatchRecheck
		if (requiresKnownModel || trigger.Model != "") && j.Model != trigger.Model {
			s.Held = true
			if j.reason == gatewayRecheck {
				g.queueGatewayRecheck(now, s)
			}
			return "different_model"
		}
		s.Abnormal = nil
		g.release(s)
		return "matched"
	case Mismatch:
		s.Consecutive++
		if s.Consecutive < cfg.ConfirmRounds {
			if j.reason == gatewayRecheck {
				g.queueGatewayRecheck(now, s)
			} else {
				s.Pending, s.Due = "confirm", now.Add(seconds(cfg.RetrySeconds)+g.jitter(cfg.JitterSeconds))
			}
			return "confirm_again"
		}
		s.Abnormal = &Abnormal{
			Trigger: trigger, Status: "confirmed_mismatch", Expected: j.Expected, RequestModel: j.Model,
			Detected: r.Detected, Score: r.Score, Probability: r.Probability,
			Consecutive: s.Consecutive, Confirmed: now,
		}
		s.Isolated, s.Held = true, true
		if s.Trigger.At.IsZero() {
			s.Trigger = trigger
		}
		return "confirmed_isolation"
	}

	if j.reason == gatewayRecheck {
		return g.queueGatewayRecheck(now, s)
	}
	switch r.Status {
	case Transient, Inconclusive:
		if business && s.Abnormal == nil && trigger.Model != "" && s.Retries >= cfg.MaxRetries &&
			s.GatewayFailures >= min(2, cfg.MaxRetries+1) {
			return g.queueGatewayRecheck(now, s)
		}
		if s.Isolated || j.reason == "manual" || j.reason == "confirm" {
			return g.retry(now, s, j.reason, cfg)
		}
	case Unsupported:
		if s.Isolated {
			s.Held = true
			return "held_unsupported"
		}
	}
	return "recorded"
}

func isGatewayStatus(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable
}

func (r Result) GatewayFailure() bool {
	return r.Status == Transient && isGatewayStatus(r.HTTPStatus)
}

func (g *Guard) queueGatewayRecheck(now time.Time, s *AuthState) string {
	s.Held = true
	s.Pending, s.Due = gatewayRecheck, now.Add(seconds(g.state.Config.GatewayRecheckSeconds))
	return "gateway_recheck_scheduled"
}

func (g *Guard) retry(now time.Time, s *AuthState, reason string, cfg Config) string {
	if s.Retries >= cfg.MaxRetries {
		s.Held = s.Isolated
		return "retries_exhausted"
	}
	if s.ProbeCooldown.After(now) {
		s.Retries++
		s.Pending, s.Due = reason, now
		return "retry_scheduled"
	}
	delay := seconds(cfg.RetrySeconds)
	for i := 0; i < s.Retries && delay < seconds(cfg.MaxRetrySeconds); i++ {
		delay = min(delay*2, seconds(cfg.MaxRetrySeconds))
	}
	s.Retries++
	s.Pending, s.Due = reason, now.Add(delay+g.jitter(cfg.JitterSeconds))
	return "retry_scheduled"
}

func (g *Guard) recordOverload(now time.Time, provider string, overload bool) {
	cfg := g.state.Config
	for _, key := range []string{provider, ""} {
		if !overload {
			g.overloads[key] = 0
			continue
		}
		g.overloads[key]++
		if g.overloads[key] >= cfg.OverloadLimit {
			g.pauses[key] = now.Add(seconds(cfg.OverloadPause))
			g.overloads[key] = 0
		}
	}
}

func (g *Guard) release(s *AuthState) {
	s.Isolated, s.Held, s.Retries, s.Consecutive = false, false, 0, 0
	s.Trigger, s.Pending, s.Due, s.GatewayFailures, s.ProbeCooldown = Trigger{}, "", time.Time{}, 0, time.Time{}
	s.CancelledRecheck = ""
}

func (g *Guard) trimHistory() {
	if excess := len(g.state.History) - g.state.Config.HistoryLimit; excess > 0 {
		g.state.History = append([]Record(nil), g.state.History[excess:]...)
	}
}
