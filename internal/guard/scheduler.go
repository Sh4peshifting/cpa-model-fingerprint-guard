package guard

import (
	"context"
	"sort"
	"time"
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
		if s.Isolated && !s.Trigger.At.IsZero() && now.Sub(s.Trigger.At) >= seconds(cfg.MaxIsolation) {
			if cfg.Expiry == "release" && s.Abnormal == nil && s.Trigger.Reason != "manual" {
				g.expire(id, s, true)
			} else if !s.Held {
				g.expire(id, s, false)
			}
		}
		if !p.Enabled || a.Disabled || g.listErr || g.running[id] != nil {
			continue
		}
		if scan && p.Idle && !s.Isolated && s.Pending == "" && g.idle(now, id, s, cfg) {
			s.Pending = "idle"
			s.Due = now.Add(g.jitter(cfg.JitterSeconds))
			g.dirty = true
		}
		if s.Pending == "" || now.Before(s.Due) || now.Before(g.pauses[""]) || now.Before(g.pauses[a.Provider]) {
			continue
		}
		if s.Pending == "idle" && (!p.Idle || !g.idle(now, id, s, cfg)) {
			s.Pending, s.Due = "", time.Time{}
			g.dirty = true
			continue
		}
		if s.Isolated && s.Trigger.Reason != "manual" && !p.Trigger && s.Pending != "manual" {
			continue
		}
		ready = append(ready, candidate{a, s})
	}

	priority := map[string]int{"error": 0, "manual": 1, "confirm": 2, "idle": 3}
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

func (g *Guard) idle(now time.Time, id string, s *AuthState, cfg Config) bool {
	return g.active[id] == 0 && !now.Before(s.WatchUntil) &&
		now.Sub(s.LastBusiness) >= seconds(cfg.IdleSeconds) &&
		now.Sub(s.LastCheck) >= seconds(cfg.IntervalSeconds)
}

func (g *Guard) launch(a Auth, s *AuthState, cfg Config) {
	p := cfg.Policy(a.ID, a.Provider)
	model, expect := cfg.Target(p, s.Trigger.Model)
	ctx, cancel := context.WithCancel(g.ctx)
	j := &job{
		Probe:  Probe{Auth: a, Model: model, Expected: expect, Probability: cfg.MinProbability, Timeout: seconds(cfg.TimeoutSeconds)},
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
		s.Pending, s.Due, s.Consecutive = "", time.Time{}, 0
		if s.Isolated {
			s.Held = true
		}
		g.save()
		return
	}
	trigger := j.trigger
	if trigger.At.IsZero() {
		trigger = Trigger{Reason: j.reason, At: start}
	}
	if s.LastModel != j.Model || s.LastExpected != j.Expected || s.LastResult.ReferenceBuild != r.ReferenceBuild || r.Status != Mismatch {
		s.Consecutive = 0
	}
	s.LastCheck, s.LastModel, s.LastExpected, s.LastResult = now, j.Model, j.Expected, r
	s.Pending, s.Due = "", time.Time{}
	action := g.applyResult(ctx, now, j, s, trigger, r)
	g.recordOverload(now, j.Provider, r.Overloaded)
	g.state.History = append(g.state.History, Record{
		At: start, AuthID: j.ID, Name: j.Name, Trigger: trigger,
		Model: j.Model, Expect: j.Expected, Result: r, Millis: now.Sub(start).Milliseconds(), Action: action,
	})
	g.trimHistory()
	g.save()
}

func (g *Guard) applyResult(ctx context.Context, now time.Time, j *job, s *AuthState, trigger Trigger, r Result) string {
	cfg := g.state.Config
	switch r.Status {
	case Match:
		s.Abnormal = nil
		if trigger.Model != "" && j.Model != trigger.Model {
			s.Held = true
			return "different_model"
		}
		g.release(s)
		return "matched"
	case Mismatch:
		s.Consecutive++
		if s.Consecutive < cfg.ConfirmRounds {
			s.Pending, s.Due = "confirm", now.Add(seconds(cfg.RetrySeconds)+g.jitter(cfg.JitterSeconds))
			return "confirm_again"
		}
		abnormal := Abnormal{
			Trigger: trigger, Status: "confirmed_mismatch", Expected: j.Expected, RequestModel: j.Model,
			Detected: r.Detected, Score: r.Score, Probability: r.Probability,
			Consecutive: s.Consecutive, Confirmed: now,
		}
		s.Abnormal = &abnormal
		s.Isolated, s.Held = true, true
		if s.Trigger.At.IsZero() {
			s.Trigger = trigger
		}
		if !cfg.AutoDisable {
			return "held_by_policy"
		}
		if !g.host.CanMutate() {
			return "host_mutation_unavailable"
		}
		if trigger.Model != "" && j.Model != trigger.Model {
			return "different_model"
		}
		// Persist the isolation before requesting the authoritative mutation.
		if g.save() != nil {
			return "persistence_failed"
		}
		disabled := abnormal
		disabled.DisabledAt, disabled.PluginDisabled = now, true
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := g.host.Disable(writeCtx, j.Auth, disabled); err != nil {
			return "host_write_failed"
		}
		s.Abnormal = &disabled
		auth := g.inventory[j.ID]
		auth.Disabled = true
		g.inventory[j.ID] = auth
		return "disabled"
	case Transient, Inconclusive:
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

func (g *Guard) retry(now time.Time, s *AuthState, reason string, cfg Config) string {
	if s.Retries >= cfg.MaxRetries {
		s.Held = s.Isolated
		return "retries_exhausted"
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

func (g *Guard) expire(id string, s *AuthState, release bool) {
	if j := g.running[id]; j != nil {
		j.cancel()
	}
	if release {
		g.release(s)
	} else {
		s.Held, s.Pending, s.Due = true, "", time.Time{}
	}
	g.dirty = true
}

func (g *Guard) release(s *AuthState) {
	s.Isolated, s.Held, s.Retries, s.Consecutive = false, false, 0, 0
	s.Trigger, s.Pending, s.Due = Trigger{}, "", time.Time{}
}

func (g *Guard) trimHistory() {
	if excess := len(g.state.History) - g.state.Config.HistoryLimit; excess > 0 {
		g.state.History = append([]Record(nil), g.state.History[excess:]...)
	}
}
