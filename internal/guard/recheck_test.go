package guard

import (
	"testing"
	"time"
)

func TestConfirmedMismatchRechecksAtTwoDaysAfterRestart(t *testing.T) {
	g, h, d, now := setupGuard(t, Mismatch)
	cfg := g.View().Config
	cfg.Default.Idle = false
	cfg.ScanSeconds = 1
	if err := g.UpdateConfig(g.View().Revision, cfg); err != nil {
		t.Fatal(err)
	}
	g.Begin("business", "a")
	g.Observe("business", "a", "fixture", 503, "", "")
	g.Complete("business")
	close(d.done)
	g.step()
	nextProbe(t, d)
	g.wg.Wait()

	wantDue := now.Add(48 * time.Hour)
	if a := g.View().Auths[0]; a.Abnormal == nil || !a.Isolated || !a.NextRecheck.Equal(wantDue) {
		t.Fatalf("confirmed mismatch did not get a two-day recheck: %+v", a)
	}
	// Recovery does not depend on either trigger switch or on today's default model.
	cfg.Default.Trigger = false
	cfg.Default.Model, cfg.Default.Expect = "other-model", "other-reference"
	if err := g.UpdateConfig(g.View().Revision, cfg); err != nil {
		t.Fatal(err)
	}
	g.Close()
	d.result = Result{Status: Match}
	h.auths[0].Cooling = true
	restarted, err := Open(g.path, DefaultConfig(), h, d)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restarted.now = func() time.Time { return *now }
	*now = wantDue.Add(-time.Second)
	restarted.step()
	if a := restarted.View().Auths[0]; !a.Isolated || a.Running || !a.NextRecheck.Equal(wantDue) {
		t.Fatalf("recheck ran before its restored deadline: %+v", a)
	}
	*now = wantDue
	restarted.step()
	if probe := nextProbe(t, d); probe.ID != "a" || probe.Model != "fixture" || probe.Expected != "fixture-reference" {
		t.Fatalf("recheck used an unrelated model: %+v", probe)
	}
	restarted.wg.Wait()

	v := restarted.View()
	a, record := v.Auths[0], v.History[0]
	if a.Isolated || a.Held || a.Abnormal != nil || !a.Cooling || !a.NextRecheck.IsZero() {
		t.Fatalf("recheck did not release only plugin quarantine: %+v", a)
	}
	if record.Trigger.Reason != mismatchRecheck || record.Result.Status != Match || record.Action != "matched" {
		t.Fatalf("recheck history = %+v", record)
	}
}

func TestUnsuccessfulRecheckStaysIsolatedAndUsesConfiguredInterval(t *testing.T) {
	for _, result := range []Status{Mismatch, Inconclusive, Transient, Unsupported, Cancelled} {
		t.Run(string(result), func(t *testing.T) {
			g, _, d, now := setupGuard(t, result)
			cfg := g.View().Config
			cfg.MismatchRecheckSeconds, cfg.ScanSeconds = 120, 1
			cfg.Default.Idle, cfg.Default.Trigger = false, false
			if err := g.UpdateConfig(g.View().Revision, cfg); err != nil {
				t.Fatal(err)
			}
			confirmed := now.Add(-time.Hour)
			s := g.state.Auths["a"]
			s.Isolated, s.Held, s.LastCheck = true, true, confirmed
			s.Trigger = Trigger{Reason: "http_status", At: confirmed}
			s.Pending, s.Due = "confirm", confirmed
			s.Abnormal = &Abnormal{Confirmed: confirmed, RequestModel: "fixture", Expected: "fixture-reference"}
			*now = now.Add(3 * time.Hour)

			close(d.done)
			g.step()
			nextProbe(t, d)
			g.wg.Wait()
			v := g.View()
			a, record := v.Auths[0], v.History[0]
			if !a.Isolated || !a.Held || a.Abnormal == nil || !a.Abnormal.Confirmed.Equal(confirmed) {
				t.Fatalf("unsuccessful recheck altered the confirmed quarantine: %+v", a)
			}
			due := now.Add(2 * time.Minute)
			if a.Pending != "" || !a.NextRecheck.Equal(due) {
				t.Fatalf("unexpected follow-up state: %+v", a)
			}
			if record.Trigger.Reason != mismatchRecheck || record.Result.Status != result || record.Action != "recheck_kept_isolated" {
				t.Fatalf("recheck history = %+v", record)
			}

			*now = due.Add(-time.Second)
			g.step()
			if g.View().Auths[0].Running {
				t.Fatal("retry reused the short backoff")
			}
			d.result = Result{Status: Match}
			*now = due
			g.step()
			nextProbe(t, d)
			g.wg.Wait()
			if g.Isolated("a") {
				t.Fatal("later match did not release the quarantine")
			}
		})
	}
}

func TestRecheckEligibility(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Auth, *AuthState, *Config)
	}{
		{"disabled by host", func(a *Auth, _ *AuthState, _ *Config) { a.Disabled = true }},
		{"disabled by plugin", func(_ *Auth, s *AuthState, _ *Config) { s.Abnormal.PluginDisabled = true }},
		{"globally disabled", func(_ *Auth, _ *AuthState, c *Config) { c.Enabled = false }},
		{"per-auth detection disabled", func(a *Auth, _ *AuthState, c *Config) {
			off := false
			c.Auths[a.ID] = Override{Enabled: &off}
		}},
		{"another quarantine", func(_ *Auth, s *AuthState, _ *Config) {
			s.Trigger = Trigger{Reason: "manual", At: s.Abnormal.Confirmed.Add(time.Minute)}
		}},
		{"unconfirmed quarantine", func(_ *Auth, s *AuthState, _ *Config) { s.Abnormal = nil }},
		{"unsupported route", func(a *Auth, _ *AuthState, _ *Config) { a.Probeable = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Enabled = true
			auth := Auth{ID: "a", Probeable: true}
			state := AuthState{
				Isolated: true,
				Abnormal: &Abnormal{Confirmed: time.Now(), RequestModel: "model", Expected: "expected"},
			}
			tc.change(&auth, &state, &cfg)
			if due := mismatchRecheckDue(auth, &state, cfg.Policy(auth.ID, auth.Provider), cfg); !due.IsZero() {
				t.Fatalf("ineligible recheck scheduled at %v", due)
			}
		})
	}
}

func TestRecheckMatchDoesNotClearAnUnverifiedTriggerModel(t *testing.T) {
	g, _, d, now := setupGuard(t, Match)
	g.state.Config.Default.Idle = false
	s := g.state.Auths["a"]
	s.Isolated, s.Held = true, true
	s.Trigger = Trigger{Reason: "http_status", Model: "a-different-failed-model", At: now.Add(-72 * time.Hour)}
	s.Abnormal = &Abnormal{Confirmed: s.Trigger.At, RequestModel: "fixture", Expected: "fixture-reference"}
	*now = now.Add(time.Minute)
	close(d.done)
	g.step()
	nextProbe(t, d)
	g.wg.Wait()

	v := g.View()
	if a := v.Auths[0]; !a.Isolated || a.Abnormal == nil || a.NextRecheck.IsZero() {
		t.Fatalf("a different model cleared the guard: %+v", a)
	}
	if v.History[0].Action != "different_model" {
		t.Fatalf("unexpected history: %+v", v.History[0])
	}
}
