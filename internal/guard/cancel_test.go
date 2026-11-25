package guard

import (
	"errors"
	"testing"
	"time"
)

func TestCancelQueuedProbeLeavesRunningProbeAlone(t *testing.T) {
	g, _, d, _ := setupGuard(t, Match)
	g.state.Config.Default.Idle = false
	if err := g.Act("check", "a"); err != nil {
		t.Fatal(err)
	}
	g.step()
	nextProbe(t, d)
	if err := g.Act("check", "b"); err != nil {
		t.Fatal(err)
	}
	g.step()
	if err := g.Act("cancel", "a"); !errors.Is(err, ErrNoQueuedProbe) {
		t.Fatalf("cancel running probe = %v", err)
	}
	if err := g.Act("cancel", "b"); err != nil {
		t.Fatal(err)
	}
	if err := g.Act("cancel", "b"); !errors.Is(err, ErrNoQueuedProbe) {
		t.Fatalf("cancel missing probe = %v", err)
	}
	close(d.done)
	g.wg.Wait()
	g.step()
	view := g.View()
	if b := view.Auths[1]; b.Running || b.Pending != "" || !b.LastCheck.IsZero() {
		t.Fatalf("cancelled probe still ran: %+v", b)
	}
	if len(view.History) != 1 || view.History[0].AuthID != "a" || view.History[0].Result.Status != Match {
		t.Fatalf("history = %+v", view.History)
	}
}

func TestCancellingIdleProbeSkipsOnlyOneCycle(t *testing.T) {
	g, h, d, now := setupGuard(t, Match)
	*now = time.Now().UTC()
	cfg := &g.state.Config
	cfg.ScanSeconds, cfg.IntervalSeconds = 1, 60
	off := false
	cfg.Auths = map[string]Override{"b": {Enabled: &off}}
	s := g.state.Auths["a"]
	lastCheck := now.Add(-time.Hour)
	s.Pending, s.Due, s.LastCheck = "idle", now.Add(time.Second), lastCheck

	if err := g.Act("cancel", "a"); err != nil {
		t.Fatal(err)
	}
	g.Close()
	reopened, err := Open(g.path, DefaultConfig(), h, d)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return *now }
	due := now.Add(time.Minute)
	*now = due.Add(-time.Second)
	reopened.step()
	if a := reopened.View().Auths[0]; a.Pending != "" || a.Running || !a.LastCheck.Equal(lastCheck) {
		t.Fatalf("idle check ran before the next cycle: %+v", a)
	}
	close(d.done)
	*now = due
	reopened.step()
	if p := nextProbe(t, d); p.ID != "a" {
		t.Fatalf("next idle round tested the wrong target: %+v", p)
	}
	reopened.wg.Wait()
}

func TestCancellingRechecksLeavesManualOnlyQuarantine(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		scheduled    bool
		legacy       bool
	}{
		{name: "queued mismatch", reason: mismatchRecheck},
		{name: "scheduled mismatch", reason: mismatchRecheck, scheduled: true},
		{name: "queued gateway", reason: gatewayRecheck},
		{name: "legacy mismatch", reason: mismatchRecheck, legacy: true},
		{name: "legacy gateway", reason: gatewayRecheck, legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, h, d, now := setupGuard(t, Transient)
			cfg := &g.state.Config
			cfg.ScanSeconds, cfg.MismatchRecheckSeconds, cfg.GatewayRecheckSeconds = 1, 120, 180
			cfg.Default.Idle = false
			cfg.Default.Model, cfg.Default.Expect = "different-model", "different-reference"
			cfg.ExpectedModels["fixture"] = "fixture-reference"
			s := g.state.Auths["a"]
			lastCheck := now.Add(-time.Second)
			s.Isolated, s.Held, s.LastCheck = true, true, lastCheck
			s.Trigger = Trigger{Reason: "http_status", Model: "fixture", Status: 503, At: lastCheck}
			if tc.reason == mismatchRecheck {
				s.Abnormal = &Abnormal{Confirmed: lastCheck, RequestModel: "fixture", Expected: "fixture-reference"}
			}
			if !tc.scheduled {
				s.Pending, s.Due = tc.reason, now.Add(time.Second)
			}
			if tc.legacy {
				switch tc.reason {
				case mismatchRecheck:
					s.LegacyRecheckSkippedAt = *now
				case gatewayRecheck:
					s.LegacyGatewaySkippedAt = *now
				}
				if err := g.save(); err != nil {
					t.Fatal(err)
				}
			} else if err := g.Act("cancel", "a"); err != nil {
				t.Fatal(err)
			}
			g.Close()
			reopened, err := Open(g.path, DefaultConfig(), h, d)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			reopened.now = func() time.Time { return *now }

			assertHeld := func() {
				t.Helper()
				a := reopened.View().Auths[0]
				if a.Pending != "" || a.Running || !a.Isolated || !a.Held || a.CancelledRecheck != tc.reason ||
					!a.NextProbe.IsZero() || !a.NextRecheck.IsZero() {
					t.Fatalf("expected manual-only quarantine: %+v", a)
				}
			}
			*now = now.Add(24 * time.Hour)
			reopened.step()
			assertHeld()
			if len(reopened.View().History) != 0 || !reopened.View().Auths[0].LastCheck.Equal(lastCheck) {
				t.Fatal("the cancelled automatic recheck ran after restart")
			}

			d.result.HTTPStatus = 503
			close(d.done)
			if err := reopened.Act("check", "a"); err != nil {
				t.Fatal(err)
			}
			reopened.step()
			if p := nextProbe(t, d); p.ID != "a" || p.Model != "fixture" || p.Expected != "fixture-reference" {
				t.Fatalf("manual check changed the original recheck target: %+v", p)
			}
			reopened.wg.Wait()
			assertHeld()
			*now = now.Add(24 * time.Hour)
			reopened.step()
			assertHeld()

			d.result = Result{Status: Match}
			if err := reopened.Act("check", "a"); err != nil {
				t.Fatal(err)
			}
			reopened.step()
			nextProbe(t, d)
			reopened.wg.Wait()
			if a := reopened.View().Auths[0]; a.Isolated || a.Held || a.CancelledRecheck != "" {
				t.Fatalf("matching manual check left the auth quarantined: %+v", a)
			}
		})
	}
}
