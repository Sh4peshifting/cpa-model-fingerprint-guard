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

func TestSkippingAutomaticProbePersistsUntilNextCycle(t *testing.T) {
	for _, reason := range []string{"idle", mismatchRecheck, gatewayRecheck} {
		t.Run(reason, func(t *testing.T) {
			g, h, d, now := setupGuard(t, Match)
			*now = time.Now().UTC()
			cfg := g.View().Config
			cfg.ScanSeconds = 1
			cfg.IntervalSeconds, cfg.MismatchRecheckSeconds, cfg.GatewayRecheckSeconds = 60, 120, 180
			off := false
			cfg.Auths = map[string]Override{"b": {Enabled: &off}}
			if err := g.UpdateConfig(g.View().Revision, cfg); err != nil {
				t.Fatal(err)
			}
			s := g.state.Auths["a"]
			lastCheck := now.Add(-time.Hour)
			s.Pending, s.Due, s.LastCheck = reason, now.Add(time.Second), lastCheck
			interval := cfg.IntervalSeconds
			if reason != "idle" {
				s.Isolated, s.Held = true, true
				s.Trigger = Trigger{Reason: "http_status", Model: "fixture", At: lastCheck}
			}
			switch reason {
			case mismatchRecheck:
				s.Abnormal = &Abnormal{Confirmed: lastCheck, RequestModel: "fixture", Expected: "fixture-reference"}
				interval = cfg.MismatchRecheckSeconds
			case gatewayRecheck:
				interval = cfg.GatewayRecheckSeconds
			}

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
			due := now.Add(seconds(interval))
			*now = due.Add(-time.Second)
			reopened.step()
			if a := reopened.View().Auths[0]; a.Pending != "" || a.Running || a.Isolated != (reason != "idle") || !a.LastCheck.Equal(lastCheck) {
				t.Fatalf("cancelled round affected auth or ran before the next cycle: %+v", a)
			}
			close(d.done)
			*now = due
			reopened.step()
			if p := nextProbe(t, d); p.ID != "a" || p.Model != "fixture" {
				t.Fatalf("next round tested the wrong target: %+v", p)
			}
			reopened.wg.Wait()
			if reopened.Isolated("a") {
				t.Fatal("successful round did not clear existing quarantine")
			}
		})
	}
}
