package guard

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

type testHost struct {
	auths []Auth
}

func (h *testHost) List(context.Context) ([]Auth, error) { return slices.Clone(h.auths), nil }

type testDetector struct {
	result Result
	start  chan Probe
	done   chan struct{}
}

func (d *testDetector) Models() []string { return []string{"fixture-reference"} }
func (d *testDetector) Check(ctx context.Context, p Probe) Result {
	d.start <- p
	select {
	case <-d.done:
		return d.result
	case <-ctx.Done():
		return Result{Status: Cancelled}
	}
}

func setupGuard(t *testing.T, result Status) (*Guard, *testHost, *testDetector, *time.Time) {
	t.Helper()
	c := DefaultConfig()
	c.Enabled, c.IdleSeconds, c.ConfirmRounds, c.JitterSeconds = true, 10, 1, 0
	c.Default.Model, c.Default.Expect = "fixture", "fixture-reference"
	h := &testHost{auths: []Auth{
		{ID: "a", Name: "a.json", Provider: "p", Probeable: true, Version: "v1"},
		{ID: "b", Name: "b.json", Provider: "p", Probeable: true, Version: "v1"},
	}}
	d := &testDetector{result: Result{Status: result}, start: make(chan Probe, 4), done: make(chan struct{})}
	g, err := Open(filepath.Join(t.TempDir(), "state.json"), c, h, d)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	g.step()
	t.Cleanup(g.Close)
	return g, h, d, &now
}

func nextProbe(t *testing.T, d *testDetector) Probe {
	t.Helper()
	select {
	case p := <-d.start:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("expected a probe")
		return Probe{}
	}
}

func TestQuarantineRetryAndRestart(t *testing.T) {
	g, _, d, now := setupGuard(t, Transient)
	g.Observe("unknown", "a", "fixture", 503, "", "")
	if g.Isolated("a") {
		t.Fatal("unattributed event was accepted")
	}
	g.Begin("req", "a")
	g.Observe("req", "a", "fixture", 503, "", "")
	g.Observe("req", "a", "fixture", 502, "", "")
	if !g.Isolated("a") || g.Isolated("b") || g.Begin("new", "a") || !g.Begin("new", "b") {
		t.Fatal("the wrong credential was isolated")
	}
	g.Complete("req")
	g.step()
	if p := nextProbe(t, d); p.ID != "a" || p.Model != "fixture" {
		t.Fatalf("unexpected probe %+v", p)
	}
	close(d.done)
	g.wg.Wait()
	view := g.View()
	if len(view.History) != 1 || view.History[0].Action != "retry_scheduled" {
		t.Fatalf("history = %+v", view.History)
	}
	if got := view.Auths[0].Due; !got.Equal(now.Add(seconds(view.Config.RetrySeconds))) {
		t.Fatalf("retry due at %v", got)
	}
	restored, err := Open(g.path, view.Config, g.host, d)
	if err != nil || !restored.Isolated("a") {
		t.Fatalf("quarantine lost after restart: %v", err)
	}
	restored.Close()
}

func TestBusinessStreamPreventsIdleAndMismatchIsolates(t *testing.T) {
	g, _, d, now := setupGuard(t, Mismatch)
	g.Begin("stream", "a")
	g.Begin("stream", "a")
	*now = now.Add(time.Minute)
	g.step()
	if p := nextProbe(t, d); p.ID != "b" {
		t.Fatalf("expected idle b, got %+v", p)
	}
	close(d.done)
	g.wg.Wait()
	g.Complete("stream")
	v := g.View()
	if v.Auths[0].Active != 0 || !v.Auths[0].LastBusiness.Equal(*now) {
		t.Fatalf("stream was not completed: %+v", v.Auths[0])
	}
	if !v.Auths[1].Isolated || v.Auths[1].Disabled || v.Auths[1].Abnormal == nil {
		t.Fatalf("expected quarantine only: %+v", v.Auths[1])
	}
}

func TestChangedCredentialDiscardsStaleMismatch(t *testing.T) {
	g, h, d, _ := setupGuard(t, Mismatch)
	if err := g.Act("check", "a"); err != nil {
		t.Fatal(err)
	}
	g.step()
	nextProbe(t, d)
	h.auths[0].Version = "v2"
	close(d.done)
	g.wg.Wait()
	if g.Isolated("a") || len(g.View().History) != 0 {
		t.Fatal("obsolete probe effected a decision")
	}
}

func TestTriggers(t *testing.T) {
	c := DefaultConfig()
	for _, tc := range []struct {
		status           int
		code, text, want string
	}{
		{502, "", "", "http_status"},
		{503, "", "", "http_status"},
		{200, "server_is_overloaded", "", "error_code"},
		{200, "", c.ErrorTexts[0], "error_text"},
		{429, "", "", ""},
		{200, "not_server_is_overloaded", "", ""},
	} {
		if got := matchFailure(c, tc.status, tc.code, tc.text); got != tc.want {
			t.Errorf("%+v: got %q", tc, got)
		}
	}
}

func TestMatchedProbeReleasesOnlyPluginQuarantine(t *testing.T) {
	g, h, d, _ := setupGuard(t, Match)
	h.auths[0].Cooling = true
	g.reconcile(g.now(), h.auths)
	g.Begin("business-a", "a", "selection-a")
	g.Observe("distinct-executor-id", "a", "fixture", 502, "", "", "selection-a")
	g.step()
	nextProbe(t, d)
	close(d.done)
	g.wg.Wait()
	view := g.View()
	if view.Auths[0].Isolated || !view.Auths[0].Cooling || view.History[0].Action != "matched" {
		t.Fatalf("match did not preserve host cooling: %+v", view.Auths[0])
	}
}

func TestEscalationRequiresDistinctBusinessRequests(t *testing.T) {
	g, _, _, _ := setupGuard(t, Transient)
	g.state.Config.TriggerCount, g.state.Config.DedupeSeconds = 2, 0
	g.Begin("one", "a")
	g.Observe("one", "a", "fixture", 503, "", "")
	g.Observe("one", "a", "fixture", 200, "server_is_overloaded", "")
	if g.Isolated("a") {
		t.Fatal("duplicate delivery counted as another business event")
	}
	g.Begin("two", "a")
	g.Observe("two", "a", "fixture", 503, "", "")
	if !g.Isolated("a") {
		t.Fatal("two independent failures did not meet the threshold")
	}
}

func TestMismatchConfirmationRestartsWhenReferenceChanges(t *testing.T) {
	g, _, d, now := setupGuard(t, Mismatch)
	g.state.Config.ConfirmRounds = 2
	g.state.Config.Default.Idle = false
	d.result.ReferenceBuild = "old"
	close(d.done)
	if err := g.Act("check", "a"); err != nil {
		t.Fatal(err)
	}
	g.step()
	nextProbe(t, d)
	g.wg.Wait()
	if got := g.View().Auths[0].Consecutive; got != 1 {
		t.Fatalf("first confirmation count = %d", got)
	}

	d.result.ReferenceBuild = "new"
	*now = now.Add(time.Minute)
	g.step()
	nextProbe(t, d)
	g.wg.Wait()
	a := g.View().Auths[0]
	if a.Consecutive != 1 || a.Abnormal != nil || a.LastResult.ReferenceBuild != "new" {
		t.Fatalf("combined evidence from different builds: %+v", a)
	}
}
