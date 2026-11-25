package guard

import (
	"testing"
	"time"
)

func TestGatewayExhaustionRechecksOriginalBusinessModel(t *testing.T) {
	g, _, d, now := setupGuard(t, Transient)
	cfg := &g.state.Config
	cfg.Default.Idle, cfg.PreferFailed = false, false
	cfg.MaxRetries, cfg.GatewayRecheckSeconds = 1, 3600
	cfg.ExpectedModels["business-alias"] = "business-reference"
	d.result.HTTPStatus = 502
	close(d.done)
	g.Begin("request", "a")
	g.Observe("request", "a", "business-alias", 503, "", "")
	g.Complete("request")
	g.step()
	if p := nextProbe(t, d); p.Model != "fixture" {
		t.Fatalf("short probe = %+v", p)
	}
	g.wg.Wait()
	s := g.View().Auths[0]
	if s.Retries != 1 || s.Pending != "error" {
		t.Fatalf("first attempt = %+v", s)
	}

	d.result.HTTPStatus = 503
	*now = s.Due
	g.step()
	nextProbe(t, d)
	g.wg.Wait()
	s = g.View().Auths[0]
	if !s.Isolated || !s.Held || s.Pending != gatewayRecheck || !s.Due.Equal(now.Add(time.Hour)) {
		t.Fatalf("exhausted gateway quarantine = %+v", s)
	}
	view := g.View()
	updated := view.Config
	updated.GatewayRecheckSeconds = 7200
	if err := g.UpdateConfig(view.Revision, updated); err != nil {
		t.Fatal(err)
	}
	s = g.View().Auths[0]
	if !s.NextProbe.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("changed recovery interval did not take effect: %+v", s)
	}

	g.Close()
	restored, err := Open(g.path, DefaultConfig(), g.host, d)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restored.now = func() time.Time { return *now }
	*now = s.Due.Add(-time.Second)
	restored.step()
	if a := restored.View().Auths[0]; !a.Isolated || a.Running {
		t.Fatalf("probe ran before the recovery interval: %+v", a)
	}
	*now = s.Due
	restored.step()
	if p := nextProbe(t, d); p.ID != "a" || p.Model != "business-alias" || p.Expected != "business-reference" {
		t.Fatalf("recovery tried a different target: %+v", p)
	}
	restored.wg.Wait()
	s = restored.View().Auths[0]
	if !s.Isolated || !s.Due.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("unsuccessful recovery = %+v", s)
	}

	d.result = Result{Status: Match}
	*now = s.Due
	restored.step()
	nextProbe(t, d)
	restored.wg.Wait()
	if restored.Isolated("a") {
		t.Fatal("match on the original credential and model left it isolated")
	}
}

func TestActualGatewayFailureStillCountsWhenItStartsCooldown(t *testing.T) {
	g, _, d, now := setupGuard(t, Transient)
	g.state.Config.Default.Idle = false
	cooldown := now.Add(30 * time.Second)
	d.result = Result{Status: Transient, HTTPStatus: 503, CooldownUntil: cooldown}
	close(d.done)
	g.Begin("request", "a")
	g.Observe("request", "a", "fixture", 503, "", "")
	g.step()
	nextProbe(t, d)
	g.wg.Wait()
	if a := g.View().Auths[0]; a.Retries != 1 || a.GatewayFailures != 1 || !a.NextProbe.Equal(cooldown) {
		t.Fatalf("actual failed attempt and subsequent cooldown = %+v", a)
	}
}

func TestBusinessCooldownDefersWithoutConsumingRetry(t *testing.T) {
	g, h, d, now := setupGuard(t, Transient)
	g.state.Config.Default.Idle = false
	g.state.Config.ScanSeconds = 1
	g.state.Config.MaxRetries = 1
	known := now.Add(30 * time.Second)
	h.auths[0].CooldownUntil = known
	g.nextScan = time.Time{}
	g.Begin("request", "a")
	g.Observe("request", "a", "fixture", 502, "", "")
	g.step()
	if a := g.View().Auths[0]; a.Running || a.Retries != 0 || !a.NextProbe.Equal(known) {
		t.Fatalf("known cooldown = %+v", a)
	}
	*now = known
	reported := now.Add(time.Minute)
	d.result = Result{Status: Transient, HTTPStatus: 429, CooldownUntil: reported}
	close(d.done)
	g.step()
	nextProbe(t, d)
	g.wg.Wait()
	if a := g.View().Auths[0]; a.Retries != 0 || !a.NextProbe.Equal(reported) || a.GatewayFailures != 0 {
		t.Fatalf("model cooldown used retry budget: %+v", a)
	}
	d.result = Result{Status: Transient, HTTPStatus: 503}
	*now = reported
	g.step()
	nextProbe(t, d)
	g.wg.Wait()
	if a := g.View().Auths[0]; a.Retries != 1 || !a.Due.Equal(now.Add(time.Minute)) {
		t.Fatalf("missing cooldown did not use the plugin backoff: %+v", a)
	}
}

func TestIdleGatewayFailureDoesNotIsolate(t *testing.T) {
	g, _, d, now := setupGuard(t, Transient)
	d.result.HTTPStatus = 503
	close(d.done)
	*now = now.Add(time.Minute)
	g.step()
	p := nextProbe(t, d)
	g.wg.Wait()
	if g.Isolated(p.ID) {
		t.Fatal("idle gateway failure isolated a credential")
	}
}
