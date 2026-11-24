package guard

import "testing"

func TestPolicyPrecedenceAndTarget(t *testing.T) {
	cfg := DefaultConfig()
	yes, no := true, false
	alias := "customer-alias"
	cfg.Enabled = true
	cfg.Providers["claude"] = Override{Enabled: &no, Idle: &no, Model: &alias}
	cfg.Auths["auth-a"] = Override{Enabled: &yes, Trigger: &no}
	cfg.ExpectedModels[alias] = "reference"
	cfg.ExpectedModels["failed-alias"] = "failed-reference"
	p := cfg.Policy("auth-a", "Claude")
	if !p.Enabled || p.Idle || p.Trigger {
		t.Fatalf("unexpected policy: %+v", p)
	}
	if model, expected := cfg.Target(p, "unmapped"); model != alias || expected != "reference" {
		t.Fatalf("target = %q, %q", model, expected)
	}
	if model, expected := cfg.Target(p, "failed-alias"); model != "failed-alias" || expected != "failed-reference" {
		t.Fatalf("event target = %q, %q", model, expected)
	}
	cfg.Enabled = false
	if cfg.Policy("auth-a", "claude").Enabled {
		t.Fatal("an override bypassed the global switch")
	}
}

func TestValidateConfig(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.ScanSeconds = 0 },
		func(c *Config) { c.MismatchRecheckSeconds = 0 },
		func(c *Config) { c.MismatchRecheckSeconds = 2592001 },
		func(c *Config) { c.HTTPStatuses = []int{200} },
		func(c *Config) { c.MinProbability = 1.1 },
		func(c *Config) { c.PerProvider = c.MaxConcurrent + 1 },
		func(c *Config) { c.ErrorTexts = []string{""} },
		func(c *Config) { c.Expiry = "unknown" },
	} {
		cfg := DefaultConfig()
		change(&cfg)
		if cfg.Validate() == nil {
			t.Fatalf("accepted invalid config: %+v", cfg)
		}
	}
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}
