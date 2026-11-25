package guard

import (
	"context"
	"time"
)

type Auth struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Provider      string    `json:"provider"`
	Disabled      bool      `json:"disabled"`
	Cooling       bool      `json:"cooling"`
	CooldownUntil time.Time `json:"cooldown_until,omitzero"`
	Probeable     bool      `json:"probeable"`
	ProbeFormat   string    `json:"-"`
	Version       string    `json:"-"`
}

type Status string

const (
	Match        Status = "match"
	Mismatch     Status = "mismatch"
	Inconclusive Status = "inconclusive"
	Unsupported  Status = "unsupported"
	Transient    Status = "transient"
	Cancelled    Status = "cancelled"
)

type Result struct {
	ReferenceBuild string    `json:"reference_build,omitempty"`
	Status         Status    `json:"status"`
	Detected       string    `json:"detected,omitempty"`
	Score          *float64  `json:"score,omitempty"`
	Probability    *float64  `json:"probability,omitempty"`
	Reason         string    `json:"reason,omitempty"`
	Overloaded     bool      `json:"-"`
	HTTPStatus     int       `json:"http_status,omitempty"`
	CooldownUntil  time.Time `json:"-"`
}

type Probe struct {
	Auth
	Model              string
	Expected           string
	Probability        float64
	Timeout            time.Duration
	ParallelChallenges bool
}

type Host interface {
	List(context.Context) ([]Auth, error)
}

type Detector interface {
	Check(context.Context, Probe) Result
	Models() []string
}

type Trigger struct {
	Reason string    `json:"reason"`
	Model  string    `json:"failed_model,omitempty"`
	Status int       `json:"http_status,omitempty"`
	Code   string    `json:"error_code,omitempty"`
	At     time.Time `json:"at"`
}

func (t Trigger) isBusiness() bool {
	return t.Reason == "http_status" || t.Reason == "error_code" || t.Reason == "error_text"
}

type Abnormal struct {
	Trigger
	Status       string    `json:"status"`
	Expected     string    `json:"expected"`
	RequestModel string    `json:"request_model"`
	Detected     string    `json:"detected"`
	Score        *float64  `json:"score,omitempty"`
	Probability  *float64  `json:"probability,omitempty"`
	Consecutive  int       `json:"consecutive"`
	Confirmed    time.Time `json:"confirmed_at"`
	// Suppress automatic recovery for legacy plugin-disabled records.
	PluginDisabled bool `json:"plugin_disabled,omitempty"`
}

type Record struct {
	At      time.Time `json:"at"`
	AuthID  string    `json:"auth_id"`
	Name    string    `json:"name"`
	Trigger Trigger   `json:"trigger"`
	Model   string    `json:"model"`
	Expect  string    `json:"expected"`
	Result  Result    `json:"result"`
	Millis  int64     `json:"duration_ms"`
	Action  string    `json:"action"`
}

type AuthState struct {
	LastBusiness     time.Time `json:"last_business,omitzero"`
	LastCheck        time.Time `json:"last_check,omitzero"`
	Isolated         bool      `json:"isolated"`
	Held             bool      `json:"held"`
	Trigger          Trigger   `json:"trigger,omitzero"`
	Due              time.Time `json:"due,omitzero"`
	ProbeCooldown    time.Time `json:"probe_cooldown_until,omitzero"`
	IdleSkippedAt    time.Time `json:"idle_skipped_at,omitzero"`
	RecheckSkippedAt time.Time `json:"recheck_skipped_at,omitzero"`
	GatewaySkippedAt time.Time `json:"gateway_skipped_at,omitzero"`
	Pending          string    `json:"pending,omitempty"`
	Retries          int       `json:"retries"`
	GatewayFailures  int       `json:"gateway_failures,omitempty"`
	Consecutive      int       `json:"consecutive"`
	LastModel        string    `json:"last_model,omitempty"`
	LastExpected     string    `json:"last_expected,omitempty"`
	LastResult       Result    `json:"last_result,omitzero"`
	Abnormal         *Abnormal `json:"abnormal,omitempty"`
	Version          string    `json:"version,omitempty"`
	WatchUntil       time.Time `json:"watch_until,omitzero"`
}
