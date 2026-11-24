package guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStateDurabilityAndDamagedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := loadState(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	s.Config.Enabled = true
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	s.Auths["auth-a"] = &AuthState{Isolated: true, Pending: "error", Due: now}
	if err := saveState(path, s); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !json.Valid(data) || !strings.Contains(string(data), now.Format(time.RFC3339)) {
		t.Fatalf("unexpected saved state, err = %v", err)
	}
	restored, err := loadState(path, DefaultConfig())
	if err != nil || !restored.Config.Enabled || !restored.Auths["auth-a"].Isolated {
		t.Fatalf("recovered state = %+v, %v", restored, err)
	}
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(path, DefaultConfig()); err == nil {
		t.Fatal("corrupt state was reset")
	}
}
