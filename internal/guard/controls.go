package guard

import (
	"context"
	"slices"
	"strings"
	"time"
)

type AuthView struct {
	Auth
	AuthState
	Policy  Policy `json:"policy"`
	Running bool   `json:"running"`
	Active  int    `json:"active"`
}

type View struct {
	Revision       uint64     `json:"revision"`
	Config         Config     `json:"config"`
	Auths          []AuthView `json:"auths"`
	History        []Record   `json:"history"`
	Models         []string   `json:"models"`
	CanMutate      bool       `json:"can_mutate"`
	StorageError   bool       `json:"storage_error"`
	InventoryError bool       `json:"inventory_error"`
	OverloadUntil  time.Time  `json:"overload_until,omitzero"`
}

func (g *Guard) View() View {
	g.mu.Lock()
	defer g.mu.Unlock()
	v := View{
		Config: g.state.Config, Revision: g.state.Revision,
		Auths: make([]AuthView, 0, len(g.inventory)), History: append([]Record{}, g.state.History...),
		Models: g.detector.Models(), CanMutate: g.host.CanMutate(),
		StorageError: g.storageErr, InventoryError: g.listErr, OverloadUntil: g.pauses[""],
	}
	for id, a := range g.inventory {
		v.Auths = append(v.Auths, AuthView{a, *g.state.Auths[id], g.state.Config.Policy(id, a.Provider), g.running[id] != nil, g.active[id]})
	}
	slices.SortFunc(v.Auths, func(a, b AuthView) int {
		if cmp := strings.Compare(a.Name, b.Name); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.ID, b.ID)
	})
	slices.Reverse(v.History)
	return v
}

func (g *Guard) UpdateConfig(revision uint64, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.updateConfig(revision, cfg)
}

func (g *Guard) UpdateAuths(revision uint64, overrides map[string]Override) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	cfg := g.state.Config
	cfg.Auths = make(map[string]Override, len(cfg.Auths)+len(overrides))
	for id, ov := range g.state.Config.Auths {
		cfg.Auths[id] = ov
	}
	for id, ov := range overrides {
		if _, known := g.inventory[id]; !known {
			return ErrUnknownAuth
		}
		if ov == (Override{}) {
			delete(cfg.Auths, id)
		} else {
			cfg.Auths[id] = ov
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	return g.updateConfig(revision, cfg)
}

func (g *Guard) updateConfig(revision uint64, cfg Config) error {
	if revision != g.state.Revision {
		return ErrConflict
	}
	next := g.state
	next.Config = cfg
	next.Revision++
	// A failed configuration write does not change the active configuration.
	if err := saveState(g.path, next); err != nil {
		g.storageErr = true
		return err
	}
	g.state = next
	g.storageErr, g.dirty = false, false
	for _, j := range g.running {
		j.cancel()
	}
	clear(g.failures)
	for _, s := range g.state.Auths {
		s.Consecutive = 0
	}
	g.dirty = true
	g.nextScan = time.Time{}
	g.signal()
	return nil
}

func (g *Guard) Act(ctx context.Context, action, id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	a, known := g.inventory[id]
	if !known {
		return ErrUnknownAuth
	}
	s := g.state.Auths[id]
	p := g.state.Config.Policy(id, a.Provider)
	now := g.now().UTC()
	if a.Disabled && action != "recover" && action != "release" {
		return ErrUnavailable
	}
	switch action {
	case "check":
		if !p.Enabled || !a.Probeable {
			return ErrUnavailable
		}
		if g.running[id] != nil || s.Pending == "error" {
			return nil
		}
		s.Pending, s.Due, s.Retries = "manual", now, 0
	case "isolate":
		if s.Isolated {
			return nil
		}
		if j := g.running[id]; j != nil {
			j.cancel()
		}
		s.Isolated, s.Held = true, true
		s.Pending, s.Due = "", time.Time{}
		s.Trigger = Trigger{Reason: "manual", At: now}
	case "release":
		if s.Abnormal != nil && s.Abnormal.PluginDisabled {
			return ErrUnavailable
		}
		if j := g.running[id]; j != nil {
			j.cancel()
		}
		g.release(s)
	case "recover":
		if !g.host.CanMutate() || !a.Disabled || s.Abnormal == nil || !s.Abnormal.PluginDisabled {
			return ErrUnavailable
		}
		if err := g.host.Recover(ctx, a, *s.Abnormal); err != nil {
			return err
		}
		a.Disabled = false
		g.inventory[id] = a
		s.Abnormal = nil
		g.release(s)
	default:
		return ErrUnavailable
	}
	g.signal()
	return g.save()
}
