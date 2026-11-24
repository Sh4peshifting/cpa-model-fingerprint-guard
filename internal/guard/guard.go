package guard

import (
	"context"
	"errors"
	"math/rand/v2"
	"path/filepath"
	"sync"
	"time"
)

type job struct {
	Probe
	reason   string
	trigger  Trigger
	revision uint64
	cancel   context.CancelFunc
}

type requestActivity struct {
	auths map[string]struct{}
	done  time.Time
}

type failureWindow struct {
	first Trigger
	last  time.Time
	count int
}

type Guard struct {
	mu         sync.Mutex
	wg         sync.WaitGroup
	host       Host
	detector   Detector
	path       string
	now        func() time.Time
	jitter     func(int) time.Duration
	ctx        context.Context
	cancel     context.CancelFunc
	wake       chan struct{}
	state      state
	inventory  map[string]Auth
	active     map[string]int
	requests   map[string]*requestActivity
	failures   map[string]failureWindow
	running    map[string]*job
	pauses     map[string]time.Time
	overloads  map[string]int
	nextScan   time.Time
	dirty      bool
	storageErr bool
	listErr    bool
}

func Open(path string, initial Config, host Host, detector Detector) (*Guard, error) {
	var err error
	if path, err = filepath.Abs(path); err != nil {
		return nil, err
	}
	state, err := loadState(path, initial)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Guard{
		host: host, detector: detector, path: path, now: time.Now, jitter: randomDelay,
		ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), state: state,
		inventory: map[string]Auth{}, active: map[string]int{}, requests: map[string]*requestActivity{},
		failures: map[string]failureWindow{}, running: map[string]*job{},
		pauses: map[string]time.Time{}, overloads: map[string]int{},
	}, nil
}

func randomDelay(max int) time.Duration {
	if max == 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(seconds(max)) + 1))
}

func (g *Guard) Start() {
	g.wg.Go(g.loop)
}

func (g *Guard) Close() {
	g.cancel()
	g.wg.Wait()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.dirty {
		g.save()
	}
}

func (g *Guard) signal() {
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

// save runs with mu held. Failed writes leave in-memory quarantine enforced.
func (g *Guard) save() error {
	err := saveState(g.path, g.state)
	g.storageErr = err != nil
	g.dirty = err != nil
	return err
}

func (g *Guard) Isolated(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.state.Auths[id]
	return s != nil && s.Isolated
}

// Begin returns false when the selected credential must be skipped. One request
// can attempt several credentials, so all observed IDs remain active until its
// terminal event arrives.
func (g *Guard) Begin(request, id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.state.Auths[id]
	if s != nil && s.Isolated {
		return false
	}
	if id == "" || request == "" {
		return true
	}
	r := g.requests[request]
	if r == nil {
		r = &requestActivity{auths: map[string]struct{}{}}
		g.requests[request] = r
	}
	if _, seen := r.auths[id]; seen {
		return true
	}
	r.auths[id] = struct{}{}
	g.active[id]++
	if s != nil {
		s.LastBusiness = g.now().UTC()
		g.dirty = true
	}
	if j := g.running[id]; j != nil && j.reason == "idle" {
		j.cancel()
	}
	return true
}

func (g *Guard) Complete(request string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	r := g.requests[request]
	if r == nil || !r.done.IsZero() {
		return
	}
	r.done = g.now().UTC()
	for id := range r.auths {
		if g.active[id] > 1 {
			g.active[id]--
		} else {
			delete(g.active, id)
		}
		if s := g.state.Auths[id]; s != nil {
			s.LastBusiness = r.done
			g.dirty = true
		}
	}
}

func (g *Guard) loop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for g.ctx.Err() == nil {
		g.step()
		select {
		case <-g.ctx.Done():
		case <-g.wake:
		case <-ticker.C:
		}
	}
}

func (g *Guard) step() {
	now := g.now().UTC()
	g.mu.Lock()
	scan := !now.Before(g.nextScan)
	if scan {
		g.nextScan = now.Add(seconds(g.state.Config.ScanSeconds))
	}
	g.mu.Unlock()

	if scan {
		ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
		auths, err := g.host.List(ctx)
		cancel()
		g.mu.Lock()
		g.listErr = err != nil
		if err == nil {
			g.reconcile(now, auths)
		}
		g.mu.Unlock()
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx.Err() != nil {
		return
	}
	g.schedule(now, scan && !g.listErr)
	if g.dirty {
		g.save()
	}
}

func (g *Guard) reconcile(now time.Time, auths []Auth) {
	cfg := g.state.Config
	inventory := make(map[string]Auth, len(auths))
	for _, a := range auths {
		if a.ID == "" {
			continue
		}
		inventory[a.ID] = a
		s := g.state.Auths[a.ID]
		if s == nil {
			s = &AuthState{}
			g.state.Auths[a.ID] = s
		}
		if s.Version == a.Version && !s.WatchUntil.IsZero() {
			continue
		}
		if j := g.running[a.ID]; j != nil {
			j.cancel()
		}
		s.Version = a.Version
		s.Consecutive = 0
		s.WatchUntil = now.Add(seconds(cfg.IdleSeconds))
		g.dirty = true
	}
	for id, s := range g.state.Auths {
		if _, present := inventory[id]; present {
			continue
		}
		if j := g.running[id]; j != nil {
			j.cancel()
		}
		// Keep unresolved quarantine through temporary omissions from the host list.
		if !s.Isolated && (s.Abnormal == nil || !s.Abnormal.PluginDisabled) {
			delete(g.state.Auths, id)
			delete(g.failures, id)
			g.dirty = true
		}
	}
	g.inventory = inventory
	for id, r := range g.requests {
		if !r.done.IsZero() && now.Sub(r.done) > 10*time.Minute {
			delete(g.requests, id)
		}
	}
	for id, window := range g.failures {
		if now.Sub(window.last) > max(time.Minute, seconds(cfg.DedupeSeconds)*2) {
			delete(g.failures, id)
		}
	}
	for key, until := range g.pauses {
		if !now.Before(until) {
			delete(g.pauses, key)
		}
	}
}

var (
	ErrUnknownAuth = errors.New("认证文件不存在")
	ErrUnavailable = errors.New("当前认证或操作不可用")
	ErrConflict    = errors.New("配置已变更，请刷新后重试")
)
