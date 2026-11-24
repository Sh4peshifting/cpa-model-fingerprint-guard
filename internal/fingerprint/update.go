package fingerprint

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"
)

var publishedSources = []string{
	"https://lm.ikale.io/data/",
	"https://cdn.jsdmirror.com/npm/lmfpd-data@latest/",
	"https://cdn.jsdelivr.net/npm/lmfpd-data@latest/",
}

type ReferenceInfo struct {
	BuiltAt   time.Time `json:"built_at"`
	Source    string    `json:"source"`
	Updating  bool      `json:"auto_update"`
	LastCheck time.Time `json:"last_check,omitzero"`
	Failed    bool      `json:"last_check_failed"`
}

type Updater struct {
	detector *Detector
	interval time.Duration
	cache    string
	client   *http.Client
	sources  []string
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	last     time.Time
	failed   bool
}

// NewUpdater restores a verified cache when it is newer than the shipped
// reference. Network requests begin only after Start.
func NewUpdater(d *Detector, stateDir string, interval time.Duration) *Updater {
	ctx, cancel := context.WithCancel(context.Background())
	u := &Updater{detector: d, interval: interval, ctx: ctx, cancel: cancel}
	if interval <= 0 {
		return u
	}
	u.cache = filepath.Join(stateDir, "reference-cache.json")
	u.sources = publishedSources
	u.client = &http.Client{
		Timeout: 25 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host {
				return errors.New("reference redirect outside its HTTPS origin")
			}
			return nil
		},
	}
	if ref, err := restoreReference(ctx, u.cache); err == nil && ref.builtAt.After(d.active.Load().builtAt) {
		d.active.Store(ref)
	}
	return u
}

func (u *Updater) Start() {
	if u.interval > 0 {
		u.wg.Go(u.run)
	}
}

func (u *Updater) Close() {
	u.cancel()
	u.wg.Wait()
}

func (u *Updater) Info() ReferenceInfo {
	u.mu.Lock()
	defer u.mu.Unlock()
	ref := u.detector.active.Load()
	return ReferenceInfo{
		BuiltAt: ref.builtAt, Source: ref.source, Updating: u.interval > 0,
		LastCheck: u.last, Failed: u.failed,
	}
}

func (u *Updater) run() {
	for u.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(u.ctx, 2*time.Minute)
		err := u.refresh(ctx)
		cancel()
		wait := u.interval
		if err != nil {
			wait = min(wait, time.Hour)
		}
		timer := time.NewTimer(wait)
		select {
		case <-u.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (u *Updater) refresh(ctx context.Context) (err error) {
	defer func() {
		u.mu.Lock()
		u.last, u.failed = time.Now().UTC(), err != nil
		u.mu.Unlock()
	}()
	current := u.detector.active.Load()
	for _, source := range u.sources {
		next, data, err := u.download(ctx, source, current.builtAt)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if next == nil {
			return nil
		}
		if err := saveReference(u.cache, data); err != nil {
			return fmt.Errorf("save reference: %w", err)
		}
		u.detector.active.Store(next)
		return nil
	}
	return errors.New("all reference sources unavailable or incompatible")
}
