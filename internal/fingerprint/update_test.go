package fingerprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sh4peshifting/cpa-model-fingerprint-guard/internal/guard"
	"github.com/klauspost/compress/zstd"
)

const samplePart = detectorName + ".0123456789abcdef.0.zst"

func TestRemoteBundleRejectsInvalidManifest(t *testing.T) {
	const manifest = `{"schema":"lmfpd-data-v1","detector_schema":"shared-detector-v2","built_at":"2026-11-24T00:00:00Z",
	"files":{"shared_detector.bin":{"sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","parts":["` + samplePart + `"],"bytes":10}}}`
	if _, err := parseBundle([]byte(manifest)); err != nil {
		t.Fatal(err)
	}
	for _, replace := range [][2]string{
		{samplePart, "../secret"}, {samplePart, detectorName + ".0123456789abcdef.1.zst"},
		{"shared-detector-v2", "shared-detector-v3"}, {"10}}", "999999999}}"}, {"T00:00:00Z", ""},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "bad"},
	} {
		bad := strings.Replace(manifest, replace[0], replace[1], 1)
		if _, err := parseBundle([]byte(bad)); err == nil {
			t.Errorf("accepted invalid bundle substitution %q", replace)
		}
	}
}

func TestReferenceRefreshAndOfflineCache(t *testing.T) {
	dir := os.Getenv("MFG_TEST_REFERENCE")
	if dir == "" {
		t.Skip("set MFG_TEST_REFERENCE to the pinned lm-detector data directory")
	}
	d, err := Open(t.Context(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	embedded := d.active.Load().builtAt
	newer := embedded.AddDate(0, 0, 1)
	manifest, compressed := referenceFixture(t, dir, newer, false)
	var chunkCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
			t.Errorf("unexpected reference request %s", r.URL.Path)
		}
		switch r.URL.Path {
		case "/bundle.json":
			_, _ = w.Write(manifest)
		case "/chunks/" + samplePart:
			chunkCount++
			_, _ = w.Write(compressed[:min(len(compressed), maxChunkBytes)])
		case "/chunks/" + detectorName + ".0123456789abcdef.1.zst":
			chunkCount++
			_, _ = w.Write(compressed[maxChunkBytes:])
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	state := t.TempDir()
	u := NewUpdater(d, state, 24*time.Hour)
	t.Cleanup(u.Close)
	u.client, u.sources = server.Client(), []string{server.URL + "/"}
	if err := u.refresh(t.Context()); err != nil || !u.Info().BuiltAt.Equal(newer) || u.Info().Source != "published" {
		t.Fatalf("refresh = %+v, %v", u.Info(), err)
	}
	if updated := d.Check(t.Context(), guard.Probe{Expected: "unsupported-fixture"}); updated.ReferenceBuild != newer.Format(time.RFC3339Nano) {
		t.Fatalf("round reference = %+v", updated)
	}
	initialDownloads := chunkCount
	if err := u.refresh(t.Context()); err != nil || initialDownloads == 0 || chunkCount != initialDownloads {
		t.Fatalf("unchanged version downloaded again, chunks = %d, err = %v", chunkCount, err)
	}

	manifest, compressed = referenceFixture(t, dir, newer.AddDate(0, 0, 1), true)
	if err := u.refresh(t.Context()); err == nil || !u.Info().Failed || !u.Info().BuiltAt.Equal(newer) {
		t.Fatalf("checksum failure displaced active reference: %+v, %v", u.Info(), err)
	}
	manifest, compressed = referenceFixture(t, dir, embedded, false)
	if err := u.refresh(t.Context()); err == nil || !u.Info().BuiltAt.Equal(newer) {
		t.Fatalf("older source displaced active reference: %+v, %v", u.Info(), err)
	}

	restarted, err := Open(t.Context(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	u2 := NewUpdater(restarted, state, 24*time.Hour)
	defer u2.Close()
	if info := u2.Info(); info.Source != "cache" || !info.BuiltAt.Equal(newer) || !slices.Equal(d.Models(), restarted.Models()) {
		t.Fatalf("restart did not recover validated cache: %+v", info)
	}
}

func TestReferenceWorkerCancelsOnClose(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	d := &Detector{}
	d.active.Store(&reference{builtAt: time.Now()})
	u := NewUpdater(d, t.TempDir(), time.Hour)
	defer u.cancel()
	u.client, u.sources = server.Client(), []string{server.URL + "/"}
	u.Start()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("reference worker did not start")
	}
	done := make(chan struct{})
	go func() { u.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reference worker did not cancel")
	}
}

func referenceFixture(t *testing.T, dir string, date time.Time, corruptHash bool) ([]byte, []byte) {
	t.Helper()
	var metadata struct {
		BuiltAt string `json:"built_at"`
		Models  []struct {
			ID         string  `json:"id"`
			Display    string  `json:"display_name"`
			Family     string  `json:"family"`
			FamilyName string  `json:"family_name"`
			Count      float64 `json:"response_count"`
		} `json:"models"`
	}
	bank, err := os.ReadFile(filepath.Join(dir, "unified_bank.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bank, &metadata); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(filepath.Join(dir, detectorName))
	if err != nil {
		t.Fatal(err)
	}
	newDate := date.Format("2006-01-02") + metadata.BuiltAt[10:]
	binary = bytes.ReplaceAll(binary, []byte(metadata.BuiltAt), []byte(newDate))
	sum := sha256.Sum256(binary)
	if corruptHash {
		sum[0] ^= 1
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	compressed := encoder.EncodeAll(binary, nil)
	// The test fixture uses the same chunk naming and metadata as the public bundle.
	var parts []string
	for offset := 0; offset < len(compressed); offset += maxChunkBytes {
		parts = append(parts, fmt.Sprintf("%s.0123456789abcdef.%d.zst", detectorName, len(parts)))
	}
	manifest, err := json.Marshal(map[string]any{
		"schema": "lmfpd-data-v1", "detector_schema": "shared-detector-v2", "built_at": newDate, "models": metadata.Models,
		"files": map[string]any{detectorName: map[string]any{"sha256": fmt.Sprintf("%x", sum), "parts": parts, "bytes": len(compressed)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manifest, compressed
}
