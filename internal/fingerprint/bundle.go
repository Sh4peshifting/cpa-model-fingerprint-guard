package fingerprint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	detectorName   = "shared_detector.bin"
	maxBundleBytes = 512 << 10
	maxChunkBytes  = 4 << 20
	maxParts       = 16
	maxDataBytes   = 64 << 20
	maxCacheBytes  = 90 << 20
)

var partName = regexp.MustCompile(`^shared_detector\.bin\.[a-f0-9]{16}\.[0-9]+\.zst$`)

type bundle struct {
	Schema         string    `json:"schema"`
	DetectorSchema string    `json:"detector_schema"`
	BuiltAt        time.Time `json:"built_at"`
	Files          map[string]struct {
		SHA256 string   `json:"sha256"`
		Parts  []string `json:"parts"`
		Bytes  int      `json:"bytes"`
	} `json:"files"`
}

type cachedReference struct {
	Manifest json.RawMessage `json:"manifest"`
	Detector []byte          `json:"detector"`
}

func parseBundle(body []byte) (bundle, error) {
	var b bundle
	if len(body) > maxBundleBytes || json.Unmarshal(body, &b) != nil ||
		b.Schema != "lmfpd-data-v1" || b.DetectorSchema != "shared-detector-v2" || b.BuiltAt.IsZero() {
		return b, errors.New("unsupported reference bundle")
	}
	file := b.Files[detectorName]
	hash, err := hex.DecodeString(file.SHA256)
	if err != nil || len(hash) != sha256.Size || len(file.Parts) == 0 || len(file.Parts) > maxParts ||
		file.Bytes <= 0 || file.Bytes > maxChunkBytes*len(file.Parts) {
		return b, errors.New("invalid detector description")
	}
	base, _ := strings.CutSuffix(file.Parts[0], ".0.zst")
	for i, part := range file.Parts {
		suffix := "." + strconv.Itoa(i) + ".zst"
		if !partName.MatchString(part) || part != base+suffix {
			return b, errors.New("invalid detector chunk names")
		}
	}
	return b, nil
}

func (u *Updater) download(ctx context.Context, source string, current time.Time) (*reference, cachedReference, error) {
	var data cachedReference
	manifest, err := u.get(ctx, source+"bundle.json", maxBundleBytes)
	if err != nil {
		return nil, data, err
	}
	b, err := parseBundle(manifest)
	if err != nil {
		return nil, data, err
	}
	if b.BuiltAt.Before(current) {
		return nil, data, errors.New("reference source older than active build")
	}
	if b.BuiltAt.Equal(current) {
		return nil, data, nil
	}
	file := b.Files[detectorName]
	var chunks bytes.Buffer
	for _, part := range file.Parts {
		chunk, err := u.get(ctx, source+"chunks/"+part, min(maxChunkBytes, file.Bytes-chunks.Len()))
		if err != nil {
			return nil, data, err
		}
		chunks.Write(chunk)
	}
	if chunks.Len() != file.Bytes {
		return nil, data, errors.New("incomplete compressed detector")
	}
	decoder, err := zstd.NewReader(&chunks, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxDataBytes))
	if err != nil {
		return nil, data, err
	}
	defer decoder.Close()
	binary, err := readBounded(decoder, maxDataBytes)
	if err != nil {
		return nil, data, err
	}
	data = cachedReference{Manifest: manifest, Detector: binary}
	ref, err := data.load(ctx, b, "published")
	return ref, data, err
}

func (u *Updater) get(ctx context.Context, url string, limit int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > int64(limit) {
		return nil, fmt.Errorf("reference download returned HTTP %d or exceeded its limit", response.StatusCode)
	}
	return readBounded(response.Body, limit)
}

func readBounded(reader io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("reference exceeds its size limit")
	}
	return data, nil
}

func (data cachedReference) load(ctx context.Context, b bundle, source string) (ref *reference, err error) {
	// A corrupt upstream detector must not terminate the host even if decoding
	// panics inside the SDK rather than returning an error.
	defer func() {
		if recover() != nil {
			ref, err = nil, errors.New("invalid reference detector")
		}
	}()
	expected, _ := hex.DecodeString(b.Files[detectorName].SHA256)
	hash := sha256.Sum256(data.Detector)
	if len(data.Detector) > maxDataBytes || !bytes.Equal(hash[:], expected) {
		return nil, errors.New("reference checksum mismatch")
	}
	dir, err := os.MkdirTemp("", "mfg-reference-update-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	// The public bundle carries exactly the bank metadata required by lmfpd.
	if err := os.WriteFile(filepath.Join(dir, "unified_bank.json"), data.Manifest, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, detectorName), data.Detector, 0600); err != nil {
		return nil, err
	}
	return loadReference(ctx, dir, source)
}

func restoreReference(ctx context.Context, path string) (*reference, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := readBounded(f, maxCacheBytes)
	if err != nil {
		return nil, err
	}
	var data cachedReference
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	b, err := parseBundle(data.Manifest)
	if err != nil {
		return nil, err
	}
	return data.load(ctx, b, "cache")
}

func saveReference(path string, data cachedReference) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".reference-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	writeErr := json.NewEncoder(f).Encode(data)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
