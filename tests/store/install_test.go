package store

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginstore"
)

type releaseHTTP map[string][]byte

func (h releaseHTTP) Do(r *http.Request) (*http.Response, error) {
	body, ok := h[r.URL.String()]
	if !ok {
		return nil, fmt.Errorf("unexpected package download %s", r.URL)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
		Request:    r,
	}, nil
}

func TestStoreInstallsReleaseZIPs(t *testing.T) {
	dir := os.Getenv("MFG_RELEASE_DIR")
	if dir == "" {
		t.Skip("set MFG_RELEASE_DIR to verified release ZIPs and checksums.txt")
	}
	version := os.Getenv("MFG_RELEASE_VERSION")
	const id = "model-fingerprint-guard"
	const download = "https://downloads.example/"
	checksums, err := os.ReadFile(filepath.Join(dir, "checksums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := os.ReadFile("../../docs/plugin-store-entry.json")
	if err != nil {
		t.Fatal(err)
	}
	var plugin pluginstore.Plugin
	if err := json.Unmarshal(entry, &plugin); err != nil {
		t.Fatal(err)
	}
	if err := pluginstore.ValidatePlugin(plugin); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.zip"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no release ZIPs in %s: %v", dir, err)
	}
	for _, file := range files {
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			target, ok := strings.CutPrefix(name, id+"_"+version+"_")
			goos, goarch, split := strings.Cut(strings.TrimSuffix(target, ".zip"), "_")
			if !ok || !split {
				t.Fatal("invalid release filename")
			}
			archive, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			release := pluginstore.Release{
				TagName: "v" + version,
				Assets: []pluginstore.ReleaseAsset{
					{Name: name, BrowserDownloadURL: download + name},
					{Name: "checksums.txt", BrowserDownloadURL: download + "checksums.txt"},
				},
			}
			response, err := json.Marshal(release)
			if err != nil {
				t.Fatal(err)
			}
			client := pluginstore.NewClient(releaseHTTP{
				"https://api.github.com/repos/bul1horn/cpa-model-fingerprint-guard/releases/latest": response,
				download + name:            archive,
				download + "checksums.txt": checksums,
			}, "")
			result, err := client.Install(t.Context(), plugin, pluginstore.InstallOptions{
				PluginsDir: t.TempDir(), GOOS: goos, GOARCH: goarch,
			})
			if err != nil || result.Version != version {
				t.Fatalf("install result = %+v, err = %v", result, err)
			}
			reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
			if err != nil {
				t.Fatal(err)
			}
			library := id + filepath.Ext(result.Path)
			want, err := reader.Open(library)
			if err != nil {
				t.Fatal(err)
			}
			defer want.Close()
			original, readErr := io.ReadAll(want)
			installed, installErr := os.ReadFile(result.Path)
			if readErr != nil || installErr != nil || len(installed) == 0 || !bytes.Equal(original, installed) {
				t.Fatalf("installed library differs: %v %v", readErr, installErr)
			}
		})
	}
}
