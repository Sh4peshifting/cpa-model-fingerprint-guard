//go:build reference_embedded

package fingerprint

import (
	"compress/gzip"
	"embed"
	"errors"
	"io"
	"os"
	"path/filepath"
)

//go:embed reference/*.gz
var references embed.FS

func embeddedReference() (string, func(), error) {
	dir, err := os.MkdirTemp("", "model-fingerprint-reference-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	for _, name := range []string{"unified_bank.json", "shared_detector.bin"} {
		if err := extractReference(dir, name); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	return dir, cleanup, nil
}

func extractReference(dir, name string) error {
	input, err := references.Open("reference/" + name + ".gz")
	if err != nil {
		return err
	}
	defer input.Close()
	gz, err := gzip.NewReader(input)
	if err != nil {
		return err
	}
	defer gz.Close()
	out, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, gz)
	return errors.Join(copyErr, out.Close())
}
