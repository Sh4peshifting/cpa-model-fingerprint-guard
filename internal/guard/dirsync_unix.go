//go:build unix

package guard

import "os"

func syncDirectory(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}
