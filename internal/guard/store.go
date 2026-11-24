package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type state struct {
	Schema   int                   `json:"schema"`
	Revision uint64                `json:"revision"`
	Config   Config                `json:"config"`
	Auths    map[string]*AuthState `json:"auths"`
	History  []Record              `json:"history"`
}

const maxStateBytes = 64 << 20

func loadState(path string, initial Config) (state, error) {
	s := state{Schema: 1, Revision: 1, Config: initial, Auths: make(map[string]*AuthState), History: []Record{}}
	if err := initial.Validate(); err != nil {
		return state{}, err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, saveState(path, s)
	}
	if err != nil {
		return state{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return state{}, err
	}
	if info.Size() > maxStateBytes {
		return state{}, errors.New("守卫状态文件超过大小限制")
	}
	dec := json.NewDecoder(io.LimitReader(file, maxStateBytes))
	// Older state files inherit the new interval without resetting other fields.
	s = state{Config: Config{MismatchRecheckSeconds: initial.MismatchRecheckSeconds}}
	if err := dec.Decode(&s); err != nil {
		return state{}, fmt.Errorf("读取守卫状态: %w", err)
	}
	var extra any
	if s.Schema != 1 || s.Revision == 0 || s.Auths == nil || dec.Decode(&extra) != io.EOF {
		return state{}, errors.New("守卫状态格式无效")
	}
	for id, a := range s.Auths {
		if id == "" || a == nil {
			return state{}, errors.New("守卫认证状态无效")
		}
	}
	return s, s.Config.Validate()
}

func saveState(path string, s state) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(data) >= maxStateBytes {
		return errors.New("守卫状态文件超过大小限制")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".guard-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	syncDirectory(dir)
	return nil
}
