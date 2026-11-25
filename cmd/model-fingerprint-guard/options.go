package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Sh4peshifting/cpa-model-fingerprint-guard/internal/guard"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"go.yaml.in/yaml/v3"
)

const (
	defaultReferenceInterval     = 24 * time.Hour
	defaultReferenceIntervalText = "24h"
)

type pluginOptions struct {
	Enabled             bool          `yaml:"enabled"`
	Priority            int           `yaml:"priority"`
	Store               yaml.Node     `yaml:"store"`
	StateDir            string        `yaml:"state-dir"`
	ReferenceAutoUpdate configToggle  `yaml:"reference-auto-update"`
	ReferenceInterval   time.Duration `yaml:"reference-refresh-interval"`
	ReferenceDir        string        `yaml:"reference-dir"`
	Native              bool          `yaml:"native-diagnostics"`
	Settings            guard.Config  `yaml:"settings"`
}

// The panel's enum control can distinguish an unset value from explicit false.
// Keep accepting the original YAML boolean as well as the panel's string patch.
type configToggle bool

func (b *configToggle) UnmarshalYAML(n *yaml.Node) error {
	switch n.Value {
	case "true":
		*b = true
	case "false":
		*b = false
	default:
		var value bool
		if err := n.Decode(&value); err != nil {
			return err
		}
		*b = configToggle(value)
	}
	return nil
}

func decodePluginOptions(data []byte) (pluginOptions, error) {
	o := pluginOptions{
		StateDir: ".model-fingerprint-guard", Settings: guard.DefaultConfig(),
		ReferenceAutoUpdate: true, ReferenceInterval: defaultReferenceInterval,
	}
	if len(data) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&o); err != nil {
			return o, fmt.Errorf("invalid plugin configuration: %w", err)
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return o, errors.New("only one YAML document is allowed")
		}
	}
	if dir := os.Getenv("MODEL_FINGERPRINT_GUARD_STATE_DIR"); dir != "" {
		o.StateDir = dir
	}
	if o.StateDir == "" {
		return o, errors.New("state-dir must be a local directory")
	}
	if o.ReferenceInterval < time.Minute || o.ReferenceInterval > 30*24*time.Hour {
		return o, errors.New("reference-refresh-interval must be between 1m and 720h")
	}
	return o, o.Settings.Validate()
}

func (o pluginOptions) updateInterval() time.Duration {
	if !o.ReferenceAutoUpdate || o.ReferenceDir != "" {
		return 0
	}
	return o.ReferenceInterval
}

func configFields() []pluginapi.ConfigField {
	return []pluginapi.ConfigField{
		{Name: "native-diagnostics", Type: pluginapi.ConfigFieldTypeBoolean, Default: false,
			Description: "开启经过验证的原生 OAuth 诊断，默认关闭，保存后生效。"},
		{Name: "reference-auto-update", Type: pluginapi.ConfigFieldTypeEnum, Default: "true", EnumValues: []string{"true", "false"},
			Description: "true 启用，false 暂停。留空时默认启用，指定 reference-dir 时使用本地库。"},
		{Name: "reference-refresh-interval", Type: pluginapi.ConfigFieldTypeString, Default: defaultReferenceIntervalText,
			Description: "更新间隔默认 24h，可填写 1m 到 720h 的时长，例如 30m 或 12h。"},
	}
}

func (p *runtime) applyOptions(o pluginOptions, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// The host has already saved the document. Keep serving the last applied
	// configuration if the proposed settings cannot be used in this process.
	p.configRejected = err != nil || p.options.StateDir != o.StateDir || p.options.ReferenceDir != o.ReferenceDir
	if p.configRejected {
		return
	}
	if p.options.Native != o.Native {
		p.host.SetNativeDiagnostics(o.Native)
		p.Guard.RefreshInventory()
	}
	p.references.SetInterval(o.updateInterval())
	p.options = o
}
