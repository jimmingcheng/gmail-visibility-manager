package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	DefaultVisibilityLabel = "Donna"
)

// Config is trusted-side configuration. Donna must not be able to edit it.
type Config struct {
	StatePath                     string   `json:"state_path"`
	AuditLogPath                  string   `json:"audit_log_path"`
	VisibilityLabel               string   `json:"visibility_label"`
	AllowedClassificationLabels   []string `json:"allowed_classification_labels"`
	SensitiveClassificationLabels []string `json:"sensitive_classification_labels,omitempty"`
}

// Default returns a local development config.
func Default() Config {
	stateDir := defaultStateDir()
	return Config{
		StatePath:       filepath.Join(stateDir, "state.db"),
		AuditLogPath:    filepath.Join(stateDir, "audit.jsonl"),
		VisibilityLabel: DefaultVisibilityLabel,
	}
}

// Load reads a config JSON file. If path is empty, the local default is used.
func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		cfg := Default()
		return cfg, cfg.Validate()
	}
	data, err := os.ReadFile(expandPath(path))
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// WriteSample writes a starter config file without overwriting an existing file.
func WriteSample(path string) error {
	path = expandPath(path)
	cfg := Default()
	cfg.AllowedClassificationLabels = []string{
		"Kids/Activities",
		"Kids/School",
		"House/Renovation",
		"Receipts",
		"Travel",
	}
	cfg.SensitiveClassificationLabels = []string{}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create config: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func (c *Config) applyDefaults() {
	defaults := Default()
	if strings.TrimSpace(c.StatePath) == "" {
		c.StatePath = defaults.StatePath
	}
	if strings.TrimSpace(c.AuditLogPath) == "" {
		c.AuditLogPath = defaults.AuditLogPath
	}
	if strings.TrimSpace(c.VisibilityLabel) == "" {
		c.VisibilityLabel = DefaultVisibilityLabel
	}
	c.StatePath = expandPath(c.StatePath)
	c.AuditLogPath = expandPath(c.AuditLogPath)
	c.AllowedClassificationLabels = normalizeLabelList(c.AllowedClassificationLabels)
	c.SensitiveClassificationLabels = normalizeLabelList(c.SensitiveClassificationLabels)
}

// Validate checks trusted config invariants.
func (c Config) Validate() error {
	if strings.TrimSpace(c.StatePath) == "" {
		return fmt.Errorf("config: state_path is required")
	}
	if filepath.Clean(c.StatePath) == "." {
		return fmt.Errorf("config: state_path must not resolve to current directory")
	}
	if strings.TrimSpace(c.AuditLogPath) == "" {
		return fmt.Errorf("config: audit_log_path is required")
	}
	if filepath.Clean(c.AuditLogPath) == "." {
		return fmt.Errorf("config: audit_log_path must not resolve to current directory")
	}
	if strings.TrimSpace(c.VisibilityLabel) == "" {
		return fmt.Errorf("config: visibility_label is required")
	}
	if strings.ContainsAny(c.VisibilityLabel, "\x00\r\n") {
		return fmt.Errorf("config: visibility_label contains invalid control character")
	}
	allowed := c.AllowedLabelSet()
	if _, ok := allowed[NormalizeLabel(c.VisibilityLabel)]; ok {
		return fmt.Errorf("config: visibility_label must not also be an allowed classification label")
	}
	for _, label := range c.SensitiveClassificationLabels {
		if _, ok := allowed[NormalizeLabel(label)]; !ok {
			return fmt.Errorf("config: sensitive label %q must also be allowed", label)
		}
	}
	return nil
}

// AllowedLabelSet returns allowed classification labels keyed case-insensitively.
func (c Config) AllowedLabelSet() map[string]string {
	result := make(map[string]string, len(c.AllowedClassificationLabels))
	for _, label := range c.AllowedClassificationLabels {
		result[NormalizeLabel(label)] = strings.TrimSpace(label)
	}
	return result
}

// SensitiveLabelSet returns sensitive labels keyed case-insensitively.
func (c Config) SensitiveLabelSet() map[string]string {
	result := make(map[string]string, len(c.SensitiveClassificationLabels))
	for _, label := range c.SensitiveClassificationLabels {
		result[NormalizeLabel(label)] = strings.TrimSpace(label)
	}
	return result
}

// NormalizeLabel normalizes labels for case-insensitive policy comparison.
func NormalizeLabel(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeLabelList(labels []string) []string {
	seen := map[string]string{}
	for _, label := range labels {
		trimmed := strings.TrimSpace(label)
		if trimmed == "" {
			continue
		}
		seen[NormalizeLabel(trimmed)] = trimmed
	}
	result := make([]string, 0, len(seen))
	for _, label := range seen {
		result = append(result, label)
	}
	sort.Slice(result, func(i, j int) bool {
		return NormalizeLabel(result[i]) < NormalizeLabel(result[j])
	})
	return result
}

func defaultStateDir() string {
	if value := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); value != "" {
		return filepath.Join(expandPath(value), "gmail-visibility-manager")
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(".", ".gmail-visibility-manager")
	}
	return filepath.Join(home, ".local", "state", "gmail-visibility-manager")
}

func expandPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		if path == "~" {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}
