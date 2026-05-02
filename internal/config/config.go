package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	DefaultVisibilityLabel = "Donna"
	defaultInstance        = "default"
	defaultSocketMode      = "0660"
	defaultAuthBackend     = "system"
	defaultAuthService     = "gmail-visibility-manager"
	defaultDiscordTokenEnv = "GMAIL_VISIBILITY_MANAGER_DISCORD_TOKEN"
	defaultDiscordPrefix   = "!gvm"
)

// Config is trusted-side configuration. Donna must not be able to edit it.
type Config struct {
	Instance                      string          `json:"instance,omitempty"`
	AccountEmail                  string          `json:"account_email,omitempty"`
	ClientUID                     uint32          `json:"client_uid,omitempty"`
	SocketPath                    string          `json:"socket_path,omitempty"`
	SocketMode                    string          `json:"socket_mode,omitempty"`
	StatePath                     string          `json:"state_path"`
	AuditLogPath                  string          `json:"audit_log_path"`
	OAuthClientPath               string          `json:"oauth_client_path,omitempty"`
	AuthStore                     AuthStoreConfig `json:"auth_store,omitempty"`
	VisibilityLabel               string          `json:"visibility_label"`
	AllowedClassificationLabels   []string        `json:"allowed_classification_labels"`
	SensitiveClassificationLabels []string        `json:"sensitive_classification_labels,omitempty"`
	Discord                       DiscordConfig   `json:"discord,omitempty"`
}

// AuthStoreConfig controls where Gmail OAuth refresh tokens are stored.
type AuthStoreConfig struct {
	Backend string `json:"backend,omitempty"`
	Service string `json:"service,omitempty"`
	FileDir string `json:"file_dir,omitempty"`
}

// DiscordConfig controls the optional approval adapter in daemon mode.
type DiscordConfig struct {
	TokenEnv       string   `json:"token_env,omitempty"`
	ChannelID      string   `json:"channel_id,omitempty"`
	AllowedUserIDs []string `json:"allowed_user_ids,omitempty"`
	CommandPrefix  string   `json:"command_prefix,omitempty"`
}

// Default returns a local development config.
func Default() Config {
	stateDir := defaultStateDir()
	return Config{
		Instance:        defaultInstance,
		SocketPath:      filepath.Join(os.TempDir(), "gmail-visibility-manager", "default.sock"),
		SocketMode:      defaultSocketMode,
		StatePath:       filepath.Join(stateDir, "state.db"),
		AuditLogPath:    filepath.Join(stateDir, "audit.jsonl"),
		VisibilityLabel: DefaultVisibilityLabel,
		AuthStore: AuthStoreConfig{
			Backend: defaultAuthBackend,
			Service: defaultAuthService,
		},
		Discord: DiscordConfig{
			TokenEnv:      defaultDiscordTokenEnv,
			CommandPrefix: defaultDiscordPrefix,
		},
	}
}

// Load reads a config JSON file. If path is empty, the local default is used.
func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		cfg := Default()
		return cfg, cfg.Validate()
	}
	data, err := os.ReadFile(ExpandPath(path))
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
	path = ExpandPath(path)
	cfg := Default()
	cfg.SocketPath = "/var/tmp/gmail-visibility-manager/default.sock"
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
	if strings.TrimSpace(c.Instance) == "" {
		c.Instance = defaults.Instance
	}
	if strings.TrimSpace(c.SocketPath) == "" {
		c.SocketPath = defaults.SocketPath
	}
	if strings.TrimSpace(c.SocketMode) == "" {
		c.SocketMode = defaults.SocketMode
	}
	if strings.TrimSpace(c.StatePath) == "" {
		c.StatePath = defaults.StatePath
	}
	if strings.TrimSpace(c.AuditLogPath) == "" {
		c.AuditLogPath = defaults.AuditLogPath
	}
	if strings.TrimSpace(c.VisibilityLabel) == "" {
		c.VisibilityLabel = DefaultVisibilityLabel
	}
	c.SocketPath = ExpandPath(c.SocketPath)
	c.StatePath = ExpandPath(c.StatePath)
	c.AuditLogPath = ExpandPath(c.AuditLogPath)
	c.OAuthClientPath = ExpandPath(c.OAuthClientPath)
	c.AuthStore.applyDefaults(c.StatePath)
	c.Discord.applyDefaults()
	c.AllowedClassificationLabels = normalizeLabelList(c.AllowedClassificationLabels)
	c.SensitiveClassificationLabels = normalizeLabelList(c.SensitiveClassificationLabels)
}

// Validate checks trusted config invariants.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Instance) == "" {
		return fmt.Errorf("config: instance is required")
	}
	if strings.TrimSpace(c.SocketPath) != "" && filepath.Clean(c.SocketPath) == "." {
		return fmt.Errorf("config: socket_path must not resolve to current directory")
	}
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
	if err := c.AuthStore.Validate(); err != nil {
		return err
	}
	if err := c.Discord.Validate(); err != nil {
		return err
	}
	return nil
}

// ValidateDaemon enforces invariants needed before accepting untrusted socket clients.
func (c Config) ValidateDaemon() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.SocketPath) == "" {
		return fmt.Errorf("config: socket_path is required for daemon mode")
	}
	if c.ClientUID == 0 {
		return fmt.Errorf("config: client_uid is required for daemon mode")
	}
	if _, err := c.SocketFileMode(); err != nil {
		return err
	}
	return nil
}

// ValidateGmail enforces invariants needed for Gmail OAuth/API operations.
func (c Config) ValidateGmail() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.AccountEmail) == "" {
		return fmt.Errorf("config: account_email is required for Gmail operations")
	}
	if strings.TrimSpace(c.OAuthClientPath) == "" {
		return fmt.Errorf("config: oauth_client_path is required for Gmail operations")
	}
	if filepath.Clean(c.OAuthClientPath) == "." {
		return fmt.Errorf("config: oauth_client_path must not resolve to current directory")
	}
	return nil
}

// GmailConfigured reports whether OAuth settings are present.
func (c Config) GmailConfigured() bool {
	return strings.TrimSpace(c.AccountEmail) != "" && strings.TrimSpace(c.OAuthClientPath) != ""
}

// SocketFileMode parses SocketMode as an octal filesystem mode.
func (c Config) SocketFileMode() (os.FileMode, error) {
	value := strings.TrimSpace(c.SocketMode)
	if value == "" {
		value = defaultSocketMode
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("config: invalid socket_mode %q", c.SocketMode)
	}
	return os.FileMode(parsed), nil
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

func (c *AuthStoreConfig) applyDefaults(statePath string) {
	if strings.TrimSpace(c.Backend) == "" {
		c.Backend = defaultAuthBackend
	}
	if strings.TrimSpace(c.Service) == "" {
		c.Service = defaultAuthService
	}
	if strings.EqualFold(strings.TrimSpace(c.Backend), "file") {
		c.FileDir = ExpandPath(c.FileDir)
		if strings.TrimSpace(c.FileDir) == "" && strings.TrimSpace(statePath) != "" {
			c.FileDir = filepath.Join(filepath.Dir(statePath), "keyring")
		}
	}
}

// Validate checks token store config.
func (c AuthStoreConfig) Validate() error {
	switch strings.ToLower(strings.TrimSpace(c.Backend)) {
	case "", "system":
		return nil
	case "file":
		if strings.TrimSpace(c.FileDir) == "" {
			return fmt.Errorf("config: auth_store.file_dir is required when backend=file")
		}
		if filepath.Clean(c.FileDir) == "." {
			return fmt.Errorf("config: auth_store.file_dir must not resolve to current directory")
		}
		return nil
	default:
		return fmt.Errorf("config: unsupported auth_store.backend %q", c.Backend)
	}
}

func (c *DiscordConfig) applyDefaults() {
	if strings.TrimSpace(c.TokenEnv) == "" {
		c.TokenEnv = defaultDiscordTokenEnv
	}
	if strings.TrimSpace(c.CommandPrefix) == "" {
		c.CommandPrefix = defaultDiscordPrefix
	}
	for i := range c.AllowedUserIDs {
		c.AllowedUserIDs[i] = strings.TrimSpace(c.AllowedUserIDs[i])
	}
}

// Validate checks optional Discord approval config.
func (c DiscordConfig) Validate() error {
	allowedCount := 0
	for _, id := range c.AllowedUserIDs {
		if strings.TrimSpace(id) != "" {
			allowedCount++
		}
	}
	if strings.TrimSpace(c.ChannelID) == "" && allowedCount == 0 {
		return nil
	}
	if allowedCount == 0 {
		return fmt.Errorf("config: discord.allowed_user_ids is required when Discord approval is configured")
	}
	return nil
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
		return filepath.Join(ExpandPath(value), "gmail-visibility-manager")
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(".", ".gmail-visibility-manager")
	}
	return filepath.Join(home, ".local", "state", "gmail-visibility-manager")
}

// ExpandPath expands "~" prefixes for config-owned paths.
func ExpandPath(path string) string {
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
