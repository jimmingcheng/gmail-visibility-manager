package request

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion1 = "1.0"

	ActionCreateVisibilityGrant = "create_visibility_grant"
	ActionUpdateGrantLabels     = "update_grant_labels"
)

// VisibilityRequest is the only untrusted request shape accepted in v1.
type VisibilityRequest struct {
	SchemaVersion        string   `json:"schema_version"`
	RequestID            string   `json:"request_id,omitempty"`
	CreatedAt            string   `json:"created_at,omitempty"`
	RequestedBy          string   `json:"requested_by"`
	Action               string   `json:"action"`
	Email                string   `json:"email"`
	ClassificationLabels []string `json:"classification_labels,omitempty"`
	Rationale            string   `json:"rationale,omitempty"`
}

// ParseStrict decodes a request and rejects unknown fields.
func ParseStrict(data []byte) (VisibilityRequest, error) {
	var req VisibilityRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return VisibilityRequest{}, fmt.Errorf("parse request: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return VisibilityRequest{}, fmt.Errorf("parse request: request must contain exactly one JSON object")
	}
	if err := req.ValidateBasic(); err != nil {
		return VisibilityRequest{}, err
	}
	return req.NormalizeBasic()
}

// ValidateBasic enforces syntax that does not depend on trusted policy config.
func (r VisibilityRequest) ValidateBasic() error {
	if strings.TrimSpace(r.SchemaVersion) != SchemaVersion1 {
		return fmt.Errorf("request: schema_version must be %q", SchemaVersion1)
	}
	if strings.TrimSpace(r.RequestID) != "" && len(strings.TrimSpace(r.RequestID)) > 128 {
		return fmt.Errorf("request: request_id is too long")
	}
	if strings.TrimSpace(r.CreatedAt) != "" {
		if _, err := time.Parse(time.RFC3339, strings.TrimSpace(r.CreatedAt)); err != nil {
			return fmt.Errorf("request: created_at must be RFC3339")
		}
	}
	if strings.TrimSpace(r.RequestedBy) == "" {
		return fmt.Errorf("request: requested_by is required")
	}
	switch strings.TrimSpace(r.Action) {
	case ActionCreateVisibilityGrant, ActionUpdateGrantLabels:
	default:
		return fmt.Errorf("request: unsupported action %q", r.Action)
	}
	if _, err := NormalizeEmail(r.Email); err != nil {
		return err
	}
	if _, err := NormalizeLabels(r.ClassificationLabels); err != nil {
		return err
	}
	if strings.ContainsAny(r.Rationale, "\x00") {
		return fmt.Errorf("request: rationale contains invalid control character")
	}
	return nil
}

// NormalizeBasic returns the request with deterministic email and label fields.
func (r VisibilityRequest) NormalizeBasic() (VisibilityRequest, error) {
	email, err := NormalizeEmail(r.Email)
	if err != nil {
		return VisibilityRequest{}, err
	}
	labels, err := NormalizeLabels(r.ClassificationLabels)
	if err != nil {
		return VisibilityRequest{}, err
	}
	r.SchemaVersion = strings.TrimSpace(r.SchemaVersion)
	r.RequestID = strings.TrimSpace(r.RequestID)
	r.CreatedAt = strings.TrimSpace(r.CreatedAt)
	r.RequestedBy = strings.TrimSpace(r.RequestedBy)
	r.Action = strings.TrimSpace(r.Action)
	r.Email = email
	r.ClassificationLabels = labels
	r.Rationale = strings.TrimSpace(r.Rationale)
	return r, nil
}

// NormalizeEmail accepts only one bare mailbox address. Domains, display names,
// comma-separated lists, and Gmail query fragments are not valid v1 grants.
func NormalizeEmail(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("request: email is required")
	}
	if strings.ContainsAny(value, " ,<>") {
		return "", fmt.Errorf("request: email must be one bare email address")
	}
	if strings.Contains(value, "*") {
		return "", fmt.Errorf("request: email must be one individual email address")
	}
	if strings.Count(value, "@") != 1 {
		return "", fmt.Errorf("request: email must be one individual email address")
	}
	addr, err := mail.ParseAddress(value)
	if err != nil {
		return "", fmt.Errorf("request: invalid email address %q", value)
	}
	normalized := strings.ToLower(strings.TrimSpace(addr.Address))
	if normalized == "" || normalized != strings.ToLower(value) {
		return "", fmt.Errorf("request: email must be one bare email address")
	}
	local, domain, ok := strings.Cut(normalized, "@")
	if !ok || local == "" || domain == "" || strings.ContainsAny(domain, " \t\r\n") {
		return "", fmt.Errorf("request: invalid email address %q", value)
	}
	return normalized, nil
}

// NormalizeLabels trims, deduplicates, and sorts requested classification labels.
func NormalizeLabels(labels []string) ([]string, error) {
	seen := map[string]string{}
	for _, label := range labels {
		trimmed := strings.TrimSpace(label)
		if trimmed == "" {
			return nil, fmt.Errorf("request: classification label must not be empty")
		}
		if len(trimmed) > 128 {
			return nil, fmt.Errorf("request: classification label %q is too long", trimmed)
		}
		if strings.ContainsAny(trimmed, "\x00\r\n") {
			return nil, fmt.Errorf("request: classification label %q contains invalid control character", trimmed)
		}
		seen[strings.ToLower(trimmed)] = trimmed
	}
	result := make([]string, 0, len(seen))
	for _, label := range seen {
		result = append(result, label)
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i]) < strings.ToLower(result[j])
	})
	return result, nil
}

// Hash returns a stable hash of the normalized request.
func Hash(req VisibilityRequest) (string, error) {
	normalized, err := req.NormalizeBasic()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
