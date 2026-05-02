package manager

import (
	"context"
	"fmt"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/audit"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/config"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/gmail"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/policy"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/request"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/state"
)

// Manager coordinates policy, state, audit, and optional Gmail reconciliation.
type Manager struct {
	cfg   config.Config
	store *state.Store
}

// New opens manager state.
func New(cfg config.Config) (*Manager, error) {
	store, err := state.Open(cfg.StatePath)
	if err != nil {
		return nil, err
	}
	return &Manager{cfg: cfg, store: store}, nil
}

// Close closes manager state.
func (m *Manager) Close() error {
	if m == nil || m.store == nil {
		return nil
	}
	return m.store.Close()
}

// Store returns the underlying trusted state store for read-only callers.
func (m *Manager) Store() *state.Store {
	return m.store
}

// Submit stores a strict untrusted request.
func (m *Manager) Submit(ctx context.Context, req request.VisibilityRequest) (state.RequestRecord, error) {
	eval := policy.Evaluate(m.cfg, req)
	record, err := m.store.Submit(ctx, eval)
	if err != nil {
		return state.RequestRecord{}, err
	}
	_ = audit.Logger{Path: m.cfg.AuditLogPath}.Append(audit.Record{
		Event:       "request_submitted",
		RequestID:   record.RequestID,
		RequestHash: record.RequestHash,
		Actor:       record.RequestedBy,
		Status:      record.Status,
		Details: map[string]any{
			"policy_verdict":    record.PolicyVerdict,
			"approval_required": record.ApprovalRequired,
			"email":             record.Email,
			"labels":            record.ClassificationLabels,
			"reasons":           record.PolicyReasons,
		},
	})
	return record, nil
}

// Approve applies a pending request to canonical grants and reconciles Gmail when configured.
func (m *Manager) Approve(ctx context.Context, requestID, actor string) (state.RequestRecord, state.GrantRecord, *gmail.ReconcileResult, error) {
	req, grant, err := m.store.Approve(ctx, requestID, actor, m.cfg.VisibilityLabel)
	if err != nil {
		return state.RequestRecord{}, state.GrantRecord{}, nil, err
	}

	var reconcileResult *gmail.ReconcileResult
	if m.cfg.GmailConfigured() {
		client, err := gmail.New(ctx, m.cfg)
		if err != nil {
			return req, grant, nil, fmt.Errorf("approve stored canonical grant, but open Gmail failed: %w", err)
		}
		result, err := client.ReconcileGrant(ctx, grant, gmail.ReconcileOptions{Apply: true})
		reconcileResult = &result
		if result.GmailFilterID != "" {
			_ = m.store.SetGrantFilterID(ctx, grant.Email, result.GmailFilterID)
		}
		if err != nil {
			return req, grant, reconcileResult, fmt.Errorf("approve stored canonical grant, but Gmail reconciliation failed: %w", err)
		}
	}

	details := map[string]any{
		"email":             grant.Email,
		"visibility_label":  grant.VisibilityLabel,
		"classification":    grant.ClassificationLabels,
		"canonical_applied": true,
	}
	if reconcileResult != nil {
		details["gmail_reconcile"] = reconcileResult
	}
	_ = audit.Logger{Path: m.cfg.AuditLogPath}.Append(audit.Record{
		Event:       "request_approved_applied",
		RequestID:   req.RequestID,
		RequestHash: req.RequestHash,
		Actor:       actor,
		Status:      req.Status,
		Details:     details,
	})
	return req, grant, reconcileResult, nil
}

// Deny marks a pending request denied.
func (m *Manager) Deny(ctx context.Context, requestID, actor, reason string) (state.RequestRecord, error) {
	req, err := m.store.Deny(ctx, requestID, actor, reason)
	if err != nil {
		return state.RequestRecord{}, err
	}
	_ = audit.Logger{Path: m.cfg.AuditLogPath}.Append(audit.Record{
		Event:       "request_denied",
		RequestID:   req.RequestID,
		RequestHash: req.RequestHash,
		Actor:       actor,
		Status:      req.Status,
		Details: map[string]any{
			"reason": reason,
			"email":  req.Email,
		},
	})
	return req, nil
}

// ReconcileAll reconciles active grants with Gmail filters.
func (m *Manager) ReconcileAll(ctx context.Context, apply bool) ([]gmail.ReconcileResult, error) {
	if err := m.cfg.ValidateGmail(); err != nil {
		return nil, err
	}
	client, err := gmail.New(ctx, m.cfg)
	if err != nil {
		return nil, err
	}
	grants, err := m.store.ListGrants(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]gmail.ReconcileResult, 0, len(grants))
	for _, grant := range grants {
		result, err := client.ReconcileGrant(ctx, grant, gmail.ReconcileOptions{Apply: apply})
		results = append(results, result)
		if apply && result.GmailFilterID != "" && (result.Status == "created" || result.Status == "bind_existing") {
			_ = m.store.SetGrantFilterID(ctx, grant.Email, result.GmailFilterID)
		}
		if err != nil {
			return results, err
		}
	}
	_ = audit.Logger{Path: m.cfg.AuditLogPath}.Append(audit.Record{
		Event:  "gmail_reconcile",
		Actor:  "local",
		Status: "completed",
		Details: map[string]any{
			"apply":   apply,
			"results": results,
		},
	})
	return results, nil
}
