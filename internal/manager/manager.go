package manager

import (
	"context"
	"fmt"
	"strings"

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

// Approve records approval, then marks the request applied only after enforcement succeeds.
func (m *Manager) Approve(ctx context.Context, requestID, actor string) (state.RequestRecord, state.GrantRecord, *gmail.ReconcileResult, error) {
	req, grant, err := m.store.Approve(ctx, requestID, actor, m.cfg.VisibilityLabel)
	if err != nil {
		return state.RequestRecord{}, state.GrantRecord{}, nil, err
	}

	var reconcileResult *gmail.ReconcileResult
	if m.cfg.GmailConfigured() {
		client, err := gmail.New(ctx, m.cfg)
		if err != nil {
			m.auditApprovalFailure(req, grant, nil, actor, err)
			return req, grant, nil, fmt.Errorf("approval recorded, but open Gmail failed: %w", err)
		}
		grants, err := m.store.ListGrants(ctx)
		if err != nil {
			m.auditApprovalFailure(req, grant, nil, actor, err)
			return req, grant, nil, fmt.Errorf("approval recorded, but loading grants for Gmail reconciliation failed: %w", err)
		}
		results, err := client.ReconcileGrants(ctx, grants, gmail.ReconcileOptions{
			Apply:                    true,
			BackfillHistorical:       true,
			BackfillHistoricalEmails: map[string]bool{grant.Email: true},
		})
		if found := findReconcileResult(results, grant.Email); found != nil {
			reconcileResult = found
		}
		if updateErr := m.recordGrantFilterIDs(ctx, results); updateErr != nil {
			m.auditApprovalFailure(req, grant, reconcileResult, actor, updateErr)
			return req, grant, reconcileResult, fmt.Errorf("approval reconciled Gmail, but recording Gmail filter IDs failed: %w", updateErr)
		}
		if reconcileResult != nil && reconcileResult.GmailFilterID != "" {
			grant.GmailFilterID = reconcileResult.GmailFilterID
		}
		if err != nil {
			m.auditApprovalFailure(req, grant, reconcileResult, actor, err)
			return req, grant, reconcileResult, fmt.Errorf("approval recorded, but Gmail reconciliation failed: %w", err)
		}
		if reconcileResult == nil {
			err := fmt.Errorf("approval recorded, but Gmail reconciliation returned no result for %s", grant.Email)
			m.auditApprovalFailure(req, grant, nil, actor, err)
			return req, grant, nil, err
		}
	}
	appliedReq, err := m.store.MarkRequestApplied(ctx, req.RequestID)
	if err != nil {
		m.auditApprovalFailure(req, grant, reconcileResult, actor, err)
		return req, grant, reconcileResult, fmt.Errorf("approval enforcement succeeded, but marking request applied failed: %w", err)
	}
	req = appliedReq

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

func (m *Manager) recordGrantFilterIDs(ctx context.Context, results []gmail.ReconcileResult) error {
	for _, result := range results {
		if strings.TrimSpace(result.GmailFilterID) == "" || !result.Changed {
			continue
		}
		if err := m.store.SetGrantFilterID(ctx, result.Email, result.GmailFilterID); err != nil {
			return err
		}
	}
	return nil
}

func findReconcileResult(results []gmail.ReconcileResult, email string) *gmail.ReconcileResult {
	normalized, err := request.NormalizeEmail(email)
	if err != nil {
		return nil
	}
	for i := range results {
		resultEmail, err := request.NormalizeEmail(results[i].Email)
		if err == nil && resultEmail == normalized {
			return &results[i]
		}
	}
	return nil
}

func successfulReconcileStatus(status string) bool {
	switch status {
	case "ok", "created", "bind_existing":
		return true
	default:
		return false
	}
}

func (m *Manager) auditApprovalFailure(req state.RequestRecord, grant state.GrantRecord, reconcileResult *gmail.ReconcileResult, actor string, err error) {
	details := map[string]any{
		"email":              grant.Email,
		"visibility_label":   grant.VisibilityLabel,
		"classification":     grant.ClassificationLabels,
		"canonical_approved": true,
		"error":              err.Error(),
	}
	if reconcileResult != nil {
		details["gmail_reconcile"] = reconcileResult
	}
	_ = audit.Logger{Path: m.cfg.AuditLogPath}.Append(audit.Record{
		Event:       "request_approved_enforcement_failed",
		RequestID:   req.RequestID,
		RequestHash: req.RequestHash,
		Actor:       actor,
		Status:      req.Status,
		Details:     details,
	})
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
func (m *Manager) ReconcileAll(ctx context.Context, apply, backfillHistorical bool) ([]gmail.ReconcileResult, error) {
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
	backfillEmails := map[string]bool{}
	if apply && !backfillHistorical {
		for _, grant := range grants {
			if grant.CreatedFromRequestID == "" {
				continue
			}
			req, err := m.store.GetRequest(ctx, grant.CreatedFromRequestID)
			if err != nil {
				return nil, err
			}
			if req.Status == state.StatusApproved {
				backfillEmails[grant.Email] = true
			}
		}
	}
	opts := gmail.ReconcileOptions{
		Apply:              apply,
		BackfillHistorical: backfillHistorical || len(backfillEmails) > 0,
	}
	if !backfillHistorical && len(backfillEmails) > 0 {
		opts.BackfillHistoricalEmails = backfillEmails
	}
	results, err := client.ReconcileGrants(ctx, grants, opts)
	if apply {
		if updateErr := m.recordGrantFilterIDs(ctx, results); updateErr != nil {
			return results, updateErr
		}
	}
	if err != nil {
		return results, err
	}
	for _, grant := range grants {
		if !apply || grant.CreatedFromRequestID == "" {
			continue
		}
		result := findReconcileResult(results, grant.Email)
		if result == nil || !successfulReconcileStatus(result.Status) {
			continue
		}
		if _, markErr := m.store.MarkRequestApplied(ctx, grant.CreatedFromRequestID); markErr != nil {
			return results, markErr
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
