package state

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/policy"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/request"
	_ "modernc.org/sqlite"
)

const (
	StatusPending = "pending"
	StatusBlocked = "blocked"
	StatusDenied  = "denied"
	StatusApplied = "applied"
)

// RequestRecord is the trusted persisted view of an untrusted request.
type RequestRecord struct {
	RequestID            string   `json:"request_id"`
	RequestHash          string   `json:"request_hash"`
	SchemaVersion        string   `json:"schema_version"`
	CreatedAt            string   `json:"created_at"`
	ReceivedAt           string   `json:"received_at"`
	RequestedBy          string   `json:"requested_by"`
	Action               string   `json:"action"`
	Email                string   `json:"email"`
	ClassificationLabels []string `json:"classification_labels"`
	Rationale            string   `json:"rationale"`
	Status               string   `json:"status"`
	PolicyVerdict        string   `json:"policy_verdict"`
	PolicyReasons        []string `json:"policy_reasons"`
	ApprovalRequired     bool     `json:"approval_required"`
	DecidedBy            string   `json:"decided_by,omitempty"`
	DecisionReason       string   `json:"decision_reason,omitempty"`
	DecidedAt            string   `json:"decided_at,omitempty"`
	AppliedAt            string   `json:"applied_at,omitempty"`
}

// GrantRecord is the canonical trusted source of truth for a Donna visibility grant.
type GrantRecord struct {
	Email                string   `json:"email"`
	VisibilityLabel      string   `json:"visibility_label"`
	ClassificationLabels []string `json:"classification_labels"`
	Status               string   `json:"status"`
	CreatedFromRequestID string   `json:"created_from_request_id"`
	RequestedBy          string   `json:"requested_by"`
	Rationale            string   `json:"rationale"`
	ApprovedBy           string   `json:"approved_by"`
	ApprovedAt           string   `json:"approved_at"`
	CreatedAt            string   `json:"created_at"`
	UpdatedAt            string   `json:"updated_at"`
	GmailFilterID        string   `json:"gmail_filter_id,omitempty"`
}

// Store owns the local SQLite state database.
type Store struct {
	db *sql.DB
}

// Open opens or creates a trusted state database.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	store := &Store{db: db}
	if err := store.configure(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) configure() error {
	for _, stmt := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA journal_mode = WAL`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("configure state db: %w", err)
		}
	}
	return nil
}

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS requests (
			request_id TEXT PRIMARY KEY,
			request_hash TEXT NOT NULL,
			schema_version TEXT NOT NULL,
			created_at TEXT NOT NULL,
			received_at TEXT NOT NULL,
			requested_by TEXT NOT NULL,
			action TEXT NOT NULL,
			email TEXT NOT NULL,
			classification_labels_json TEXT NOT NULL,
			rationale TEXT NOT NULL,
			status TEXT NOT NULL,
			policy_verdict TEXT NOT NULL,
			policy_reasons_json TEXT NOT NULL,
			approval_required INTEGER NOT NULL,
			decided_by TEXT NOT NULL DEFAULT '',
			decision_reason TEXT NOT NULL DEFAULT '',
			decided_at TEXT NOT NULL DEFAULT '',
			applied_at TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_requests_status_received ON requests(status, received_at)`,
		`CREATE TABLE IF NOT EXISTS grants (
			email TEXT PRIMARY KEY,
			visibility_label TEXT NOT NULL,
			classification_labels_json TEXT NOT NULL,
			status TEXT NOT NULL,
			created_from_request_id TEXT NOT NULL,
			requested_by TEXT NOT NULL,
			rationale TEXT NOT NULL,
			approved_by TEXT NOT NULL,
			approved_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			gmail_filter_id TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_grants_status ON grants(status)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate state db: %w", err)
		}
	}
	return nil
}

// Submit stores the request and its trusted policy verdict.
func (s *Store) Submit(ctx context.Context, eval policy.Evaluation) (RequestRecord, error) {
	req := eval.Request
	if strings.TrimSpace(req.RequestID) == "" {
		req.RequestID = newRequestID()
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if strings.TrimSpace(req.CreatedAt) == "" {
		req.CreatedAt = now
	}
	hash, err := request.Hash(req)
	if err != nil {
		return RequestRecord{}, err
	}
	status := StatusPending
	if eval.Verdict == policy.VerdictBlocked {
		status = StatusBlocked
	}
	labelsJSON, err := marshalStringSlice(req.ClassificationLabels)
	if err != nil {
		return RequestRecord{}, err
	}
	reasonsJSON, err := marshalStringSlice(eval.Reasons)
	if err != nil {
		return RequestRecord{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO requests (
		request_id, request_hash, schema_version, created_at, received_at,
		requested_by, action, email, classification_labels_json, rationale,
		status, policy_verdict, policy_reasons_json, approval_required
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.RequestID, hash, req.SchemaVersion, req.CreatedAt, now,
		req.RequestedBy, req.Action, req.Email, labelsJSON, req.Rationale,
		status, eval.Verdict, reasonsJSON, boolInt(eval.ApprovalRequired))
	if err != nil {
		return RequestRecord{}, fmt.Errorf("insert request: %w", err)
	}
	return RequestRecord{
		RequestID:            req.RequestID,
		RequestHash:          hash,
		SchemaVersion:        req.SchemaVersion,
		CreatedAt:            req.CreatedAt,
		ReceivedAt:           now,
		RequestedBy:          req.RequestedBy,
		Action:               req.Action,
		Email:                req.Email,
		ClassificationLabels: append([]string(nil), req.ClassificationLabels...),
		Rationale:            req.Rationale,
		Status:               status,
		PolicyVerdict:        eval.Verdict,
		PolicyReasons:        append([]string(nil), eval.Reasons...),
		ApprovalRequired:     eval.ApprovalRequired,
	}, nil
}

// Approve applies a pending trusted request to the canonical grant table.
func (s *Store) Approve(ctx context.Context, requestID, approver, visibilityLabel string) (RequestRecord, GrantRecord, error) {
	requestID = strings.TrimSpace(requestID)
	approver = strings.TrimSpace(approver)
	if requestID == "" {
		return RequestRecord{}, GrantRecord{}, fmt.Errorf("request id is required")
	}
	if approver == "" {
		return RequestRecord{}, GrantRecord{}, fmt.Errorf("approver is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RequestRecord{}, GrantRecord{}, err
	}
	defer tx.Rollback()

	req, err := getRequestTx(ctx, tx, requestID)
	if err != nil {
		return RequestRecord{}, GrantRecord{}, err
	}
	if req.Status != StatusPending {
		return RequestRecord{}, GrantRecord{}, fmt.Errorf("request %s is %s, not pending", requestID, req.Status)
	}

	if req.Action == request.ActionUpdateGrantLabels {
		exists, err := grantExistsTx(ctx, tx, req.Email)
		if err != nil {
			return RequestRecord{}, GrantRecord{}, err
		}
		if !exists {
			return RequestRecord{}, GrantRecord{}, fmt.Errorf("cannot update labels: grant for %s does not exist", req.Email)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	labelsJSON, err := marshalStringSlice(req.ClassificationLabels)
	if err != nil {
		return RequestRecord{}, GrantRecord{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO grants (
		email, visibility_label, classification_labels_json, status,
		created_from_request_id, requested_by, rationale, approved_by,
		approved_at, created_at, updated_at
	) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(email) DO UPDATE SET
		visibility_label = excluded.visibility_label,
		classification_labels_json = excluded.classification_labels_json,
		status = 'active',
		created_from_request_id = excluded.created_from_request_id,
		requested_by = excluded.requested_by,
		rationale = excluded.rationale,
		approved_by = excluded.approved_by,
		approved_at = excluded.approved_at,
		updated_at = excluded.updated_at`,
		req.Email, visibilityLabel, labelsJSON, req.RequestID, req.RequestedBy, req.Rationale, approver, now, now, now)
	if err != nil {
		return RequestRecord{}, GrantRecord{}, fmt.Errorf("upsert grant: %w", err)
	}

	_, err = tx.ExecContext(ctx, `UPDATE requests
		SET status = ?, decided_by = ?, decided_at = ?, applied_at = ?
		WHERE request_id = ?`, StatusApplied, approver, now, now, requestID)
	if err != nil {
		return RequestRecord{}, GrantRecord{}, fmt.Errorf("update request approval: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return RequestRecord{}, GrantRecord{}, err
	}
	req.Status = StatusApplied
	req.DecidedBy = approver
	req.DecidedAt = now
	req.AppliedAt = now
	grant, err := s.LookupGrant(ctx, req.Email)
	if err != nil {
		return RequestRecord{}, GrantRecord{}, err
	}
	return req, grant, nil
}

// Deny marks a pending request denied.
func (s *Store) Deny(ctx context.Context, requestID, actor, reason string) (RequestRecord, error) {
	requestID = strings.TrimSpace(requestID)
	actor = strings.TrimSpace(actor)
	if requestID == "" {
		return RequestRecord{}, fmt.Errorf("request id is required")
	}
	if actor == "" {
		return RequestRecord{}, fmt.Errorf("actor is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RequestRecord{}, err
	}
	defer tx.Rollback()

	req, err := getRequestTx(ctx, tx, requestID)
	if err != nil {
		return RequestRecord{}, err
	}
	if req.Status != StatusPending {
		return RequestRecord{}, fmt.Errorf("request %s is %s, not pending", requestID, req.Status)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = tx.ExecContext(ctx, `UPDATE requests
		SET status = ?, decided_by = ?, decision_reason = ?, decided_at = ?
		WHERE request_id = ?`, StatusDenied, actor, strings.TrimSpace(reason), now, requestID)
	if err != nil {
		return RequestRecord{}, fmt.Errorf("update request denial: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RequestRecord{}, err
	}
	req.Status = StatusDenied
	req.DecidedBy = actor
	req.DecisionReason = strings.TrimSpace(reason)
	req.DecidedAt = now
	return req, nil
}

// ListPending returns pending requests ordered oldest first.
func (s *Store) ListPending(ctx context.Context) ([]RequestRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+requestColumns+` FROM requests WHERE status = ? ORDER BY received_at ASC`, StatusPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRequests(rows)
}

// ListRecent returns recent request records ordered newest first.
func (s *Store) ListRecent(ctx context.Context, limit int) ([]RequestRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+requestColumns+` FROM requests ORDER BY received_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRequests(rows)
}

// GetRequest returns one request.
func (s *Store) GetRequest(ctx context.Context, requestID string) (RequestRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+requestColumns+` FROM requests WHERE request_id = ?`, strings.TrimSpace(requestID))
	return scanRequest(row)
}

// ListGrants returns active grants ordered by email.
func (s *Store) ListGrants(ctx context.Context) ([]GrantRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+grantColumns+` FROM grants WHERE status = 'active' ORDER BY email ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrants(rows)
}

// LookupGrant returns one grant by normalized email.
func (s *Store) LookupGrant(ctx context.Context, email string) (GrantRecord, error) {
	email, err := request.NormalizeEmail(email)
	if err != nil {
		return GrantRecord{}, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM grants WHERE email = ?`, email)
	return scanGrant(row)
}

const requestColumns = `request_id, request_hash, schema_version, created_at, received_at,
	requested_by, action, email, classification_labels_json, rationale, status,
	policy_verdict, policy_reasons_json, approval_required, decided_by,
	decision_reason, decided_at, applied_at`

const grantColumns = `email, visibility_label, classification_labels_json, status,
	created_from_request_id, requested_by, rationale, approved_by, approved_at,
	created_at, updated_at, gmail_filter_id`

type scanner interface {
	Scan(dest ...any) error
}

func getRequestTx(ctx context.Context, tx *sql.Tx, requestID string) (RequestRecord, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+requestColumns+` FROM requests WHERE request_id = ?`, strings.TrimSpace(requestID))
	return scanRequest(row)
}

func grantExistsTx(ctx context.Context, tx *sql.Tx, email string) (bool, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM grants WHERE email = ? AND status = 'active'`, email).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func scanRequests(rows *sql.Rows) ([]RequestRecord, error) {
	var result []RequestRecord
	for rows.Next() {
		record, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func scanRequest(row scanner) (RequestRecord, error) {
	var record RequestRecord
	var labelsJSON, reasonsJSON string
	var approvalRequired int
	if err := row.Scan(
		&record.RequestID,
		&record.RequestHash,
		&record.SchemaVersion,
		&record.CreatedAt,
		&record.ReceivedAt,
		&record.RequestedBy,
		&record.Action,
		&record.Email,
		&labelsJSON,
		&record.Rationale,
		&record.Status,
		&record.PolicyVerdict,
		&reasonsJSON,
		&approvalRequired,
		&record.DecidedBy,
		&record.DecisionReason,
		&record.DecidedAt,
		&record.AppliedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return RequestRecord{}, fmt.Errorf("request not found")
		}
		return RequestRecord{}, err
	}
	labels, err := unmarshalStringSlice(labelsJSON)
	if err != nil {
		return RequestRecord{}, err
	}
	reasons, err := unmarshalStringSlice(reasonsJSON)
	if err != nil {
		return RequestRecord{}, err
	}
	record.ClassificationLabels = labels
	record.PolicyReasons = reasons
	record.ApprovalRequired = approvalRequired != 0
	return record, nil
}

func scanGrants(rows *sql.Rows) ([]GrantRecord, error) {
	var result []GrantRecord
	for rows.Next() {
		record, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func scanGrant(row scanner) (GrantRecord, error) {
	var record GrantRecord
	var labelsJSON string
	if err := row.Scan(
		&record.Email,
		&record.VisibilityLabel,
		&labelsJSON,
		&record.Status,
		&record.CreatedFromRequestID,
		&record.RequestedBy,
		&record.Rationale,
		&record.ApprovedBy,
		&record.ApprovedAt,
		&record.CreatedAt,
		&record.UpdatedAt,
		&record.GmailFilterID,
	); err != nil {
		if err == sql.ErrNoRows {
			return GrantRecord{}, fmt.Errorf("grant not found")
		}
		return GrantRecord{}, err
	}
	labels, err := unmarshalStringSlice(labelsJSON)
	if err != nil {
		return GrantRecord{}, err
	}
	record.ClassificationLabels = labels
	return record, nil
}

func marshalStringSlice(values []string) (string, error) {
	if values == nil {
		values = []string{}
	}
	data, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func unmarshalStringSlice(data string) ([]string, error) {
	if strings.TrimSpace(data) == "" {
		return []string{}, nil
	}
	var values []string
	if err := json.Unmarshal([]byte(data), &values); err != nil {
		return nil, err
	}
	if values == nil {
		values = []string{}
	}
	return values, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return "req-" + hex.EncodeToString(b[:])
}
