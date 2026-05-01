package state

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/config"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/policy"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/request"
)

func TestSubmitApproveCreatesCanonicalGrant(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	defer store.Close()

	cfg := config.Config{
		StatePath:                   "/tmp/state.db",
		AuditLogPath:                "/tmp/audit.jsonl",
		VisibilityLabel:             "Donna",
		AllowedClassificationLabels: []string{"Kids/Activities"},
	}
	req := request.VisibilityRequest{
		SchemaVersion:        request.SchemaVersion1,
		RequestID:            "req-1",
		RequestedBy:          "donna",
		Action:               request.ActionCreateVisibilityGrant,
		Email:                "coach@example.com",
		ClassificationLabels: []string{"Kids/Activities"},
		Rationale:            "New coach contact.",
	}
	record, err := store.Submit(ctx, policy.Evaluate(cfg, req))
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != StatusPending {
		t.Fatalf("status = %s", record.Status)
	}

	approved, grant, err := store.Approve(ctx, "req-1", "jimming", cfg.VisibilityLabel)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != StatusApplied {
		t.Fatalf("approved status = %s", approved.Status)
	}
	if grant.Email != "coach@example.com" {
		t.Fatalf("grant email = %s", grant.Email)
	}
	if grant.VisibilityLabel != "Donna" {
		t.Fatalf("visibility label = %s", grant.VisibilityLabel)
	}
	if len(grant.ClassificationLabels) != 1 || grant.ClassificationLabels[0] != "Kids/Activities" {
		t.Fatalf("grant labels = %#v", grant.ClassificationLabels)
	}
}

func TestDenyDoesNotCreateGrant(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	defer store.Close()

	cfg := config.Config{
		StatePath:                   "/tmp/state.db",
		AuditLogPath:                "/tmp/audit.jsonl",
		VisibilityLabel:             "Donna",
		AllowedClassificationLabels: []string{"Kids/Activities"},
	}
	req := request.VisibilityRequest{
		SchemaVersion:        request.SchemaVersion1,
		RequestID:            "req-1",
		RequestedBy:          "donna",
		Action:               request.ActionCreateVisibilityGrant,
		Email:                "coach@example.com",
		ClassificationLabels: []string{"Kids/Activities"},
	}
	if _, err := store.Submit(ctx, policy.Evaluate(cfg, req)); err != nil {
		t.Fatal(err)
	}
	denied, err := store.Deny(ctx, "req-1", "jimming", "not needed")
	if err != nil {
		t.Fatal(err)
	}
	if denied.Status != StatusDenied {
		t.Fatalf("denied status = %s", denied.Status)
	}
	if _, err := store.LookupGrant(ctx, "coach@example.com"); err == nil {
		t.Fatal("expected no grant")
	}
}

func TestUpdateLabelsRequiresExistingGrant(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	defer store.Close()

	cfg := config.Config{
		StatePath:                   "/tmp/state.db",
		AuditLogPath:                "/tmp/audit.jsonl",
		VisibilityLabel:             "Donna",
		AllowedClassificationLabels: []string{"Kids/Activities"},
	}
	req := request.VisibilityRequest{
		SchemaVersion:        request.SchemaVersion1,
		RequestID:            "req-1",
		RequestedBy:          "donna",
		Action:               request.ActionUpdateGrantLabels,
		Email:                "coach@example.com",
		ClassificationLabels: []string{"Kids/Activities"},
	}
	if _, err := store.Submit(ctx, policy.Evaluate(cfg, req)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Approve(ctx, "req-1", "jimming", cfg.VisibilityLabel); err == nil {
		t.Fatal("expected update approval to fail without existing grant")
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
