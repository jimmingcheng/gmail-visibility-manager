package manager

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/config"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/request"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/state"
)

func TestApproveLeavesRequestApprovedWhenGmailFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.Config{
		StatePath:                   filepath.Join(dir, "state.db"),
		AuditLogPath:                filepath.Join(dir, "audit.jsonl"),
		VisibilityLabel:             "Donna",
		AllowedClassificationLabels: []string{"Kids/Activities"},
		AccountEmail:                "owner@example.com",
		OAuthClientPath:             filepath.Join(dir, "missing-oauth-client.json"),
	}
	mgr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	_, err = mgr.Submit(ctx, request.VisibilityRequest{
		SchemaVersion:        request.SchemaVersion1,
		RequestID:            "req-1",
		RequestedBy:          "donna",
		Action:               request.ActionCreateVisibilityGrant,
		Email:                "coach@example.com",
		ClassificationLabels: []string{"Kids/Activities"},
		Rationale:            "New coach contact.",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, err = mgr.Approve(ctx, "req-1", "jimming")
	if err == nil {
		t.Fatal("expected Gmail setup failure")
	}
	record, err := mgr.Store().GetRequest(ctx, "req-1")
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != state.StatusApproved {
		t.Fatalf("status = %s, want %s", record.Status, state.StatusApproved)
	}
	if record.AppliedAt != "" {
		t.Fatalf("applied_at = %s", record.AppliedAt)
	}
}
