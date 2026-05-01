package policy

import (
	"testing"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/config"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/request"
)

func TestEvaluateAllowedGrantNeedsApproval(t *testing.T) {
	cfg := config.Config{
		StatePath:                   "/tmp/state.db",
		AuditLogPath:                "/tmp/audit.jsonl",
		VisibilityLabel:             "Donna",
		AllowedClassificationLabels: []string{"Kids/Activities"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	eval := Evaluate(cfg, request.VisibilityRequest{
		SchemaVersion:        request.SchemaVersion1,
		RequestedBy:          "donna",
		Action:               request.ActionCreateVisibilityGrant,
		Email:                "coach@example.com",
		ClassificationLabels: []string{"kids/activities"},
	})
	if eval.Verdict != VerdictNeedsHumanApproval {
		t.Fatalf("verdict = %s", eval.Verdict)
	}
	if !eval.ApprovalRequired {
		t.Fatal("approval should be required")
	}
	if got := eval.Request.ClassificationLabels[0]; got != "Kids/Activities" {
		t.Fatalf("canonical label = %q", got)
	}
}

func TestEvaluateBlocksDisallowedLabel(t *testing.T) {
	cfg := config.Config{
		StatePath:                   "/tmp/state.db",
		AuditLogPath:                "/tmp/audit.jsonl",
		VisibilityLabel:             "Donna",
		AllowedClassificationLabels: []string{"Kids/Activities"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	eval := Evaluate(cfg, request.VisibilityRequest{
		SchemaVersion:        request.SchemaVersion1,
		RequestedBy:          "donna",
		Action:               request.ActionCreateVisibilityGrant,
		Email:                "coach@example.com",
		ClassificationLabels: []string{"Taxes"},
	})
	if eval.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s", eval.Verdict)
	}
}

func TestEvaluateBlocksVisibilityLabelAsClassification(t *testing.T) {
	cfg := config.Config{
		StatePath:                   "/tmp/state.db",
		AuditLogPath:                "/tmp/audit.jsonl",
		VisibilityLabel:             "Donna",
		AllowedClassificationLabels: []string{"Kids/Activities"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	eval := Evaluate(cfg, request.VisibilityRequest{
		SchemaVersion:        request.SchemaVersion1,
		RequestedBy:          "donna",
		Action:               request.ActionCreateVisibilityGrant,
		Email:                "coach@example.com",
		ClassificationLabels: []string{"Donna"},
	})
	if eval.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s", eval.Verdict)
	}
}
