package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/config"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/request"
)

const (
	VerdictAutoSafe           = "auto_safe"
	VerdictNeedsHumanApproval = "needs_human_approval"
	VerdictBlocked            = "blocked"
)

// Evaluation is the trusted policy result for one normalized request.
type Evaluation struct {
	Verdict          string
	ApprovalRequired bool
	Reasons          []string
	Request          request.VisibilityRequest
}

// Evaluate applies deterministic trusted policy. It must not use Donna-provided
// claims beyond the strict request fields.
func Evaluate(cfg config.Config, req request.VisibilityRequest) Evaluation {
	normalized, err := req.NormalizeBasic()
	if err != nil {
		return Evaluation{
			Verdict:          VerdictBlocked,
			ApprovalRequired: false,
			Reasons:          []string{err.Error()},
			Request:          req,
		}
	}

	reasons := []string{}
	allowedLabels := cfg.AllowedLabelSet()
	sensitiveLabels := cfg.SensitiveLabelSet()
	visibilityLabelKey := config.NormalizeLabel(cfg.VisibilityLabel)

	canonicalLabels := make([]string, 0, len(normalized.ClassificationLabels))
	for _, label := range normalized.ClassificationLabels {
		key := config.NormalizeLabel(label)
		if key == visibilityLabelKey {
			reasons = append(reasons, "classification labels must not include the Donna visibility label")
			continue
		}
		canonical, ok := allowedLabels[key]
		if !ok {
			reasons = append(reasons, fmt.Sprintf("classification label %q is not allowlisted", label))
			continue
		}
		canonicalLabels = append(canonicalLabels, canonical)
		if _, ok := sensitiveLabels[key]; ok {
			reasons = append(reasons, fmt.Sprintf("classification label %q is sensitive", canonical))
		}
	}
	sort.Slice(canonicalLabels, func(i, j int) bool {
		return config.NormalizeLabel(canonicalLabels[i]) < config.NormalizeLabel(canonicalLabels[j])
	})
	normalized.ClassificationLabels = canonicalLabels

	if hasBlockingReason(reasons) {
		return Evaluation{
			Verdict:          VerdictBlocked,
			ApprovalRequired: false,
			Reasons:          reasons,
			Request:          normalized,
		}
	}

	switch normalized.Action {
	case request.ActionCreateVisibilityGrant:
		reasons = append(reasons, "creates or confirms Donna-readable visibility for one sender")
	case request.ActionUpdateGrantLabels:
		reasons = append(reasons, "changes trusted classification labels for an existing Donna-visible sender")
	default:
		reasons = append(reasons, "unsupported action")
		return Evaluation{
			Verdict:          VerdictBlocked,
			ApprovalRequired: false,
			Reasons:          reasons,
			Request:          normalized,
		}
	}

	return Evaluation{
		Verdict:          VerdictNeedsHumanApproval,
		ApprovalRequired: true,
		Reasons:          reasons,
		Request:          normalized,
	}
}

func hasBlockingReason(reasons []string) bool {
	for _, reason := range reasons {
		switch {
		case reason == "":
			continue
		case strings.Contains(reason, "not allowlisted"):
			return true
		case strings.Contains(reason, "visibility label"):
			return true
		}
	}
	return false
}
