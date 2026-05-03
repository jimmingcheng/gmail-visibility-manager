package gmailfilter

import (
	"sort"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/config"
)

// Spec is the logical Gmail enforcement shape this manager reconciles.
// The Gmail API adapter may emit more than one narrow filter to enforce it.
type Spec struct {
	From      string   `json:"from"`
	AddLabels []string `json:"add_labels"`
}

// CompileGrant compiles one canonical visibility grant into a narrow logical
// filter specification.
func CompileGrant(email, visibilityLabel string, classificationLabels []string) Spec {
	labels := append([]string{visibilityLabel}, classificationLabels...)
	seen := map[string]string{}
	for _, label := range labels {
		seen[config.NormalizeLabel(label)] = label
	}
	labels = labels[:0]
	for _, label := range seen {
		labels = append(labels, label)
	}
	sort.Slice(labels, func(i, j int) bool {
		if config.NormalizeLabel(labels[i]) == config.NormalizeLabel(visibilityLabel) {
			return true
		}
		if config.NormalizeLabel(labels[j]) == config.NormalizeLabel(visibilityLabel) {
			return false
		}
		return config.NormalizeLabel(labels[i]) < config.NormalizeLabel(labels[j])
	})
	return Spec{
		From:      email,
		AddLabels: labels,
	}
}
