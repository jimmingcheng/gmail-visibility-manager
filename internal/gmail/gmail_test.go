package gmail

import (
	"testing"

	gmailapi "google.golang.org/api/gmail/v1"
)

func TestFilterMatchesOnlyExactAddLabelFilter(t *testing.T) {
	filter := &gmailapi.Filter{
		Id:       "f1",
		Criteria: &gmailapi.FilterCriteria{From: "coach@example.com"},
		Action:   &gmailapi.FilterAction{AddLabelIds: []string{"Label_1", "Label_2"}},
	}
	if !filterMatches(filter, "coach@example.com", []string{"Label_2", "Label_1"}) {
		t.Fatal("expected exact add-label filter to match")
	}
}

func TestFilterMatchesRejectsDestructiveOrBroadFilters(t *testing.T) {
	tests := map[string]*gmailapi.Filter{
		"query": {
			Criteria: &gmailapi.FilterCriteria{From: "coach@example.com", Query: "newer_than:30d"},
			Action:   &gmailapi.FilterAction{AddLabelIds: []string{"Label_1"}},
		},
		"forward": {
			Criteria: &gmailapi.FilterCriteria{From: "coach@example.com"},
			Action:   &gmailapi.FilterAction{AddLabelIds: []string{"Label_1"}, Forward: "attacker@example.com"},
		},
		"remove": {
			Criteria: &gmailapi.FilterCriteria{From: "coach@example.com"},
			Action:   &gmailapi.FilterAction{AddLabelIds: []string{"Label_1"}, RemoveLabelIds: []string{"INBOX"}},
		},
	}
	for name, filter := range tests {
		t.Run(name, func(t *testing.T) {
			if filterMatches(filter, "coach@example.com", []string{"Label_1"}) {
				t.Fatal("expected filter to be rejected")
			}
		})
	}
}
