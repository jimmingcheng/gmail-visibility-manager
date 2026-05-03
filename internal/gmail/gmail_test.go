package gmail

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/state"
	gmailapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

func TestFilterMatchesOnlyExactSingleLabelFilter(t *testing.T) {
	filter := &gmailapi.Filter{
		Id:       "f1",
		Criteria: &gmailapi.FilterCriteria{From: "coach@example.com"},
		Action:   &gmailapi.FilterAction{AddLabelIds: []string{"Label_1"}},
	}
	if !filterMatches(filter, "coach@example.com", []string{"Label_1"}) {
		t.Fatal("expected exact single-label filter to match")
	}
	if filterMatches(filter, "coach@example.com", []string{"Label_1", "Label_2"}) {
		t.Fatal("expected multi-label expectation to be rejected")
	}
	filter.Action.AddLabelIds = []string{"Label_1", "Label_2"}
	if filterMatches(filter, "coach@example.com", []string{"Label_1"}) {
		t.Fatal("expected multi-label Gmail filter to be rejected")
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

func TestVisibilityFilterMatchesExactSenderGroup(t *testing.T) {
	filter := &gmailapi.Filter{
		Id:       "f1",
		Criteria: &gmailapi.FilterCriteria{From: "friend@example.com OR coach@example.com"},
		Action:   &gmailapi.FilterAction{AddLabelIds: []string{"Label_Donna"}},
	}
	if !visibilityFilterMatchesExactSender(filter, "coach@example.com", "Label_Donna") {
		t.Fatal("expected grouped exact-email visibility filter to match")
	}
	filter.Criteria.From = "(friend@example.com) or (coach@example.com)"
	if !visibilityFilterMatchesExactSender(filter, "coach@example.com", "Label_Donna") {
		t.Fatal("expected parenthesized grouped exact-email visibility filter to match")
	}
	filter.Criteria.From = "friend@example.com OR srcs.org"
	if visibilityFilterMatchesExactSender(filter, "friend@example.com", "Label_Donna") {
		t.Fatal("expected mixed exact/non-exact sender group to be rejected")
	}
	filter.Criteria.From = "friend@example.com OR coach@example.com"
	filter.Criteria.Query = "newer_than:30d"
	if visibilityFilterMatchesExactSender(filter, "coach@example.com", "Label_Donna") {
		t.Fatal("expected query-bearing filter to be rejected")
	}
}

func TestReconcileGrantCreatesOneFilterPerLabel(t *testing.T) {
	ctx := context.Background()
	var created []*gmailapi.Filter
	var batchModified []*gmailapi.BatchModifyMessagesRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			_ = json.NewEncoder(w).Encode(&gmailapi.ListLabelsResponse{
				Labels: []*gmailapi.Label{
					{Id: "Label_Donna", Name: "Donna"},
					{Id: "Label_Kids", Name: "Kids/Activities"},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/settings/filters"):
			_ = json.NewEncoder(w).Encode(&gmailapi.ListFiltersResponse{})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/settings/filters"):
			var filter gmailapi.Filter
			if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
				t.Errorf("decode created filter: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			created = append(created, &filter)
			_ = json.NewEncoder(w).Encode(&gmailapi.Filter{Id: fmt.Sprintf("f-%d", len(created))})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages"):
			if got := r.URL.Query().Get("q"); got != "from:(coach@example.com)" {
				t.Errorf("historical query = %q", got)
			}
			if got := r.URL.Query().Get("includeSpamTrash"); got != "true" {
				t.Errorf("includeSpamTrash = %q", got)
			}
			_ = json.NewEncoder(w).Encode(&gmailapi.ListMessagesResponse{
				Messages: []*gmailapi.Message{
					{Id: "m-1"},
					{Id: "m-2"},
				},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/messages/batchModify"):
			var req gmailapi.BatchModifyMessagesRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode batch modify: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			batchModified = append(batchModified, &req)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	svc, err := gmailapi.NewService(ctx,
		option.WithEndpoint(server.URL+"/"),
		option.WithHTTPClient(server.Client()),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatal(err)
	}

	client := &Client{svc: svc}
	result, err := client.ReconcileGrant(ctx, state.GrantRecord{
		Email:                "coach@example.com",
		VisibilityLabel:      "Donna",
		ClassificationLabels: []string{"Kids/Activities"},
	}, ReconcileOptions{Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "created" {
		t.Fatalf("status = %s", result.Status)
	}
	if result.GmailFilterID != "f-1" {
		t.Fatalf("primary gmail filter id = %q", result.GmailFilterID)
	}
	if len(result.LabelFilters) != 2 {
		t.Fatalf("label filters = %#v", result.LabelFilters)
	}
	if len(created) != 2 {
		t.Fatalf("created filters = %d", len(created))
	}
	gotLabels := map[string]bool{}
	for _, filter := range created {
		if filter.Criteria == nil || filter.Criteria.From != "coach@example.com" {
			t.Fatalf("created filter criteria = %#v", filter.Criteria)
		}
		if filter.Action == nil || len(filter.Action.AddLabelIds) != 1 {
			t.Fatalf("created filter action = %#v", filter.Action)
		}
		gotLabels[filter.Action.AddLabelIds[0]] = true
	}
	for _, labelID := range []string{"Label_Donna", "Label_Kids"} {
		if !gotLabels[labelID] {
			t.Fatalf("missing created label %s in %#v", labelID, gotLabels)
		}
	}
	if result.HistoricalBackfill == nil {
		t.Fatal("expected historical backfill")
	}
	if result.HistoricalBackfill.MessagesMatched != 2 || result.HistoricalBackfill.MessagesModified != 2 {
		t.Fatalf("backfill = %#v", result.HistoricalBackfill)
	}
	if len(batchModified) != 1 {
		t.Fatalf("batch modify calls = %d", len(batchModified))
	}
	if strings.Join(batchModified[0].Ids, ",") != "m-1,m-2" {
		t.Fatalf("batch ids = %#v", batchModified[0].Ids)
	}
	if strings.Join(batchModified[0].AddLabelIds, ",") != "Label_Donna,Label_Kids" {
		t.Fatalf("batch labels = %#v", batchModified[0].AddLabelIds)
	}
}

func TestReconcileGrantsConsolidatesVisibilityExactSenderFilters(t *testing.T) {
	ctx := context.Background()
	existingFilters := []*gmailapi.Filter{
		{
			Id:       "old-coach",
			Criteria: &gmailapi.FilterCriteria{From: "coach@example.com"},
			Action:   &gmailapi.FilterAction{AddLabelIds: []string{"Label_Donna"}},
		},
		{
			Id:       "old-legacy",
			Criteria: &gmailapi.FilterCriteria{From: "legacy@example.com"},
			Action:   &gmailapi.FilterAction{AddLabelIds: []string{"Label_Donna"}},
		},
		{
			Id:       "query-donna",
			Criteria: &gmailapi.FilterCriteria{Query: "from:(example.org)"},
			Action:   &gmailapi.FilterAction{AddLabelIds: []string{"Label_Donna"}},
		},
	}
	var created []*gmailapi.Filter
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			_ = json.NewEncoder(w).Encode(&gmailapi.ListLabelsResponse{
				Labels: []*gmailapi.Label{{Id: "Label_Donna", Name: "Donna"}},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/settings/filters"):
			_ = json.NewEncoder(w).Encode(&gmailapi.ListFiltersResponse{Filter: existingFilters})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/settings/filters"):
			var filter gmailapi.Filter
			if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
				t.Errorf("decode created filter: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			created = append(created, &filter)
			_ = json.NewEncoder(w).Encode(&gmailapi.Filter{Id: fmt.Sprintf("new-%d", len(created))})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/settings/filters/"):
			deleted = append(deleted, r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages"):
			_ = json.NewEncoder(w).Encode(&gmailapi.ListMessagesResponse{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	svc, err := gmailapi.NewService(ctx,
		option.WithEndpoint(server.URL+"/"),
		option.WithHTTPClient(server.Client()),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatal(err)
	}

	client := &Client{svc: svc}
	results, err := client.ReconcileGrants(ctx, []state.GrantRecord{
		{Email: "coach@example.com", VisibilityLabel: "Donna", GmailFilterID: "old-coach"},
		{Email: "parent@example.com", VisibilityLabel: "Donna"},
	}, ReconcileOptions{Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d", len(results))
	}
	for _, result := range results {
		if result.Status != "created" {
			t.Fatalf("%s status = %s", result.Email, result.Status)
		}
		if result.GmailFilterID != "new-1" {
			t.Fatalf("%s gmail filter id = %q", result.Email, result.GmailFilterID)
		}
		if !result.Changed {
			t.Fatalf("%s changed = false", result.Email)
		}
	}
	if len(created) != 1 {
		t.Fatalf("created filters = %d", len(created))
	}
	if created[0].Criteria == nil || created[0].Criteria.From != "coach@example.com OR legacy@example.com OR parent@example.com" {
		t.Fatalf("created criteria = %#v", created[0].Criteria)
	}
	if created[0].Action == nil || strings.Join(created[0].Action.AddLabelIds, ",") != "Label_Donna" {
		t.Fatalf("created action = %#v", created[0].Action)
	}
	sort.Strings(deleted)
	if strings.Join(deleted, ",") != "old-coach,old-legacy" {
		t.Fatalf("deleted filters = %#v", deleted)
	}
}
