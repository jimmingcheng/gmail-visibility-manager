package gmail

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/auth"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/config"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/gmailfilter"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/state"
	"golang.org/x/oauth2"
	gmailapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

const requestTimeout = 30 * time.Second

// OAuthScopes returns the Gmail scopes required to manage labels and filters.
func OAuthScopes() []string {
	return []string{
		gmailapi.GmailReadonlyScope,
		gmailapi.GmailLabelsScope,
		gmailapi.GmailSettingsBasicScope,
	}
}

// Client wraps the Gmail API surface used by this manager.
type Client struct {
	svc *gmailapi.Service
}

// New opens a Gmail API client from trusted config.
func New(ctx context.Context, cfg config.Config) (*Client, error) {
	if err := cfg.ValidateGmail(); err != nil {
		return nil, err
	}
	oauthClient, err := auth.LoadOAuthClient(cfg.OAuthClientPath)
	if err != nil {
		return nil, err
	}
	store, err := auth.OpenTokenStore(cfg.AuthStore)
	if err != nil {
		return nil, err
	}
	tokenSource, err := auth.TokenSource(ctx, oauthClient, store, cfg.Instance, cfg.AccountEmail, OAuthScopes())
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{
		Transport: &oauth2.Transport{
			Source: tokenSource,
			Base:   http.DefaultTransport,
		},
	}
	svc, err := gmailapi.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("create gmail service: %w", err)
	}
	return &Client{svc: svc}, nil
}

// ProfileEmailFromToken verifies an OAuth token's Gmail account.
func ProfileEmailFromToken(ctx context.Context, tok *oauth2.Token) (string, error) {
	if tok == nil {
		return "", fmt.Errorf("missing oauth token")
	}
	httpClient := &http.Client{
		Transport: &oauth2.Transport{
			Source: oauth2.StaticTokenSource(tok),
			Base:   http.DefaultTransport,
		},
	}
	svc, err := gmailapi.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return "", fmt.Errorf("create gmail service: %w", err)
	}
	return (&Client{svc: svc}).ProfileEmail(ctx)
}

// ProfileEmail returns the Gmail address for the authorized token.
func (c *Client) ProfileEmail(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	profile, err := c.svc.Users.GetProfile("me").Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("get gmail profile: %w", err)
	}
	return strings.TrimSpace(profile.EmailAddress), nil
}

// LabelNameToID returns Gmail labels keyed by normalized name.
func (c *Client) LabelNameToID(ctx context.Context) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := c.svc.Users.Labels.List("me").
		Context(ctx).
		Fields("labels(id,name)").
		Do()
	if err != nil {
		return nil, fmt.Errorf("list gmail labels: %w", err)
	}
	result := map[string]string{}
	for _, label := range resp.Labels {
		if label == nil || strings.TrimSpace(label.Id) == "" || strings.TrimSpace(label.Name) == "" {
			continue
		}
		result[config.NormalizeLabel(label.Name)] = strings.TrimSpace(label.Id)
	}
	return result, nil
}

// ListFilters returns all Gmail filters.
func (c *Client) ListFilters(ctx context.Context) ([]*gmailapi.Filter, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := c.svc.Users.Settings.Filters.List("me").
		Context(ctx).
		Fields("filter(id,criteria,action)").
		Do()
	if err != nil {
		return nil, fmt.Errorf("list gmail filters: %w", err)
	}
	if resp.Filter == nil {
		return []*gmailapi.Filter{}, nil
	}
	return resp.Filter, nil
}

// CreateManagedFilter creates the narrow exact-sender, add-label-only filter.
func (c *Client) CreateManagedFilter(ctx context.Context, spec gmailfilter.Spec, labelIDs []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	filter := &gmailapi.Filter{
		Criteria: &gmailapi.FilterCriteria{From: spec.From},
		Action:   &gmailapi.FilterAction{AddLabelIds: append([]string(nil), labelIDs...)},
	}
	created, err := c.svc.Users.Settings.Filters.Create("me", filter).
		Context(ctx).
		Fields("id").
		Do()
	if err != nil {
		return "", fmt.Errorf("create gmail filter: %w", err)
	}
	if strings.TrimSpace(created.Id) == "" {
		return "", fmt.Errorf("create gmail filter: Gmail returned empty filter id")
	}
	return strings.TrimSpace(created.Id), nil
}

// ReconcileOptions controls whether Gmail mutations are performed.
type ReconcileOptions struct {
	Apply bool
}

// ReconcileResult describes one grant's Gmail filter state.
type ReconcileResult struct {
	Email          string           `json:"email"`
	ExpectedFilter gmailfilter.Spec `json:"expected_filter"`
	GmailFilterID  string           `json:"gmail_filter_id,omitempty"`
	Status         string           `json:"status"`
	Changed        bool             `json:"changed"`
	Message        string           `json:"message,omitempty"`
}

// ReconcileGrant ensures a canonical grant has a corresponding managed Gmail filter.
func (c *Client) ReconcileGrant(ctx context.Context, grant state.GrantRecord, opts ReconcileOptions) (ReconcileResult, error) {
	spec := gmailfilter.CompileGrant(grant.Email, grant.VisibilityLabel, grant.ClassificationLabels)
	labelIDs, err := c.resolveLabelIDs(ctx, spec.AddLabels)
	if err != nil {
		return ReconcileResult{Email: grant.Email, ExpectedFilter: spec, Status: "error", Message: err.Error()}, err
	}
	filters, err := c.ListFilters(ctx)
	if err != nil {
		return ReconcileResult{Email: grant.Email, ExpectedFilter: spec, Status: "error", Message: err.Error()}, err
	}

	if strings.TrimSpace(grant.GmailFilterID) != "" {
		if existing := findFilterByID(filters, grant.GmailFilterID); existing != nil {
			if filterMatches(existing, spec.From, labelIDs) {
				return ReconcileResult{
					Email:          grant.Email,
					ExpectedFilter: spec,
					GmailFilterID:  grant.GmailFilterID,
					Status:         "ok",
					Message:        "managed filter exists",
				}, nil
			}
			return ReconcileResult{
				Email:          grant.Email,
				ExpectedFilter: spec,
				GmailFilterID:  grant.GmailFilterID,
				Status:         "drift",
				Message:        "stored Gmail filter id exists but no longer matches the canonical grant; leaving it untouched",
			}, nil
		}
	}

	if existing := findMatchingFilter(filters, spec.From, labelIDs); existing != nil {
		return ReconcileResult{
			Email:          grant.Email,
			ExpectedFilter: spec,
			GmailFilterID:  existing.Id,
			Status:         "bind_existing",
			Changed:        true,
			Message:        "matching Gmail filter already exists and can be recorded as managed",
		}, nil
	}

	result := ReconcileResult{
		Email:          grant.Email,
		ExpectedFilter: spec,
		Status:         "missing",
		Message:        "managed Gmail filter is missing",
	}
	if !opts.Apply {
		return result, nil
	}
	filterID, err := c.CreateManagedFilter(ctx, spec, labelIDs)
	if err != nil {
		result.Status = "error"
		result.Message = err.Error()
		return result, err
	}
	result.Status = "created"
	result.Changed = true
	result.GmailFilterID = filterID
	result.Message = "created managed Gmail filter"
	return result, nil
}

func (c *Client) resolveLabelIDs(ctx context.Context, labels []string) ([]string, error) {
	nameToID, err := c.LabelNameToID(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(labels))
	for _, label := range labels {
		id, ok := nameToID[config.NormalizeLabel(label)]
		if !ok || strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("Gmail label %q was not found; create it before reconciling", label)
		}
		result = append(result, id)
	}
	return result, nil
}

func findFilterByID(filters []*gmailapi.Filter, id string) *gmailapi.Filter {
	id = strings.TrimSpace(id)
	for _, filter := range filters {
		if filter != nil && strings.TrimSpace(filter.Id) == id {
			return filter
		}
	}
	return nil
}

func findMatchingFilter(filters []*gmailapi.Filter, from string, addLabelIDs []string) *gmailapi.Filter {
	for _, filter := range filters {
		if filterMatches(filter, from, addLabelIDs) {
			return filter
		}
	}
	return nil
}

func filterMatches(filter *gmailapi.Filter, from string, addLabelIDs []string) bool {
	if filter == nil || filter.Criteria == nil || filter.Action == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(filter.Criteria.From), strings.TrimSpace(from)) {
		return false
	}
	if strings.TrimSpace(filter.Criteria.Query) != "" ||
		strings.TrimSpace(filter.Criteria.NegatedQuery) != "" ||
		strings.TrimSpace(filter.Criteria.To) != "" ||
		strings.TrimSpace(filter.Criteria.Subject) != "" ||
		filter.Criteria.HasAttachment ||
		filter.Criteria.ExcludeChats ||
		filter.Criteria.Size != 0 ||
		strings.TrimSpace(filter.Criteria.SizeComparison) != "" {
		return false
	}
	if strings.TrimSpace(filter.Action.Forward) != "" || len(filter.Action.RemoveLabelIds) > 0 {
		return false
	}
	return sameStringSet(filter.Action.AddLabelIds, addLabelIDs)
}

func sameStringSet(a, b []string) bool {
	aa := normalizedSorted(a)
	bb := normalizedSorted(b)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func normalizedSorted(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	sort.Strings(result)
	return result
}
