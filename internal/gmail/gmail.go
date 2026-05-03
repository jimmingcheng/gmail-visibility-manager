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
	"github.com/jimmingcheng/gmail-visibility-manager/internal/request"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/state"
	"golang.org/x/oauth2"
	gmailapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

const requestTimeout = 30 * time.Second
const backfillListPageSize = 500
const batchModifyLimit = 1000
const maxExactSenderGroupTerms = 100
const maxExactSenderGroupLength = 7000

// OAuthScopes returns the Gmail scopes required to manage labels, filters, and
// historical message label backfills.
func OAuthScopes() []string {
	return []string{
		gmailapi.GmailReadonlyScope,
		gmailapi.GmailModifyScope,
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

// CreateManagedLabelFilter creates one narrow exact-sender, add-one-label-only filter.
func (c *Client) CreateManagedLabelFilter(ctx context.Context, from, labelID string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	filter := &gmailapi.Filter{
		Criteria: &gmailapi.FilterCriteria{From: from},
		Action:   &gmailapi.FilterAction{AddLabelIds: []string{labelID}},
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

// CreateManagedVisibilityGroupFilter creates one exact-sender OR filter that
// adds exactly one visibility label.
func (c *Client) CreateManagedVisibilityGroupFilter(ctx context.Context, senders []string, labelID string) (string, error) {
	from := formatExactSenderGroup(senders)
	if from == "" {
		return "", fmt.Errorf("create gmail visibility filter: at least one sender is required")
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	filter := &gmailapi.Filter{
		Criteria: &gmailapi.FilterCriteria{From: from},
		Action:   &gmailapi.FilterAction{AddLabelIds: []string{labelID}},
	}
	created, err := c.svc.Users.Settings.Filters.Create("me", filter).
		Context(ctx).
		Fields("id").
		Do()
	if err != nil {
		return "", fmt.Errorf("create gmail visibility filter: %w", err)
	}
	if strings.TrimSpace(created.Id) == "" {
		return "", fmt.Errorf("create gmail visibility filter: Gmail returned empty filter id")
	}
	return strings.TrimSpace(created.Id), nil
}

// DeleteFilter removes one Gmail filter by ID.
func (c *Client) DeleteFilter(ctx context.Context, filterID string) error {
	filterID = strings.TrimSpace(filterID)
	if filterID == "" {
		return fmt.Errorf("delete gmail filter: filter id is required")
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if err := c.svc.Users.Settings.Filters.Delete("me", filterID).Context(ctx).Do(); err != nil {
		return fmt.Errorf("delete gmail filter %s: %w", filterID, err)
	}
	return nil
}

// ReconcileOptions controls whether Gmail mutations are performed.
type ReconcileOptions struct {
	Apply                    bool
	BackfillHistorical       bool
	BackfillHistoricalEmails map[string]bool
}

// ReconcileResult describes one grant's Gmail filter state.
type ReconcileResult struct {
	Email              string              `json:"email"`
	ExpectedFilter     gmailfilter.Spec    `json:"expected_filter"`
	GmailFilterID      string              `json:"gmail_filter_id,omitempty"`
	LabelFilters       []LabelFilter       `json:"label_filters,omitempty"`
	HistoricalBackfill *HistoricalBackfill `json:"historical_backfill,omitempty"`
	Status             string              `json:"status"`
	Changed            bool                `json:"changed"`
	Message            string              `json:"message,omitempty"`
}

// LabelFilter describes the Gmail filter enforcing one label from a grant.
type LabelFilter struct {
	Label         string `json:"label"`
	GmailFilterID string `json:"gmail_filter_id,omitempty"`
	Status        string `json:"status"`
	Primary       bool   `json:"primary,omitempty"`
	Message       string `json:"message,omitempty"`
}

// HistoricalBackfill describes applying a newly managed label to already
// existing messages that match the grant's sender.
type HistoricalBackfill struct {
	Query            string   `json:"query"`
	Labels           []string `json:"labels"`
	MessagesMatched  int64    `json:"messages_matched"`
	MessagesModified int64    `json:"messages_modified"`
	Batches          int      `json:"batches"`
	IncludeSpamTrash bool     `json:"include_spam_trash"`
	Status           string   `json:"status"`
	Message          string   `json:"message,omitempty"`
}

// ReconcileGrant ensures one canonical grant has corresponding managed Gmail filters.
func (c *Client) ReconcileGrant(ctx context.Context, grant state.GrantRecord, opts ReconcileOptions) (ReconcileResult, error) {
	results, err := c.ReconcileGrants(ctx, []state.GrantRecord{grant}, opts)
	if len(results) == 0 {
		return ReconcileResult{Email: grant.Email, Status: "error", Message: "reconcile returned no results"}, err
	}
	return results[0], err
}

// ReconcileGrants ensures canonical grants have Gmail filters. Primary
// visibility labels are reconciled as grouped exact-email OR filters; secondary
// classification labels remain one exact-sender filter per label.
func (c *Client) ReconcileGrants(ctx context.Context, grants []state.GrantRecord, opts ReconcileOptions) ([]ReconcileResult, error) {
	if len(grants) == 0 {
		return []ReconcileResult{}, nil
	}

	compiled := make([]compiledGrant, 0, len(grants))
	allLabels := []string{}
	for _, grant := range grants {
		spec := gmailfilter.CompileGrant(grant.Email, grant.VisibilityLabel, grant.ClassificationLabels)
		compiled = append(compiled, compiledGrant{
			Grant:           grant,
			Spec:            spec,
			PrimaryLabelKey: config.NormalizeLabel(grant.VisibilityLabel),
		})
		allLabels = append(allLabels, spec.AddLabels...)
	}

	labelIDByKey, err := c.resolveLabelIDMap(ctx, allLabels)
	results := make([]ReconcileResult, 0, len(compiled))
	for _, item := range compiled {
		results = append(results, ReconcileResult{
			Email:          item.Grant.Email,
			ExpectedFilter: item.Spec,
		})
	}
	if err != nil {
		for i := range results {
			results[i].Status = "error"
			results[i].Message = err.Error()
		}
		return results, err
	}
	filters, err := c.ListFilters(ctx)
	if err != nil {
		for i := range results {
			results[i].Status = "error"
			results[i].Message = err.Error()
		}
		return results, err
	}

	visibilityGroups := buildVisibilityGroups(compiled, labelIDByKey)
	for _, group := range visibilityGroups {
		groupResult, err := c.reconcileVisibilityGroup(ctx, filters, group, opts.Apply)
		for _, index := range group.Indexes {
			item := compiled[index]
			labelFilter := groupResult.LabelFilters[item.Spec.From]
			if labelFilter.Label == "" {
				labelFilter = LabelFilter{
					Label:   group.Label,
					Primary: true,
					Status:  "error",
					Message: "visibility group reconcile returned no sender result",
				}
			}
			if labelFilter.GmailFilterID != "" {
				results[index].GmailFilterID = labelFilter.GmailFilterID
				if strings.TrimSpace(item.Grant.GmailFilterID) != labelFilter.GmailFilterID {
					results[index].Changed = true
					if labelFilter.Status == "ok" {
						labelFilter.Status = "bind_existing"
						labelFilter.Message = "matching grouped Gmail visibility filter already exists and can be recorded as managed"
					}
				}
			}
			if labelFilter.Status == "created" {
				results[index].Changed = true
			}
			results[index].LabelFilters = append(results[index].LabelFilters, labelFilter)
		}
		if err != nil {
			for _, index := range group.Indexes {
				if results[index].Status == "" {
					results[index].Status = "error"
					results[index].Message = err.Error()
				}
			}
			return results, err
		}
	}

	for i, item := range compiled {
		createdLabels := []string{}
		createdLabelIDs := []string{}
		missingCount := 0
		createdCount := 0
		boundPrimary := false

		for _, labelFilter := range results[i].LabelFilters {
			switch labelFilter.Status {
			case "missing":
				missingCount++
			case "created":
				createdCount++
				if labelFilter.Primary {
					createdLabels = append(createdLabels, labelFilter.Label)
					createdLabelIDs = append(createdLabelIDs, labelIDByKey[config.NormalizeLabel(labelFilter.Label)])
				}
			case "bind_existing":
				if labelFilter.Primary {
					boundPrimary = true
				}
			}
		}

		for _, label := range item.Spec.AddLabels {
			if config.NormalizeLabel(label) == item.PrimaryLabelKey {
				continue
			}
			labelID := labelIDByKey[config.NormalizeLabel(label)]
			labelFilter := LabelFilter{Label: label}
			existing := findMatchingFilter(filters, item.Spec.From, []string{labelID})
			if existing != nil {
				labelFilter.GmailFilterID = strings.TrimSpace(existing.Id)
				labelFilter.Status = "ok"
				labelFilter.Message = "matching Gmail label filter exists"
				results[i].LabelFilters = append(results[i].LabelFilters, labelFilter)
				continue
			}
			if !opts.Apply {
				labelFilter.Status = "missing"
				labelFilter.Message = "managed Gmail label filter is missing"
				missingCount++
				results[i].LabelFilters = append(results[i].LabelFilters, labelFilter)
				continue
			}

			filterID, err := c.CreateManagedLabelFilter(ctx, item.Spec.From, labelID)
			if err != nil {
				labelFilter.Status = "error"
				labelFilter.Message = err.Error()
				results[i].LabelFilters = append(results[i].LabelFilters, labelFilter)
				results[i].Status = "error"
				results[i].Message = err.Error()
				return results, err
			}
			labelFilter.GmailFilterID = filterID
			labelFilter.Status = "created"
			labelFilter.Message = "created managed Gmail label filter"
			createdCount++
			createdLabels = append(createdLabels, label)
			createdLabelIDs = append(createdLabelIDs, labelID)
			results[i].Changed = true
			results[i].LabelFilters = append(results[i].LabelFilters, labelFilter)
		}

		backfillLabels := createdLabels
		backfillLabelIDs := createdLabelIDs
		if opts.Apply && opts.shouldBackfillHistorical(item.Spec.From) {
			backfillLabels = append([]string(nil), item.Spec.AddLabels...)
			backfillLabelIDs = labelIDsForSpec(item.Spec, labelIDByKey)
		}
		if opts.Apply && len(backfillLabelIDs) > 0 {
			backfill, err := c.BackfillLabelsForSender(ctx, item.Spec.From, backfillLabels, backfillLabelIDs)
			results[i].HistoricalBackfill = &backfill
			if err != nil {
				results[i].Status = "error"
				results[i].Message = err.Error()
				return results, err
			}
		}

		switch {
		case missingCount > 0:
			results[i].Status = "missing"
			results[i].Message = fmt.Sprintf("%d managed Gmail label filter(s) are missing", missingCount)
		case createdCount > 0:
			results[i].Status = "created"
			results[i].Message = fmt.Sprintf("created %d managed Gmail label filter(s)", createdCount)
		case boundPrimary:
			results[i].Status = "bind_existing"
			results[i].Message = "matching grouped Gmail visibility filter already exists and can be recorded as managed"
		default:
			results[i].Status = "ok"
			results[i].Message = "all managed Gmail label filters exist"
		}
	}
	return results, nil
}

// BackfillLabelsForSender applies labels to existing messages that match the
// managed exact-sender filter criteria. Gmail has no "apply filter
// retroactively" API, so this uses search plus batchModify.
func (c *Client) BackfillLabelsForSender(ctx context.Context, from string, labels, labelIDs []string) (HistoricalBackfill, error) {
	query := senderQuery(from)
	result := HistoricalBackfill{
		Query:            query,
		Labels:           append([]string(nil), labels...),
		IncludeSpamTrash: true,
	}
	labelIDs = compactStrings(labelIDs)
	if strings.TrimSpace(from) == "" {
		result.Status = "error"
		result.Message = "sender email is required"
		return result, fmt.Errorf("backfill historical messages: sender email is required")
	}
	if len(labelIDs) == 0 {
		result.Status = "skipped"
		result.Message = "no labels to backfill"
		return result, nil
	}

	pageToken := ""
	batch := make([]string, 0, batchModifyLimit)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		ids := append([]string(nil), batch...)
		reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		err := c.svc.Users.Messages.BatchModify("me", &gmailapi.BatchModifyMessagesRequest{
			Ids:         ids,
			AddLabelIds: labelIDs,
		}).Context(reqCtx).Do()
		cancel()
		if err != nil {
			return fmt.Errorf("batch label historical messages for %s: %w", from, err)
		}
		result.MessagesModified += int64(len(ids))
		result.Batches++
		batch = batch[:0]
		return nil
	}

	for {
		reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		call := c.svc.Users.Messages.List("me").
			Q(query).
			IncludeSpamTrash(true).
			MaxResults(backfillListPageSize).
			Fields("messages(id),nextPageToken")
		if pageToken != "" {
			call.PageToken(pageToken)
		}
		resp, err := call.Context(reqCtx).Do()
		cancel()
		if err != nil {
			result.Status = "error"
			result.Message = err.Error()
			return result, fmt.Errorf("list historical messages for %s: %w", from, err)
		}
		for _, msg := range resp.Messages {
			if msg == nil || strings.TrimSpace(msg.Id) == "" {
				continue
			}
			result.MessagesMatched++
			batch = append(batch, strings.TrimSpace(msg.Id))
			if len(batch) == batchModifyLimit {
				if err := flush(); err != nil {
					result.Status = "error"
					result.Message = err.Error()
					return result, err
				}
			}
		}
		if strings.TrimSpace(resp.NextPageToken) == "" {
			break
		}
		pageToken = strings.TrimSpace(resp.NextPageToken)
	}
	if err := flush(); err != nil {
		result.Status = "error"
		result.Message = err.Error()
		return result, err
	}
	result.Status = "ok"
	if result.MessagesMatched == 0 {
		result.Message = "no historical messages matched"
	} else {
		result.Message = fmt.Sprintf("backfilled %d historical message(s)", result.MessagesModified)
	}
	return result, nil
}

type compiledGrant struct {
	Grant           state.GrantRecord
	Spec            gmailfilter.Spec
	PrimaryLabelKey string
}

type visibilityGroup struct {
	Label   string
	LabelID string
	Indexes []int
	Emails  []string
}

type visibilityGroupReconcile struct {
	LabelFilters map[string]LabelFilter
}

type exactSenderFilter struct {
	ID        string
	Terms     []string
	Signature string
}

func buildVisibilityGroups(compiled []compiledGrant, labelIDByKey map[string]string) []visibilityGroup {
	groupsByKey := map[string]*visibilityGroup{}
	for i, item := range compiled {
		labelKey := item.PrimaryLabelKey
		group, ok := groupsByKey[labelKey]
		if !ok {
			group = &visibilityGroup{
				Label:   item.Grant.VisibilityLabel,
				LabelID: labelIDByKey[labelKey],
			}
			groupsByKey[labelKey] = group
		}
		group.Indexes = append(group.Indexes, i)
		group.Emails = append(group.Emails, item.Spec.From)
	}
	keys := make([]string, 0, len(groupsByKey))
	for key := range groupsByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]visibilityGroup, 0, len(keys))
	for _, key := range keys {
		group := groupsByKey[key]
		group.Emails = normalizedExactSenders(group.Emails)
		result = append(result, *group)
	}
	return result
}

func (c *Client) reconcileVisibilityGroup(ctx context.Context, filters []*gmailapi.Filter, group visibilityGroup, apply bool) (visibilityGroupReconcile, error) {
	result := visibilityGroupReconcile{LabelFilters: map[string]LabelFilter{}}
	existing := exactSenderVisibilityFilters(filters, group.LabelID)
	desiredSet := map[string]bool{}
	for _, filter := range existing {
		for _, term := range filter.Terms {
			desiredSet[term] = true
		}
	}
	for _, email := range group.Emails {
		desiredSet[email] = true
	}
	desiredSenders := make([]string, 0, len(desiredSet))
	for sender := range desiredSet {
		desiredSenders = append(desiredSenders, sender)
	}
	desiredSenders = normalizedExactSenders(desiredSenders)
	desiredShards := shardExactSenders(desiredSenders)

	existingBySignature := map[string]exactSenderFilter{}
	deleteIDs := map[string]bool{}
	for _, filter := range existing {
		if _, ok := existingBySignature[filter.Signature]; ok {
			deleteIDs[filter.ID] = true
			continue
		}
		existingBySignature[filter.Signature] = filter
	}

	filterIDBySignature := map[string]string{}
	createdSignatures := map[string]bool{}
	desiredSignatures := map[string]bool{}
	for _, shard := range desiredShards {
		signature := exactSenderSignature(shard)
		desiredSignatures[signature] = true
		if existing, ok := existingBySignature[signature]; ok {
			filterIDBySignature[signature] = existing.ID
			continue
		}
		if !apply {
			continue
		}
		filterID, err := c.CreateManagedVisibilityGroupFilter(ctx, shard, group.LabelID)
		if err != nil {
			for _, email := range group.Emails {
				result.LabelFilters[email] = LabelFilter{
					Label:   group.Label,
					Primary: true,
					Status:  "error",
					Message: err.Error(),
				}
			}
			return result, err
		}
		filterIDBySignature[signature] = filterID
		createdSignatures[signature] = true
	}

	for _, filter := range existing {
		if !desiredSignatures[filter.Signature] {
			deleteIDs[filter.ID] = true
		}
	}
	if apply {
		ids := make([]string, 0, len(deleteIDs))
		for id := range deleteIDs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if err := c.DeleteFilter(ctx, id); err != nil {
				for _, email := range group.Emails {
					result.LabelFilters[email] = LabelFilter{
						Label:   group.Label,
						Primary: true,
						Status:  "error",
						Message: err.Error(),
					}
				}
				return result, err
			}
		}
	}

	signatureByEmail := map[string]string{}
	for _, shard := range desiredShards {
		signature := exactSenderSignature(shard)
		for _, sender := range shard {
			signatureByEmail[sender] = signature
		}
	}
	for _, email := range group.Emails {
		signature := signatureByEmail[email]
		filterID := filterIDBySignature[signature]
		labelFilter := LabelFilter{
			Label:         group.Label,
			GmailFilterID: filterID,
			Primary:       true,
		}
		switch {
		case filterID == "":
			labelFilter.Status = "missing"
			labelFilter.Message = "grouped exact-sender Gmail visibility filter is missing"
		case createdSignatures[signature]:
			labelFilter.Status = "created"
			labelFilter.Message = "created grouped exact-sender Gmail visibility filter"
		default:
			labelFilter.Status = "ok"
			labelFilter.Message = "grouped exact-sender Gmail visibility filter exists"
		}
		result.LabelFilters[email] = labelFilter
	}
	return result, nil
}

func (opts ReconcileOptions) shouldBackfillHistorical(email string) bool {
	if !opts.BackfillHistorical {
		return false
	}
	if len(opts.BackfillHistoricalEmails) == 0 {
		return true
	}
	normalized, err := request.NormalizeEmail(email)
	if err != nil {
		return false
	}
	return opts.BackfillHistoricalEmails[normalized]
}

func labelIDsForSpec(spec gmailfilter.Spec, labelIDByKey map[string]string) []string {
	result := make([]string, 0, len(spec.AddLabels))
	for _, label := range spec.AddLabels {
		if labelID := strings.TrimSpace(labelIDByKey[config.NormalizeLabel(label)]); labelID != "" {
			result = append(result, labelID)
		}
	}
	return result
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

func (c *Client) resolveLabelIDMap(ctx context.Context, labels []string) (map[string]string, error) {
	nameToID, err := c.LabelNameToID(ctx)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, label := range labels {
		key := config.NormalizeLabel(label)
		if _, ok := result[key]; ok {
			continue
		}
		id, ok := nameToID[key]
		if !ok || strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("Gmail label %q was not found; create it before reconciling", label)
		}
		result[key] = strings.TrimSpace(id)
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

func findMatchingVisibilityFilter(filters []*gmailapi.Filter, from, labelID string) *gmailapi.Filter {
	for _, filter := range filters {
		if visibilityFilterMatchesExactSender(filter, from, labelID) {
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
	actual := normalizedSorted(filter.Action.AddLabelIds)
	expected := normalizedSorted(addLabelIDs)
	if len(actual) != 1 || len(expected) != 1 {
		return false
	}
	return actual[0] == expected[0]
}

func visibilityFilterMatchesExactSender(filter *gmailapi.Filter, from, labelID string) bool {
	terms, ok := exactSenderTermsFromFilter(filter, labelID)
	if !ok {
		return false
	}
	want, err := request.NormalizeEmail(from)
	if err != nil {
		return false
	}
	for _, term := range terms {
		if term == want {
			return true
		}
	}
	return false
}

func splitFilterFromTerms(value string) []string {
	fields := strings.Fields(strings.TrimSpace(value))
	result := []string{}
	current := []string{}
	flush := func() {
		if len(current) == 0 {
			return
		}
		if trimmed := strings.TrimSpace(strings.Join(current, " ")); trimmed != "" {
			result = append(result, trimmed)
		}
		current = current[:0]
	}
	for _, field := range fields {
		if strings.EqualFold(field, "OR") {
			flush()
			continue
		}
		current = append(current, field)
	}
	flush()
	return result
}

func exactSenderVisibilityFilters(filters []*gmailapi.Filter, labelID string) []exactSenderFilter {
	result := []exactSenderFilter{}
	for _, filter := range filters {
		id := ""
		if filter != nil {
			id = strings.TrimSpace(filter.Id)
		}
		if id == "" {
			continue
		}
		terms, ok := exactSenderTermsFromFilter(filter, labelID)
		if !ok {
			continue
		}
		result = append(result, exactSenderFilter{
			ID:        id,
			Terms:     terms,
			Signature: exactSenderSignature(terms),
		})
	}
	return result
}

func exactSenderTermsFromFilter(filter *gmailapi.Filter, labelID string) ([]string, bool) {
	if filter == nil || filter.Criteria == nil || filter.Action == nil {
		return nil, false
	}
	if strings.TrimSpace(filter.Criteria.Query) != "" ||
		strings.TrimSpace(filter.Criteria.NegatedQuery) != "" ||
		strings.TrimSpace(filter.Criteria.To) != "" ||
		strings.TrimSpace(filter.Criteria.Subject) != "" ||
		filter.Criteria.HasAttachment ||
		filter.Criteria.ExcludeChats ||
		filter.Criteria.Size != 0 ||
		strings.TrimSpace(filter.Criteria.SizeComparison) != "" {
		return nil, false
	}
	if strings.TrimSpace(filter.Action.Forward) != "" || len(filter.Action.RemoveLabelIds) > 0 {
		return nil, false
	}
	actual := normalizedSorted(filter.Action.AddLabelIds)
	if len(actual) != 1 || actual[0] != strings.TrimSpace(labelID) {
		return nil, false
	}
	terms, ok := parseExactSenderTerms(filter.Criteria.From)
	if !ok || len(terms) == 0 {
		return nil, false
	}
	return terms, true
}

func parseExactSenderTerms(value string) ([]string, bool) {
	terms := []string{}
	seen := map[string]bool{}
	for _, term := range splitFilterFromTerms(value) {
		email, err := request.NormalizeEmail(stripOuterParens(term))
		if err != nil {
			return nil, false
		}
		if seen[email] {
			continue
		}
		seen[email] = true
		terms = append(terms, email)
	}
	sort.Strings(terms)
	return terms, len(terms) > 0
}

func stripOuterParens(value string) string {
	value = strings.TrimSpace(value)
	for len(value) >= 2 && strings.HasPrefix(value, "(") && strings.HasSuffix(value, ")") && outerParensWrap(value) {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	return value
}

func outerParensWrap(value string) bool {
	depth := 0
	for i, r := range value {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
			if depth == 0 && i != len(value)-1 {
				return false
			}
		}
	}
	return depth == 0
}

func normalizedExactSenders(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		email, err := request.NormalizeEmail(value)
		if err != nil || seen[email] {
			continue
		}
		seen[email] = true
		result = append(result, email)
	}
	sort.Strings(result)
	return result
}

func shardExactSenders(values []string) [][]string {
	values = normalizedExactSenders(values)
	shards := [][]string{}
	current := []string{}
	currentLength := 0
	for _, value := range values {
		addedLength := len(value)
		if len(current) > 0 {
			addedLength += len(" OR ")
		}
		if len(current) > 0 && (len(current) >= maxExactSenderGroupTerms || currentLength+addedLength > maxExactSenderGroupLength) {
			shards = append(shards, current)
			current = []string{}
			currentLength = 0
			addedLength = len(value)
		}
		current = append(current, value)
		currentLength += addedLength
	}
	if len(current) > 0 {
		shards = append(shards, current)
	}
	return shards
}

func formatExactSenderGroup(values []string) string {
	return strings.Join(normalizedExactSenders(values), " OR ")
}

func exactSenderSignature(values []string) string {
	return strings.Join(normalizedExactSenders(values), "\n")
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

func compactStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func senderQuery(from string) string {
	return fmt.Sprintf("from:(%s)", strings.TrimSpace(from))
}
