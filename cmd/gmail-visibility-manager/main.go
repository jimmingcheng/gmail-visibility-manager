package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/audit"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/config"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/gmailfilter"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/policy"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/request"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/state"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("gmail-visibility-manager", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("GMAIL_VISIBILITY_MANAGER_CONFIG"), "Path to trusted config JSON")
	jsonOut := fs.Bool("json", false, "Print JSON output")
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		usage(os.Stderr)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Global flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 2
	}

	switch rest[0] {
	case "config":
		return runConfig(rest[1:])
	case "validate":
		return runValidate(*configPath, *jsonOut, rest[1:])
	case "submit":
		return runSubmit(*configPath, *jsonOut, rest[1:])
	case "list":
		return runList(*configPath, *jsonOut, rest[1:])
	case "show":
		return runShow(*configPath, *jsonOut, rest[1:])
	case "approve":
		return runApprove(*configPath, *jsonOut, rest[1:])
	case "deny":
		return runDeny(*configPath, *jsonOut, rest[1:])
	case "grants":
		return runGrants(*configPath, *jsonOut, rest[1:])
	default:
		fs.Usage()
		return 2
	}
}

func runConfig(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("config init", flag.ContinueOnError)
		path := fs.String("path", defaultConfigPath(), "Path to write sample config JSON")
		fs.SetOutput(os.Stderr)
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if fs.NArg() != 0 {
			fs.Usage()
			return 2
		}
		if err := config.WriteSample(*path); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "created config: %s\n", expandPath(*path))
		return 0
	default:
		usage(os.Stderr)
		return 2
	}
}

func runValidate(configPath string, jsonOut bool, args []string) int {
	if len(args) != 1 {
		usage(os.Stderr)
		return 2
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_, eval, err := loadAndEvaluate(cfg, args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	out := map[string]any{
		"request":           eval.Request,
		"policy_verdict":    eval.Verdict,
		"approval_required": eval.ApprovalRequired,
		"reasons":           eval.Reasons,
	}
	if jsonOut {
		return printJSON(out)
	}
	fmt.Fprintf(os.Stdout, "valid request: %s %s\n", eval.Request.Action, eval.Request.Email)
	fmt.Fprintf(os.Stdout, "policy: %s\n", eval.Verdict)
	for _, reason := range eval.Reasons {
		fmt.Fprintf(os.Stdout, "- %s\n", reason)
	}
	if eval.Verdict == policy.VerdictBlocked {
		return 1
	}
	return 0
}

func runSubmit(configPath string, jsonOut bool, args []string) int {
	if len(args) != 1 {
		usage(os.Stderr)
		return 2
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_, eval, err := loadAndEvaluate(cfg, args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	store, err := state.Open(cfg.StatePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	record, err := store.Submit(ctx, eval)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = audit.Logger{Path: cfg.AuditLogPath}.Append(audit.Record{
		Event:       "request_submitted",
		RequestID:   record.RequestID,
		RequestHash: record.RequestHash,
		Actor:       record.RequestedBy,
		Status:      record.Status,
		Details: map[string]any{
			"policy_verdict":    record.PolicyVerdict,
			"approval_required": record.ApprovalRequired,
			"email":             record.Email,
			"labels":            record.ClassificationLabels,
			"reasons":           record.PolicyReasons,
		},
	})

	if jsonOut {
		return printJSON(record)
	}
	fmt.Fprintf(os.Stdout, "request_id: %s\n", record.RequestID)
	fmt.Fprintf(os.Stdout, "status: %s\n", record.Status)
	fmt.Fprintf(os.Stdout, "policy: %s\n", record.PolicyVerdict)
	for _, reason := range record.PolicyReasons {
		fmt.Fprintf(os.Stdout, "- %s\n", reason)
	}
	if record.Status == state.StatusBlocked {
		return 1
	}
	return 0
}

func runList(configPath string, jsonOut bool, args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	pending := fs.Bool("pending", false, "List pending requests")
	recent := fs.Bool("recent", false, "List recent requests")
	limit := fs.Int("limit", 20, "Maximum recent requests")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if !*pending && !*recent {
		*pending = true
	}
	_, store, ok := openConfiguredStore(configPath)
	if !ok {
		return 1
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var records []state.RequestRecord
	var err error
	if *recent {
		records, err = store.ListRecent(ctx, *limit)
	} else {
		records, err = store.ListPending(ctx)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if jsonOut {
		return printJSON(map[string]any{"requests": records})
	}
	for _, record := range records {
		fmt.Fprintf(os.Stdout, "%s\t%s\t%s\t%s\t%s\n", record.RequestID, record.Status, record.Action, record.Email, strings.Join(record.ClassificationLabels, ","))
	}
	return 0
}

func runShow(configPath string, jsonOut bool, args []string) int {
	if len(args) != 1 {
		usage(os.Stderr)
		return 2
	}
	_, store, ok := openConfiguredStore(configPath)
	if !ok {
		return 1
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	record, err := store.GetRequest(ctx, args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if jsonOut {
		return printJSON(record)
	}
	printRequest(record)
	return 0
}

func runApprove(configPath string, jsonOut bool, args []string) int {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	by := fs.String("by", defaultActor(), "Approver identity")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	cfg, store, ok := openConfiguredStore(configPath)
	if !ok {
		return 1
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, grant, err := store.Approve(ctx, fs.Arg(0), *by, cfg.VisibilityLabel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = audit.Logger{Path: cfg.AuditLogPath}.Append(audit.Record{
		Event:       "request_approved_applied",
		RequestID:   req.RequestID,
		RequestHash: req.RequestHash,
		Actor:       *by,
		Status:      req.Status,
		Details: map[string]any{
			"email":             grant.Email,
			"visibility_label":  grant.VisibilityLabel,
			"classification":    grant.ClassificationLabels,
			"compiled_filter":   gmailfilter.CompileGrant(grant.Email, grant.VisibilityLabel, grant.ClassificationLabels),
			"gmail_filter_id":   grant.GmailFilterID,
			"canonical_applied": true,
		},
	})
	if jsonOut {
		return printJSON(map[string]any{"request": req, "grant": grant, "compiled_filter": gmailfilter.CompileGrant(grant.Email, grant.VisibilityLabel, grant.ClassificationLabels)})
	}
	fmt.Fprintf(os.Stdout, "applied request: %s\n", req.RequestID)
	fmt.Fprintf(os.Stdout, "grant: %s -> %s\n", grant.Email, strings.Join(gmailfilter.CompileGrant(grant.Email, grant.VisibilityLabel, grant.ClassificationLabels).AddLabels, ", "))
	return 0
}

func runDeny(configPath string, jsonOut bool, args []string) int {
	fs := flag.NewFlagSet("deny", flag.ContinueOnError)
	by := fs.String("by", defaultActor(), "Denying actor identity")
	reason := fs.String("reason", "", "Denial reason")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	cfg, store, ok := openConfiguredStore(configPath)
	if !ok {
		return 1
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := store.Deny(ctx, fs.Arg(0), *by, *reason)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = audit.Logger{Path: cfg.AuditLogPath}.Append(audit.Record{
		Event:       "request_denied",
		RequestID:   req.RequestID,
		RequestHash: req.RequestHash,
		Actor:       *by,
		Status:      req.Status,
		Details: map[string]any{
			"reason": *reason,
			"email":  req.Email,
		},
	})
	if jsonOut {
		return printJSON(req)
	}
	fmt.Fprintf(os.Stdout, "denied request: %s\n", req.RequestID)
	return 0
}

func runGrants(configPath string, jsonOut bool, args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	cfg, store, ok := openConfiguredStore(configPath)
	if !ok {
		return 1
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	switch args[0] {
	case "list":
		if len(args) != 1 {
			usage(os.Stderr)
			return 2
		}
		grants, err := store.ListGrants(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if jsonOut {
			return printJSON(map[string]any{"grants": grants})
		}
		for _, grant := range grants {
			fmt.Fprintf(os.Stdout, "%s\t%s\t%s\n", grant.Email, grant.VisibilityLabel, strings.Join(grant.ClassificationLabels, ","))
		}
		return 0
	case "lookup":
		if len(args) != 2 {
			usage(os.Stderr)
			return 2
		}
		grant, err := store.LookupGrant(ctx, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		filter := gmailfilter.CompileGrant(grant.Email, cfg.VisibilityLabel, grant.ClassificationLabels)
		if jsonOut {
			return printJSON(map[string]any{"grant": grant, "compiled_filter": filter})
		}
		fmt.Fprintf(os.Stdout, "email: %s\n", grant.Email)
		fmt.Fprintf(os.Stdout, "labels: %s\n", strings.Join(filter.AddLabels, ", "))
		fmt.Fprintf(os.Stdout, "approved_by: %s\n", grant.ApprovedBy)
		fmt.Fprintf(os.Stdout, "approved_at: %s\n", grant.ApprovedAt)
		return 0
	default:
		usage(os.Stderr)
		return 2
	}
}

func loadAndEvaluate(cfg config.Config, path string) (request.VisibilityRequest, policy.Evaluation, error) {
	data, err := readInput(path)
	if err != nil {
		return request.VisibilityRequest{}, policy.Evaluation{}, err
	}
	req, err := request.ParseStrict(data)
	if err != nil {
		return request.VisibilityRequest{}, policy.Evaluation{}, err
	}
	eval := policy.Evaluate(cfg, req)
	return req, eval, nil
}

func openConfiguredStore(configPath string) (config.Config, *state.Store, bool) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return config.Config{}, nil, false
	}
	store, err := state.Open(cfg.StatePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return config.Config{}, nil, false
	}
	return cfg, store, true
}

func readInput(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return data, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

func printRequest(record state.RequestRecord) {
	fmt.Fprintf(os.Stdout, "request_id: %s\n", record.RequestID)
	fmt.Fprintf(os.Stdout, "status: %s\n", record.Status)
	fmt.Fprintf(os.Stdout, "action: %s\n", record.Action)
	fmt.Fprintf(os.Stdout, "email: %s\n", record.Email)
	fmt.Fprintf(os.Stdout, "classification_labels: %s\n", strings.Join(record.ClassificationLabels, ", "))
	fmt.Fprintf(os.Stdout, "policy: %s\n", record.PolicyVerdict)
	for _, reason := range record.PolicyReasons {
		fmt.Fprintf(os.Stdout, "- %s\n", reason)
	}
	if record.DecidedBy != "" {
		fmt.Fprintf(os.Stdout, "decided_by: %s\n", record.DecidedBy)
		fmt.Fprintf(os.Stdout, "decided_at: %s\n", record.DecidedAt)
	}
}

func printJSON(value any) int {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintln(os.Stdout, string(data))
	return 0
}

func defaultActor() string {
	if user := strings.TrimSpace(os.Getenv("USER")); user != "" {
		return user
	}
	return "local-user"
}

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(".", "gmail-visibility-manager.json")
	}
	return filepath.Join(home, ".config", "gmail-visibility-manager", "config.json")
}

func expandPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] validate request.json")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] submit request.json")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] list [--pending|--recent]")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] show REQUEST_ID")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] approve [--by NAME] REQUEST_ID")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] deny [--by NAME] [--reason TEXT] REQUEST_ID")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] grants list")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] grants lookup EMAIL")
	fmt.Fprintln(w, "  gmail-visibility-manager config init [--path PATH]")
}
