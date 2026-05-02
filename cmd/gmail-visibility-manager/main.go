package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/auth"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/config"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/daemon"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/discordbot"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/gmail"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/gmailfilter"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/manager"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/policy"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/request"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/rpc"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/service"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/state"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("gmail-visibility-manager", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("GMAIL_VISIBILITY_MANAGER_CONFIG"), "Path to trusted config JSON")
	socketPath := fs.String("socket", os.Getenv("GMAIL_VISIBILITY_MANAGER_SOCKET"), "Path to daemon Unix socket for client commands")
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
	case "run":
		return runDaemon(*configPath, rest[1:])
	case "config":
		return runConfig(*configPath, rest[1:])
	case "auth":
		return runAuth(*configPath, rest[1:])
	case "gmail":
		return runGmail(*configPath, *jsonOut, rest[1:])
	case "service":
		return runService(*configPath, rest[1:])
	case "client":
		return runClient(*socketPath, *jsonOut, rest[1:])
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

func runDaemon(configPath string, args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := cfg.ValidateDaemon(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	mgr, err := manager.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer mgr.Close()

	bot, err := discordbot.New(cfg.Discord, mgr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if bot != nil {
		if err := bot.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer bot.Close()
		fmt.Fprintf(os.Stderr, "discord approval adapter enabled for channel %s\n", cfg.Discord.ChannelID)
	}

	srv, err := daemon.New(cfg, mgr, bot)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "gmail-visibility-manager listening on %s for client uid %d\n", cfg.SocketPath, cfg.ClientUID)
	if err := srv.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runConfig(configPath string, args []string) int {
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
		fmt.Fprintf(os.Stdout, "created config: %s\n", config.ExpandPath(*path))
		return 0
	case "validate":
		cfg, err := config.Load(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if cfg.GmailConfigured() {
			if _, err := auth.LoadOAuthClient(cfg.OAuthClientPath); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
		}
		fmt.Fprintf(os.Stdout, "config valid: instance=%s state=%s socket=%s\n", cfg.Instance, cfg.StatePath, cfg.SocketPath)
		return 0
	default:
		usage(os.Stderr)
		return 2
	}
}

func runAuth(configPath string, args []string) int {
	if len(args) == 0 || args[0] != "login" {
		usage(os.Stderr)
		return 2
	}
	fs := flag.NewFlagSet("auth login", flag.ContinueOnError)
	redirectURI := fs.String("redirect-uri", "", "Override OAuth redirect URI")
	authURL := fs.String("auth-url", "", "Paste final redirect URL non-interactively")
	forceConsent := fs.Bool("force-consent", false, "Force consent to obtain a fresh refresh token")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := cfg.ValidateGmail(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	client, err := auth.LoadOAuthClient(cfg.OAuthClientPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	store, err := auth.OpenTokenStore(cfg.AuthStore)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	flow, err := auth.NewManualFlow(client, *redirectURI, gmail.OAuthScopes(), *forceConsent)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	finalURL := strings.TrimSpace(*authURL)
	if finalURL == "" {
		fmt.Fprintln(os.Stderr, "Visit this URL to authorize Gmail filter management:")
		fmt.Fprintln(os.Stderr, flow.AuthURL())
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "After Google redirects you back, copy the full redirect URL from the browser and paste it here.")
		fmt.Fprint(os.Stderr, "Redirect URL: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		finalURL = strings.TrimSpace(line)
	}
	if finalURL == "" {
		fmt.Fprintln(os.Stderr, "missing redirect URL")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tok, err := flow.ExchangeRedirect(ctx, finalURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	email, err := gmail.ProfileEmailFromToken(ctx, tok)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(cfg.AccountEmail)) {
		fmt.Fprintf(os.Stderr, "authorized as %s, expected %s\n", email, cfg.AccountEmail)
		return 1
	}
	if err := store.Save(cfg.Instance, cfg.AccountEmail, tok); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "stored Gmail token for %s\n", email)
	return 0
}

func runGmail(configPath string, jsonOut bool, args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "profile":
		cfg, err := config.Load(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		client, err := gmail.New(ctx, cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		email, err := client.ProfileEmail(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if jsonOut {
			return printJSON(map[string]string{"email": email})
		}
		fmt.Fprintln(os.Stdout, email)
		return 0
	case "reconcile":
		fs := flag.NewFlagSet("gmail reconcile", flag.ContinueOnError)
		apply := fs.Bool("apply", false, "Create missing managed Gmail filters and record matching filter IDs")
		fs.SetOutput(os.Stderr)
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if fs.NArg() != 0 {
			fs.Usage()
			return 2
		}
		cfg, mgr, ok := openManager(configPath)
		_ = cfg
		if !ok {
			return 1
		}
		defer mgr.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		results, err := mgr.ReconcileAll(ctx, *apply)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			if jsonOut {
				_ = printJSON(map[string]any{"results": results, "error": err.Error()})
			}
			return 1
		}
		if jsonOut {
			return printJSON(map[string]any{"results": results})
		}
		for _, result := range results {
			fmt.Fprintf(os.Stdout, "%s\t%s\t%s\t%s\n", result.Email, result.Status, result.GmailFilterID, result.Message)
		}
		return 0
	default:
		usage(os.Stderr)
		return 2
	}
}

func runService(configPath string, args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	binaryPath := fs.String("binary", "", "Path to gmail-visibility-manager binary")
	fs.SetOutput(os.Stderr)
	target := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if strings.TrimSpace(configPath) == "" {
		fmt.Fprintln(os.Stderr, "missing --config")
		return 2
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resolvedBinary := strings.TrimSpace(*binaryPath)
	if resolvedBinary == "" {
		resolvedBinary, err = os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	spec, err := service.BuildSpec(cfg, configPath, resolvedBinary)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	switch target {
	case "print-systemd":
		unit, err := service.SystemdUnit(spec)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "suggested filename: %s\n", service.SystemdUnitName(cfg.Instance))
		_, _ = fmt.Fprint(os.Stdout, unit)
		return 0
	case "print-launchd":
		plist, err := service.LaunchdPlist(spec)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "suggested filename: %s\n", service.LaunchdFileName(cfg.Instance))
		_, _ = fmt.Fprint(os.Stdout, plist)
		return 0
	default:
		usage(os.Stderr)
		return 2
	}
}

func runClient(socketPath string, jsonOut bool, args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	if strings.TrimSpace(socketPath) == "" {
		fmt.Fprintln(os.Stderr, "missing --socket or GMAIL_VISIBILITY_MANAGER_SOCKET")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch args[0] {
	case "ping":
		return callAndPrint(ctx, socketPath, jsonOut, rpc.MethodSystemPing, map[string]any{})
	case "info":
		return callAndPrint(ctx, socketPath, jsonOut, rpc.MethodSystemInfo, map[string]any{})
	case "submit":
		if len(args) != 2 {
			usage(os.Stderr)
			return 2
		}
		data, err := readInput(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		req, err := request.ParseStrict(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return callAndPrint(ctx, socketPath, jsonOut, rpc.MethodGrantSubmit, req)
	case "lookup":
		if len(args) != 2 {
			usage(os.Stderr)
			return 2
		}
		return callAndPrint(ctx, socketPath, jsonOut, rpc.MethodGrantLookup, rpc.GrantLookupParams{Email: args[1]})
	case "grants":
		if len(args) != 2 || args[1] != "list" {
			usage(os.Stderr)
			return 2
		}
		return callAndPrint(ctx, socketPath, jsonOut, rpc.MethodGrantList, rpc.GrantListParams{})
	default:
		usage(os.Stderr)
		return 2
	}
}

func callAndPrint(ctx context.Context, socketPath string, jsonOut bool, method string, params any) int {
	payload, err := json.Marshal(params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp, err := rpc.Call(ctx, socketPath, rpc.Request{
		V:      rpc.Version1,
		ID:     fmt.Sprintf("cli-%d", time.Now().UnixNano()),
		Method: method,
		Params: payload,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if jsonOut {
		return printJSON(resp)
	}
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "%s: %s\n", resp.Error.Code, resp.Error.Message)
		return 1
	}
	switch method {
	case rpc.MethodSystemPing:
		fmt.Fprintln(os.Stdout, "pong")
	case rpc.MethodSystemInfo, rpc.MethodGrantSubmit, rpc.MethodGrantLookup, rpc.MethodGrantList:
		return printJSON(resp.Result)
	}
	return 0
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
	data, err := readInput(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req, err := request.ParseStrict(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	mgr, err := manager.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer mgr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	record, err := mgr.Submit(ctx, req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
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
	_, mgr, ok := openManager(configPath)
	if !ok {
		return 1
	}
	defer mgr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, grant, reconcile, err := mgr.Approve(ctx, fs.Arg(0), *by)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	filter := gmailfilter.CompileGrant(grant.Email, grant.VisibilityLabel, grant.ClassificationLabels)
	if jsonOut {
		return printJSON(map[string]any{"request": req, "grant": grant, "compiled_filter": filter, "gmail_reconcile": reconcile})
	}
	fmt.Fprintf(os.Stdout, "applied request: %s\n", req.RequestID)
	fmt.Fprintf(os.Stdout, "grant: %s -> %s\n", grant.Email, strings.Join(filter.AddLabels, ", "))
	if reconcile != nil {
		fmt.Fprintf(os.Stdout, "gmail: %s %s\n", reconcile.Status, reconcile.GmailFilterID)
	}
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
	_, mgr, ok := openManager(configPath)
	if !ok {
		return 1
	}
	defer mgr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := mgr.Deny(ctx, fs.Arg(0), *by, *reason)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
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
			fmt.Fprintf(os.Stdout, "%s\t%s\t%s\t%s\n", grant.Email, grant.VisibilityLabel, strings.Join(grant.ClassificationLabels, ","), grant.GmailFilterID)
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
		if grant.GmailFilterID != "" {
			fmt.Fprintf(os.Stdout, "gmail_filter_id: %s\n", grant.GmailFilterID)
		}
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

func openManager(configPath string) (config.Config, *manager.Manager, bool) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return config.Config{}, nil, false
	}
	mgr, err := manager.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return config.Config{}, nil, false
	}
	return cfg, mgr, true
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

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] run")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] config init|validate")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] auth login")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] gmail profile")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] gmail reconcile [--apply]")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] service print-systemd|print-launchd [--binary PATH]")
	fmt.Fprintln(w, "  gmail-visibility-manager [--socket PATH] client ping|info|submit|lookup|grants list")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] validate request.json")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] submit request.json")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] list [--pending|--recent]")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] show REQUEST_ID")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] approve [--by NAME] REQUEST_ID")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] deny [--by NAME] [--reason TEXT] REQUEST_ID")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] grants list")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] grants lookup EMAIL")
}
