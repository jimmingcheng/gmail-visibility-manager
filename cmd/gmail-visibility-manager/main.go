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
		if strings.TrimSpace(cfg.Discord.ChannelID) == "" {
			fmt.Fprintln(os.Stderr, "discord approval adapter enabled for direct messages")
		} else {
			fmt.Fprintf(os.Stderr, "discord approval adapter enabled for channel %s\n", cfg.Discord.ChannelID)
		}
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
		apply := fs.Bool("apply", false, "Create missing managed Gmail filters and record matching visibility filter IDs")
		backfillHistorical := fs.Bool("backfill-historical", false, "Batch-apply managed labels to historical messages for active grants")
		fs.SetOutput(os.Stderr)
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if fs.NArg() != 0 {
			fs.Usage()
			return 2
		}
		if *backfillHistorical && !*apply {
			fmt.Fprintln(os.Stderr, "--backfill-historical requires --apply")
			return 2
		}
		cfg, mgr, ok := openManager(configPath)
		_ = cfg
		if !ok {
			return 1
		}
		defer mgr.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		results, err := mgr.ReconcileAll(ctx, *apply, *backfillHistorical)
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
		clientUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "help":
		if len(args) != 1 {
			clientUsage(os.Stderr)
			return 2
		}
		return printClientHelp(socketPath, jsonOut)
	case "schema":
		if len(args) != 1 {
			clientUsage(os.Stderr)
			return 2
		}
		return printClientSchema(socketPath, jsonOut)
	case "sample-request":
		return runClientSampleRequest(args[1:])
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
			clientUsage(os.Stderr)
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
			clientUsage(os.Stderr)
			return 2
		}
		return callAndPrint(ctx, socketPath, jsonOut, rpc.MethodGrantLookup, rpc.GrantLookupParams{Email: args[1]})
	case "grants":
		if len(args) != 2 || args[1] != "list" {
			clientUsage(os.Stderr)
			return 2
		}
		return callAndPrint(ctx, socketPath, jsonOut, rpc.MethodGrantList, rpc.GrantListParams{})
	default:
		clientUsage(os.Stderr)
		return 2
	}
}

func printClientHelp(socketPath string, jsonOut bool) int {
	if jsonOut {
		guidance := staticClientGuidance()
		if info, err := fetchSystemInfo(socketPath); err == nil {
			guidance = info.Client
		}
		return printJSON(guidance)
	}
	info, err := fetchSystemInfo(socketPath)
	if err == nil {
		printClientGuidance(os.Stdout, info.Client)
		return 0
	}
	printClientGuidance(os.Stdout, staticClientGuidance())
	if strings.TrimSpace(socketPath) == "" {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "Tip: set GMAIL_VISIBILITY_MANAGER_SOCKET or pass --socket, then run `gmail-visibility-manager client info` for live allowed labels.")
	} else {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintf(os.Stdout, "Tip: live daemon guidance was unavailable: %v\n", err)
	}
	return 0
}

func printClientSchema(socketPath string, jsonOut bool) int {
	guidance := staticClientGuidance()
	if info, err := fetchSystemInfo(socketPath); err == nil {
		guidance = info.Client
	}
	if jsonOut {
		return printJSON(guidance.Request)
	}
	fmt.Fprintln(os.Stdout, "Strict request JSON object:")
	fmt.Fprintf(os.Stdout, "- schema_version: %s\n", guidance.Request.SchemaVersion)
	fmt.Fprintf(os.Stdout, "- actions: %s\n", strings.Join(guidance.Request.Actions, ", "))
	fmt.Fprintf(os.Stdout, "- required fields: %s\n", strings.Join(guidance.Request.RequiredFields, ", "))
	fmt.Fprintf(os.Stdout, "- optional fields: %s\n", strings.Join(guidance.Request.OptionalFields, ", "))
	if len(guidance.AllowedClassificationLabels) > 0 {
		fmt.Fprintf(os.Stdout, "- allowed classification_labels: %s\n", strings.Join(guidance.AllowedClassificationLabels, ", "))
	}
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Example:")
	return printJSON(guidance.Request.Example)
}

func runClientSampleRequest(args []string) int {
	fs := flag.NewFlagSet("client sample-request", flag.ContinueOnError)
	email := fs.String("email", "sender@example.com", "Exact sender email address to request")
	requestID := fs.String("request-id", "", "Stable unique request id")
	requestedBy := fs.String("requested-by", "donna", "Requester identity")
	action := fs.String("action", request.ActionCreateVisibilityGrant, "Request action")
	rationale := fs.String("rationale", "Future messages from this exact sender should be visible to Donna for the named workflow.", "Human-readable reason for trusted approval")
	var labels stringListFlag
	fs.Var(&labels, "label", "Allowed classification label; repeat for multiple labels")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if len(labels) == 0 {
		labels = append(labels, "Kids/Activities")
	}
	id := strings.TrimSpace(*requestID)
	if id == "" {
		id = defaultRequestID(*email)
	}
	req := request.VisibilityRequest{
		SchemaVersion:        request.SchemaVersion1,
		RequestID:            id,
		RequestedBy:          strings.TrimSpace(*requestedBy),
		Action:               strings.TrimSpace(*action),
		Email:                strings.TrimSpace(*email),
		ClassificationLabels: []string(labels),
		Rationale:            strings.TrimSpace(*rationale),
	}
	return printJSON(req)
}

func fetchSystemInfo(socketPath string) (rpc.SystemInfo, error) {
	if strings.TrimSpace(socketPath) == "" {
		return rpc.SystemInfo{}, fmt.Errorf("missing socket")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := rpc.Call(ctx, socketPath, rpc.Request{
		V:      rpc.Version1,
		ID:     fmt.Sprintf("cli-info-%d", time.Now().UnixNano()),
		Method: rpc.MethodSystemInfo,
		Params: json.RawMessage(`{}`),
	})
	if err != nil {
		return rpc.SystemInfo{}, err
	}
	if !resp.OK {
		return rpc.SystemInfo{}, fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
	}
	data, err := json.Marshal(resp.Result)
	if err != nil {
		return rpc.SystemInfo{}, err
	}
	var info rpc.SystemInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return rpc.SystemInfo{}, err
	}
	return info, nil
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
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

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("label must not be empty")
	}
	*f = append(*f, value)
	return nil
}

func defaultRequestID(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		email = "sender@example.com"
	}
	base := strings.Builder{}
	lastDash := false
	for _, r := range email {
		switch {
		case r >= 'a' && r <= 'z':
			base.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			base.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				base.WriteByte('-')
				lastDash = true
			}
		}
	}
	slug := strings.Trim(base.String(), "-")
	if slug == "" {
		slug = "sender"
	}
	if len(slug) > 64 {
		slug = strings.Trim(slug[:64], "-")
	}
	return fmt.Sprintf("%s-%s", slug, time.Now().Format("20060102"))
}

func staticClientGuidance() rpc.ClientGuidance {
	return rpc.ClientGuidance{
		Purpose:         "Request trusted approval for future Gmail messages from one exact sender to become Donna-visible through safe-gmail.",
		SocketEnv:       "GMAIL_VISIBILITY_MANAGER_SOCKET",
		VisibilityLabel: "Donna",
		AllowedClassificationLabels: []string{
			"Kids/Activities",
			"Kids/School",
			"House/Renovation",
		},
		Request: rpc.VisibilityRequestGuidance{
			SchemaVersion: request.SchemaVersion1,
			Actions: []string{
				request.ActionCreateVisibilityGrant,
				request.ActionUpdateGrantLabels,
			},
			RequiredFields: []string{
				"schema_version",
				"requested_by",
				"action",
				"email",
			},
			OptionalFields: []string{
				"request_id",
				"created_at",
				"classification_labels",
				"rationale",
			},
			Example: request.VisibilityRequest{
				SchemaVersion: request.SchemaVersion1,
				RequestID:     "sender-visibility-grant-2026",
				RequestedBy:   "donna",
				Action:        request.ActionCreateVisibilityGrant,
				Email:         "sender@example.com",
				ClassificationLabels: []string{
					"Kids/Activities",
				},
				Rationale: "Future messages from this exact sender should be visible to Donna for the named workflow.",
			},
		},
		Commands: []rpc.CommandGuidance{
			{
				Command:     "gmail-visibility-manager client help",
				Purpose:     "Print this agent-oriented workflow guide.",
				MachineSafe: true,
			},
			{
				Command:     "gmail-visibility-manager client info",
				Purpose:     "Print live daemon capabilities, allowed labels, and request schema guidance.",
				MachineSafe: true,
			},
			{
				Command:     "gmail-visibility-manager client lookup EMAIL",
				Purpose:     "Check whether one exact sender already has an active Donna visibility grant.",
				MachineSafe: true,
			},
			{
				Command:     "gmail-visibility-manager client grants list",
				Purpose:     "List active Donna-visible sender grants.",
				MachineSafe: true,
			},
			{
				Command:     "gmail-visibility-manager client sample-request --email EMAIL --label LABEL --rationale TEXT > request.json",
				Purpose:     "Generate strict request JSON to inspect or submit.",
				MachineSafe: true,
			},
			{
				Command:     "gmail-visibility-manager client submit request.json",
				Purpose:     "Submit a visibility request for trusted human approval.",
				WhenToUse:   "Only after checking lookup/grants and writing a narrow request for one exact sender.",
				MachineSafe: false,
			},
		},
		Notes: []string{
			"Do not use this tool for reading Gmail. Use safe-gmail for visible mail after approval.",
			"Do not request Gmail query language, domains, wildcards, or multiple senders.",
			"Do not include the visibility label in classification_labels; the trusted manager adds it.",
			"Approval is human-gated. Submitting a request does not immediately change Gmail.",
			"Unknown JSON fields are rejected.",
		},
	}
}

func printClientGuidance(w io.Writer, guidance rpc.ClientGuidance) {
	fmt.Fprintln(w, "Gmail Visibility Manager client help")
	fmt.Fprintln(w)
	fmt.Fprintln(w, guidance.Purpose)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use this tool only to request future Donna visibility for one exact Gmail sender.")
	fmt.Fprintln(w, "Use safe-gmail to read mail after a request is approved.")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Socket env: %s\n", guidance.SocketEnv)
	fmt.Fprintf(w, "Visibility label added by trusted manager: %s\n", guidance.VisibilityLabel)
	if len(guidance.AllowedClassificationLabels) > 0 {
		fmt.Fprintf(w, "Allowed classification labels: %s\n", strings.Join(guidance.AllowedClassificationLabels, ", "))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Workflow for agents:")
	fmt.Fprintln(w, "1. Run `gmail-visibility-manager client info` for live policy/schema guidance.")
	fmt.Fprintln(w, "2. Run `gmail-visibility-manager client lookup sender@example.com` to avoid duplicate requests.")
	fmt.Fprintln(w, "3. Generate JSON with `gmail-visibility-manager client sample-request --email sender@example.com --label 'Kids/Activities' --rationale '...' > request.json`.")
	fmt.Fprintln(w, "4. Inspect the JSON. It must request one exact sender only.")
	fmt.Fprintln(w, "5. Submit with `gmail-visibility-manager client submit request.json`.")
	fmt.Fprintln(w, "6. Wait for trusted human approval. Approval normally happens through Discord DM.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Request JSON fields:")
	fmt.Fprintf(w, "- schema_version: %s\n", guidance.Request.SchemaVersion)
	fmt.Fprintf(w, "- actions: %s\n", strings.Join(guidance.Request.Actions, ", "))
	fmt.Fprintf(w, "- required: %s\n", strings.Join(guidance.Request.RequiredFields, ", "))
	fmt.Fprintf(w, "- optional: %s\n", strings.Join(guidance.Request.OptionalFields, ", "))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, command := range guidance.Commands {
		safety := "mutating"
		if command.MachineSafe {
			safety = "read-only/safe"
		}
		fmt.Fprintf(w, "- %s\n  %s (%s)\n", command.Command, command.Purpose, safety)
		if command.WhenToUse != "" {
			fmt.Fprintf(w, "  Use when: %s\n", command.WhenToUse)
		}
	}
	if len(guidance.Notes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Rules:")
		for _, note := range guidance.Notes {
			fmt.Fprintf(w, "- %s\n", note)
		}
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] run")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] config init|validate")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] auth login")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] gmail profile")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] gmail reconcile [--apply] [--backfill-historical]")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] service print-systemd|print-launchd [--binary PATH]")
	fmt.Fprintln(w, "  gmail-visibility-manager [--socket PATH] client help|info|schema|sample-request|ping|submit|lookup|grants list")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] validate request.json")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] submit request.json")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] list [--pending|--recent]")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] show REQUEST_ID")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] approve [--by NAME] REQUEST_ID")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] deny [--by NAME] [--reason TEXT] REQUEST_ID")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] grants list")
	fmt.Fprintln(w, "  gmail-visibility-manager [--config PATH] grants lookup EMAIL")
}

func clientUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  gmail-visibility-manager [--socket PATH] client help")
	fmt.Fprintln(w, "  gmail-visibility-manager [--socket PATH] client info")
	fmt.Fprintln(w, "  gmail-visibility-manager [--socket PATH] client schema")
	fmt.Fprintln(w, "  gmail-visibility-manager client sample-request [--email EMAIL] [--label LABEL] [--request-id ID] [--rationale TEXT]")
	fmt.Fprintln(w, "  gmail-visibility-manager [--socket PATH] client lookup EMAIL")
	fmt.Fprintln(w, "  gmail-visibility-manager [--socket PATH] client grants list")
	fmt.Fprintln(w, "  gmail-visibility-manager [--socket PATH] client submit request.json")
}
