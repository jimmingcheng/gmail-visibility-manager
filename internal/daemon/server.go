package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/config"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/manager"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/request"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/rpc"
)

const requestMaxBytes = 1 << 20

// Notifier receives request events from daemon intake.
type Notifier interface {
	NotifyPending(context.Context, string) error
}

// Server is the trusted Unix socket intake daemon.
type Server struct {
	cfg      config.Config
	manager  *manager.Manager
	notifier Notifier
}

// New constructs a daemon server.
func New(cfg config.Config, mgr *manager.Manager, notifier Notifier) (*Server, error) {
	if err := cfg.ValidateDaemon(); err != nil {
		return nil, err
	}
	if mgr == nil {
		return nil, fmt.Errorf("manager is required")
	}
	return &Server{cfg: cfg, manager: mgr, notifier: notifier}, nil
}

// Run starts the socket server until ctx is canceled.
func (s *Server) Run(ctx context.Context) error {
	parentDir := filepath.Dir(s.cfg.SocketPath)
	if err := os.MkdirAll(parentDir, 0o750); err != nil {
		return fmt.Errorf("ensure socket dir: %w", err)
	}
	if err := os.Remove(s.cfg.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	listener, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(s.cfg.SocketPath)

	mode, err := s.cfg.SocketFileMode()
	if err != nil {
		return err
	}
	if err := os.Chmod(s.cfg.SocketPath, mode); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return fmt.Errorf("accept connection: %w", err)
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = writeResponse(conn, rpc.NewError("", "internal_error", "expected unix connection", false))
		return
	}
	uid, err := peerUID(unixConn)
	if err != nil {
		_ = writeResponse(conn, rpc.NewError("", "internal_error", "failed to read peer credentials", false))
		return
	}
	if uid != s.cfg.ClientUID {
		_ = writeResponse(conn, rpc.NewError("", "unauthorized_peer", "peer uid is not allowed", false))
		return
	}

	payload, err := rpc.ReadFrame(conn, requestMaxBytes)
	if err != nil {
		_ = writeResponse(conn, rpc.NewError("", "invalid_request", err.Error(), false))
		return
	}
	var req rpc.Request
	if err := json.Unmarshal(payload, &req); err != nil {
		_ = writeResponse(conn, rpc.NewError("", "invalid_request", "request must be valid JSON", false))
		return
	}
	if err := rpc.ValidateRequest(req); err != nil {
		_ = writeResponse(conn, rpc.NewError(req.ID, "invalid_request", err.Error(), false))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_ = writeResponse(conn, s.dispatch(req))
}

func (s *Server) dispatch(req rpc.Request) rpc.Response {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch req.Method {
	case rpc.MethodSystemPing:
		return rpc.NewSuccess(req.ID, map[string]any{"pong": true})
	case rpc.MethodSystemInfo:
		return rpc.NewSuccess(req.ID, rpc.SystemInfo{
			Service:         "gmail-visibility-manager",
			Instance:        s.cfg.Instance,
			ProtocolVersion: rpc.Version1,
			Methods: []string{
				rpc.MethodSystemPing,
				rpc.MethodSystemInfo,
				rpc.MethodGrantSubmit,
				rpc.MethodGrantLookup,
				rpc.MethodGrantList,
			},
		})
	case rpc.MethodGrantSubmit:
		parsed, err := request.ParseStrict(req.Params)
		if err != nil {
			return rpc.NewError(req.ID, "invalid_params", err.Error(), false)
		}
		record, err := s.manager.Submit(ctx, parsed)
		if err != nil {
			return rpc.NewError(req.ID, "internal_error", err.Error(), false)
		}
		if record.Status == "pending" && s.notifier != nil {
			_ = s.notifier.NotifyPending(ctx, record.RequestID)
		}
		return rpc.NewSuccess(req.ID, rpc.GrantSubmitResult{Request: record})
	case rpc.MethodGrantLookup:
		var params rpc.GrantLookupParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return rpc.NewError(req.ID, "invalid_params", "invalid grant.lookup params", false)
		}
		email, err := request.NormalizeEmail(params.Email)
		if err != nil {
			return rpc.NewError(req.ID, "invalid_params", err.Error(), false)
		}
		grant, err := s.manager.Store().LookupGrant(ctx, email)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return rpc.NewSuccess(req.ID, rpc.GrantLookupResult{Email: email, DonnaVisible: false})
			}
			return rpc.NewError(req.ID, "internal_error", err.Error(), false)
		}
		return rpc.NewSuccess(req.ID, rpc.GrantLookupResult{Email: email, DonnaVisible: true, Grant: &grant})
	case rpc.MethodGrantList:
		grants, err := s.manager.Store().ListGrants(ctx)
		if err != nil {
			return rpc.NewError(req.ID, "internal_error", err.Error(), false)
		}
		return rpc.NewSuccess(req.ID, rpc.GrantListResult{Grants: grants})
	default:
		return rpc.NewError(req.ID, "method_not_allowed", "method is not exposed by this daemon", false)
	}
}

func writeResponse(conn net.Conn, resp rpc.Response) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return rpc.WriteFrame(conn, payload)
}
