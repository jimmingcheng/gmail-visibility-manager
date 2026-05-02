package rpc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jimmingcheng/gmail-visibility-manager/internal/request"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/state"
)

const Version1 = 1

const (
	MethodSystemPing = "system.ping"
	MethodSystemInfo = "system.info"

	MethodGrantSubmit = "grant.submit"
	MethodGrantLookup = "grant.lookup"
	MethodGrantList   = "grant.list"
)

type Request struct {
	V      int             `json:"v"`
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type Response struct {
	V      int        `json:"v"`
	ID     string     `json:"id"`
	OK     bool       `json:"ok"`
	Result any        `json:"result,omitempty"`
	Error  *ErrorBody `json:"error,omitempty"`
}

type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type SystemInfo struct {
	Service         string   `json:"service"`
	Instance        string   `json:"instance"`
	ProtocolVersion int      `json:"protocol_version"`
	Methods         []string `json:"methods"`
}

type GrantSubmitParams = request.VisibilityRequest

type GrantSubmitResult struct {
	Request state.RequestRecord `json:"request"`
}

type GrantLookupParams struct {
	Email string `json:"email"`
}

type GrantLookupResult struct {
	Email        string             `json:"email"`
	DonnaVisible bool               `json:"donna_visible"`
	Grant        *state.GrantRecord `json:"grant,omitempty"`
}

type GrantListParams struct{}

type GrantListResult struct {
	Grants []state.GrantRecord `json:"grants"`
}

func NewSuccess(id string, result any) Response {
	return Response{V: Version1, ID: id, OK: true, Result: result}
}

func NewError(id, code, message string, retryable bool) Response {
	return Response{
		V:  Version1,
		ID: id,
		Error: &ErrorBody{
			Code:      code,
			Message:   message,
			Retryable: retryable,
		},
	}
}

func ValidateRequest(req Request) error {
	if req.V != Version1 {
		return fmt.Errorf("unsupported version: %d", req.V)
	}
	if strings.TrimSpace(req.ID) == "" {
		return fmt.Errorf("missing id")
	}
	if len(req.ID) > 64 {
		return fmt.Errorf("id too long")
	}
	if strings.TrimSpace(req.Method) == "" {
		return fmt.Errorf("missing method")
	}
	if len(req.Params) == 0 {
		return fmt.Errorf("missing params")
	}
	if !json.Valid(req.Params) {
		return fmt.Errorf("params must be valid JSON")
	}
	return nil
}
