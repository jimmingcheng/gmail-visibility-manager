# gmail-visibility-manager

`gmail-visibility-manager` is the trusted side of a narrow Donna/OpenClaw Gmail visibility workflow.

Donna is treated as an untrusted proposer. In v1 she can only request a simple grant:

```text
make future mail from one exact email address Donna-visible,
and optionally add allowlisted classification labels
```

The trusted manager stores the canonical grant, audits the decision, and compiles the grant into the only Gmail filter shape this system should eventually create:

```text
from:person@example.com -> add labels: Donna, Kids/Activities
```

The current implementation is the local trusted CLI and state/policy core. Gmail API mutation and Discord approval are intentionally separated behind the architecture and come next.

## Current Status

Implemented:

- strict JSON request decoding with unknown fields rejected
- exact-address-only visibility grant requests
- config-driven allowlist for classification labels
- deterministic policy verdicts
- SQLite trusted state
- append-only JSONL audit log
- local approve/deny/apply flow for the canonical grant model
- compiled Gmail filter preview for each active grant

Not yet implemented:

- Gmail OAuth/filter API reconciliation
- Unix socket intake from the untrusted agent
- Discord approval adapter

## Build

```sh
go build ./cmd/gmail-visibility-manager
```

## Configure

Create a starter config:

```sh
go run ./cmd/gmail-visibility-manager config init --path ./config.local.json
```

Edit `allowed_classification_labels` to the labels Donna may request in addition to the Donna visibility label.

Example:

```json
{
  "state_path": "~/.local/state/gmail-visibility-manager/state.db",
  "audit_log_path": "~/.local/state/gmail-visibility-manager/audit.jsonl",
  "visibility_label": "Donna",
  "allowed_classification_labels": [
    "Kids/Activities",
    "Kids/School",
    "House/Renovation"
  ]
}
```

## Request Format

Donna can submit only this shape:

```json
{
  "schema_version": "1.0",
  "request_id": "optional-stable-id",
  "requested_by": "donna",
  "action": "create_visibility_grant",
  "email": "coach@example.com",
  "classification_labels": ["Kids/Activities"],
  "rationale": "New soccer coach contact."
}
```

Supported actions:

- `create_visibility_grant`
- `update_grant_labels`

The `email` field must be one bare mailbox address. Domains, Gmail queries, display names, and address lists are rejected.

## Local Flow

Validate:

```sh
go run ./cmd/gmail-visibility-manager --config ./config.local.json validate testdata/create-grant.sample.json
```

Submit:

```sh
go run ./cmd/gmail-visibility-manager --config ./config.local.json submit testdata/create-grant.sample.json
```

List pending requests:

```sh
go run ./cmd/gmail-visibility-manager --config ./config.local.json list --pending
```

Approve:

```sh
go run ./cmd/gmail-visibility-manager --config ./config.local.json approve --by jimming sample-coach-grant
```

List grants:

```sh
go run ./cmd/gmail-visibility-manager --config ./config.local.json grants list
```

Look up the compiled filter shape:

```sh
go run ./cmd/gmail-visibility-manager --config ./config.local.json grants lookup coach@example.com
```

## Security Boundary

The trusted state, config, audit log, Gmail OAuth token, and future daemon process must be owned by the trusted account owner, not by Donna's Unix user.

Donna should never receive:

- Gmail OAuth credentials
- arbitrary Gmail filter access
- the ability to approve her own requests
- write access to config, state, audit, or rollback files

Existing Gmail filters are not edited by default. This manager owns only grants in its canonical state and will later reconcile those grants into managed exact-sender Gmail filters.
