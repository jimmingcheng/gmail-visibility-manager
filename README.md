# gmail-visibility-manager

`gmail-visibility-manager` is the trusted side of a narrow Donna/OpenClaw Gmail visibility workflow.

Donna is treated as an untrusted proposer. In v1 she can only request:

```text
make future mail from one exact email address Donna-visible,
and optionally add allowlisted classification labels
```

The trusted manager stores a canonical grant, audits the decision, and reconciles that grant into one managed Gmail filter:

```text
from:person@example.com -> add labels: Donna, Kids/Activities
```

It is intentionally not a general Gmail filter editor.

## Security Model

This project is useful as a boundary only if the trusted owner and the untrusted agent run as different Unix users.

Trusted owner user:

- owns Gmail OAuth credentials
- owns config, state, audit log, and service files
- runs `gmail-visibility-manager run`
- approves or denies requests

Untrusted agent user:

- connects to the daemon over a Unix socket
- can submit exact-address visibility requests
- can look up active Donna-visible grants
- cannot read Gmail OAuth tokens or mutate Gmail filters directly

Do not treat this as a hard boundary if Donna's user can read or write the trusted owner's files, run as the trusted owner, or use sudo.

The daemon verifies the peer Unix UID before accepting socket requests. Filesystem permissions on the socket directory are still required defense-in-depth.

## What Donna Can Ask For

Donna-facing requests are strict JSON. Unknown fields are rejected.

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

Rules:

- `email` must be one bare mailbox address
- no domains
- no Gmail query language
- no address lists
- no forwarding
- no archive, delete, mark-read, or remove-label action
- classification labels must be allowlisted in trusted config
- creating Donna visibility requires approval

Supported actions:

- `create_visibility_grant`
- `update_grant_labels`

## Existing Gmail Filters

Existing Gmail filters are not edited by default.

This manager owns only grants in its canonical SQLite state. Gmail filters are generated enforcement artifacts. If an existing exact-sender filter already matches the expected managed shape, `gmail reconcile --apply` can bind that filter ID to the grant. Complex or changed filters are reported as drift and left untouched.

Recommended coexistence model:

```text
Human-owned filters: existing mailbox organization
Managed filters: exact sender -> add Donna + classification labels
Canonical DB: source of truth for Donna visibility grants
```

## Build

```sh
go build ./cmd/gmail-visibility-manager
```

Install the binary somewhere owned by the trusted owner or root, for example:

```sh
install -m 0755 gmail-visibility-manager /usr/local/bin/gmail-visibility-manager
```

## Config

Create a starter config:

```sh
gmail-visibility-manager config init --path ~/.config/gmail-visibility-manager/config.json
```

Example production config:

```json
{
  "instance": "default",
  "account_email": "you@example.com",
  "client_uid": 1001,
  "socket_path": "/var/tmp/gmail-visibility-manager/default.sock",
  "socket_mode": "0660",
  "state_path": "~/.local/state/gmail-visibility-manager/state.db",
  "audit_log_path": "~/.local/state/gmail-visibility-manager/audit.jsonl",
  "oauth_client_path": "~/.config/gmail-visibility-manager/oauth-client.json",
  "auth_store": {
    "backend": "system",
    "service": "gmail-visibility-manager"
  },
  "visibility_label": "Donna",
  "allowed_classification_labels": [
    "Kids/Activities",
    "Kids/School",
    "House/Renovation"
  ],
  "discord": {
    "token_env": "GMAIL_VISIBILITY_MANAGER_DISCORD_TOKEN",
    "channel_id": "123456789012345678",
    "allowed_user_ids": ["234567890123456789"],
    "command_prefix": "!gvm"
  }
}
```

Important config fields:

- `client_uid`: Unix UID of the untrusted Donna/OpenClaw user.
- `visibility_label`: Gmail label that `safe-gmail` uses to expose mail to Donna.
- `allowed_classification_labels`: labels Donna may request in addition to the visibility label.
- `oauth_client_path`: Google OAuth desktop-client JSON, owned by the trusted user.
- `discord.allowed_user_ids`: Discord users allowed to approve or deny requests.

Validate:

```sh
gmail-visibility-manager --config ~/.config/gmail-visibility-manager/config.json config validate
```

## Gmail OAuth

Save your Google OAuth client JSON at the configured `oauth_client_path`.

Authorize once as the trusted owner:

```sh
gmail-visibility-manager --config ~/.config/gmail-visibility-manager/config.json auth login
```

If you previously authorized with narrower scopes:

```sh
gmail-visibility-manager --config ~/.config/gmail-visibility-manager/config.json auth login --force-consent
```

Scopes used:

- Gmail readonly, to verify the account and list labels
- Gmail labels, to resolve label names to IDs
- Gmail settings basic, to create/list Gmail filters

Check the authorized Gmail account:

```sh
gmail-visibility-manager --config ~/.config/gmail-visibility-manager/config.json gmail profile
```

## Local Trusted Flow

Validate a request:

```sh
gmail-visibility-manager --config ./config.local.json validate testdata/create-grant.sample.json
```

Submit locally:

```sh
gmail-visibility-manager --config ./config.local.json submit testdata/create-grant.sample.json
```

Approve locally:

```sh
gmail-visibility-manager --config ./config.local.json approve --by jimming sample-coach-grant
```

If Gmail OAuth is configured, approval also attempts to reconcile the grant into Gmail. If Gmail is not configured, approval updates only the canonical trusted DB.

List grants:

```sh
gmail-visibility-manager --config ./config.local.json grants list
```

Reconcile all active grants:

```sh
gmail-visibility-manager --config ./config.local.json gmail reconcile
gmail-visibility-manager --config ./config.local.json gmail reconcile --apply
```

Without `--apply`, reconciliation is a dry run. With `--apply`, missing managed filters are created and matching existing filters may be recorded as managed.

## Daemon Mode

Run the trusted daemon as the trusted owner user:

```sh
gmail-visibility-manager --config ~/.config/gmail-visibility-manager/config.json run
```

The daemon:

- listens on the configured Unix socket
- checks the peer UID against `client_uid`
- accepts only typed grant RPC methods
- optionally notifies Discord for pending approvals

Donna's user can submit over the socket:

```sh
export GMAIL_VISIBILITY_MANAGER_SOCKET=/var/tmp/gmail-visibility-manager/default.sock

gmail-visibility-manager client ping
gmail-visibility-manager client submit request.json
gmail-visibility-manager client lookup coach@example.com
gmail-visibility-manager client grants list
```

## Socket Permissions

Recommended Linux setup:

```sh
sudo groupadd --system gmail-visibility-manager || true
sudo usermod -aG gmail-visibility-manager mailowner
sudo usermod -aG gmail-visibility-manager agentuser
sudo install -d -o mailowner -g gmail-visibility-manager -m 2750 /var/tmp/gmail-visibility-manager
```

Set:

```json
{
  "client_uid": 1001,
  "socket_path": "/var/tmp/gmail-visibility-manager/default.sock",
  "socket_mode": "0660"
}
```

The socket permissions let the agent connect; the daemon still verifies the peer UID.

## Discord Approval

Discord is an approval adapter, not the trust boundary.

Set a bot token in the configured environment variable:

```sh
export GMAIL_VISIBILITY_MANAGER_DISCORD_TOKEN='...'
```

The bot listens in `discord.channel_id` and accepts commands only from `discord.allowed_user_ids`.

Commands:

```text
!gvm pending
!gvm show <request-id>
!gvm approve <request-id>
!gvm deny <request-id> [reason]
```

Approving through Discord calls the same trusted manager path as local CLI approval. If Gmail OAuth is configured, approval attempts to create or bind the managed Gmail filter.

Your Discord bot must be allowed to read message content for text commands.

## Service Manifests

Print a `systemd --user` unit:

```sh
gmail-visibility-manager --config ~/.config/gmail-visibility-manager/config.json \
  service print-systemd --binary /usr/local/bin/gmail-visibility-manager \
  > ~/.config/systemd/user/gmail-visibility-manager@default.service
```

Enable:

```sh
systemctl --user daemon-reload
systemctl --user enable --now gmail-visibility-manager@default.service
```

Print a macOS launchd plist:

```sh
gmail-visibility-manager --config ~/Library/Application\ Support/gmail-visibility-manager/config.json \
  service print-launchd --binary /usr/local/bin/gmail-visibility-manager \
  > ~/Library/LaunchAgents/com.gmail-visibility-manager.default.plist
```

Load:

```sh
launchctl load ~/Library/LaunchAgents/com.gmail-visibility-manager.default.plist
```

## Audit And State

Trusted state is SQLite at `state_path`.

Audit records are append-only JSONL at `audit_log_path`. Audit includes request submission, approval/denial, and Gmail reconciliation events.

Keep both paths owned by the trusted owner and unreadable/unwritable by Donna's Unix user.

## Relationship To safe-gmail

`safe-gmail` exposes a filtered Gmail read/draft surface to Donna. `gmail-visibility-manager` controls which exact senders become visible by adding the configured visibility label through managed Gmail filters.

The two tools should use the same Donna visibility label. Donna should not receive raw Gmail filter access from either tool.
