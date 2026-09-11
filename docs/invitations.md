# Native online-play invitations (`app.lp1.five.nintendo.net`)

Workstream C of [../../prds/native-switch-parallel-plan.md](../../prds/native-switch-parallel-plan.md)
(INV-01..04). This file is the invitation lifecycle contract for workstreams A
and B, the evidence ledger with provenance, and the operator notes.

Status: implemented for review. REST/core integration complete; native push
delivery (workstream B) and every console-hardware gate remain explicitly
pending. Nothing here claims a console parsed a byte we served.

## What was built

- `invitations.go` — the `.five.nintendo.net` REST surface and the durable
  invitation store (`$NX_DATA/invitations.json`), plus the seams: policy and
  session answers come from the account core over the adapter's existing gRPC
  clients (`Social.CheckInteraction`, `Sessions.ResolveSession`), and the
  semantic event is handed to workstream B through `invitationNotify`.
- `gameapi.go` — the legacy `/api/invitations` mailbox keeps its wire shape
  (Outbound, the emulator) but is now a view over the same durable store; it
  is no longer the in-memory map the 2026-09-11 audit called out as
  "not a native implementation".
- `main.go` — two wiring lines: the host case (`*.five.nintendo.net` →
  `s.five`) and `app.lp1.five.nintendo.net` on the fixed TLS certificate.

## Lifecycle contract (owned here; consumers: A, B)

1. **Identity.** Group and invitation ids are decimal strings minted from a
   persisted monotonic sequence (µs epoch base) and render as JSON numbers —
   the friends module parses them with `%llu`, so a string id cannot survive
   its parser. Ids are minted once and never re-minted on restart.
2. **Commit order.** A create commits the store write *before* the HTTP 200
   and *before* any semantic event. An event never promises a row the inbox
   does not have; a retry re-emits the same event identity.
3. **Semantic event.** `invitationNotify(InvitationEvent)` —
   `EventID = "invitation:<id>"` (stable, dedup-able), `type` reflecting the
   firmware-recognized `friend_invitation_received`, receiver/sender BAAS ids,
   invitation/group/application ids, and the receiver's unread count at commit.
   A failed or absent hook never fails the REST call: the console also polls
   the unread count on its own cooldown, so delivery converges without push.
   B maps the event into the Penne/NPNS envelope; the console's parser paths
   for that event are firmware-confirmed as `$.type` and
   `$.invitation.{id, sender_id, application_id, invitation_group_id}`.
4. **Read state.** Per-receiver, durable, idempotent, cross-device (one store
   behind every request). Set by `PATCH /v1/invitations` (JSON patch,
   `/extras/receiver/read` paths — firmware-confirmed patch path tail) or
   `PATCH /v1/users/<uid>/invitations/mark_as_read` (uid bound to the
   principal). Read rows are retained 7 days, then pruned.
5. **Expiry.** The wire shape carries no expiry, so expiry is server-side:
   default 24h (`NX_INVITATION_TTL_SECONDS`, capped at 24h to match the
   core's invitation TTL cap), legacy mailbox rows keep the 5-minute
   room-staleness TTL. Expired rows leave the inbox, the unread count, and
   the store (after retention).
6. **Policy.** Every send and the legacy pop consult
   `Social.CheckInteraction` (friendship, directional blocks, account status)
   in the core when the adapter runs on the OpenPak core; the legacy
   fallback uses the friend projection plus local block lists. Denied or
   unknown receivers are omitted from the group — nothing is committed for
   them — and an all-denied create answers the native error
   `sender_blocks_receiver`. A core outage answers 502, never a false
   success or a false policy denial.
7. **Sessions and joins.** The adapter does not mark joins. Delivery
   (inbox/alert) and a successful multiplayer join are separate gates. The
   one place the adapter refuses delivery on session truth is the legacy
   pop: a row that recorded the sender's title is dropped when neither the
   adapter's presence nor the core's session registry says that room is
   still live, so a dead room fails quietly instead of joining into
   nothing. Rows with no recorded title are judged by TTL only (no positive
   staleness, no drop).

## REST contract and provenance

Route family and versions are per endpoint (parent PRD INV-01), each item
labeled: **F** = firmware-confirmed (22.5.0 friends NSO build `8bd39f5b861b…`
string table), **S** = source-confirmed (kinnay/NintendoClients wiki,
Online-Play-Invitation-Server page, accessed 2026-09-12), **H** = hypothesis
(our bounded choice where neither source speaks; listed so review can attack
them).

| Route | Ver | Evidence | Notes |
| --- | --- | --- | --- |
| `POST /v2/invitation_groups` | v2 | F+S | 22.5.0 create; requires `invitation_type=friend` (hardcoded by the console; absent tolerated as `friend`, wrong value 400) |
| `POST /v1/invitation_groups` | v1 | S | pre-20.0.0 firmware; no `invitation_type` |
| `GET /v1/invitation_groups/<id>` | v1 | F+S | still v1 on 22.5.0; id is `%llu`; sender and receivers of the group may read, others get 404 `resource_is_not_found` (H) |
| `GET /v2/users/<uid>/invitations/inbox` | v2 | F+S | query `fields`, `read`, `invitation_types=friend` |
| `GET /v1/users/<uid>/invitations/inbox` | v1 | S | same handler, v1 skips the type filter |
| `PATCH /v1/invitations` | v1 | F+S | JSON patch; `/extras/receiver/read` path tail is firmware-confirmed, the id-in-path binding is H |
| `PATCH /v1/users/<uid>/invitations/mark_as_read` | v1 | F+S | all unread for the caller; body may narrow to ids (H) |

Field shapes served (fixtures in `testdata/invitation-*.json`, consumed by
the shape tests):

- **Group**: `id` (number), `sender_id`, `invitation_type`, `application_id`,
  `application_group_id`, `application_data` (base64, absent when empty),
  `messages` {lang: text}, `created_at`/`updated_at`, and
  `invitations: [{id (number), receiver_id}]`; plus `acd_index` and
  `application_id_match` echoed verbatim when the sender supplied them —
  both fields' semantics are unknown (S says so explicitly; the PRD forbids
  assigning speculative meaning).
- **Inbox item**: the fields the firmware reads — `id`,
  `invitation_group_id`, `sender_id`, `application_id`, `application_data`,
  `read`, `created_at`, `updated_at` (F) — plus `application_group_id`,
  `invitation_type`, `messages`, `acd_index`, `application_id_match` (S/H).
- **Errors**: `{"error":{"code":"0003","message":"resource_is_not_found"}}` —
  codes and statuses from the wiki's known set (0001/500, 0002/400,
  0003/404, 0006/401, 0010/404, 0011/400); `message` strings are the ones
  the 22.5.0 module demonstrably maps (`invalid_params`,
  `could_not_retrieve_receiver`, `receiver_must_be_different_from_sender`,
  `sender_blocks_receiver`, `not_acceptable_language`, `invalid_token`,
  `operation_is_not_permitted`, `internal_server_error`).

Hypotheses to retire with the first hardware capture: timestamp format
(unix seconds chosen, consistent with every other friends-module timestamp),
inbox `messages` presence, PATCH id binding, `mark_as_read` body, receiver
bound (100), unread ordering (newest first). The audit's rule applies: the
console says `2124-3121` and nothing else, so every one of these is a
fixture-test change away from a fix once a capture exists.

## Core contract request C-1 (filed, not implemented here)

The core's `Invitations.SendInvitation` requires a live session for the
target account + title and expires invitations whose session dies. That is
the right model for live, core-routed delivery, but the native inbox is
store-and-forward: Nintendo's documented error set has no
"receiver offline" case, and the acceptance matrix requires offline
recipients to receive their invitations. Until the core gains a
store-and-forward send (or an inbox-state RPC), native invitations live in
the adapter projection above and the core is consulted for policy/session
answers only. Requested semantics: `SendInvitation` with
`deliver_when_online` (or a sibling RPC) that stores without a live target
session, revalidates `CheckInteraction` at delivery, and emits the same
`invitation_sent` event; plus an invitation read-state RPC if read state
must synchronize with companion apps. Integration test for the core side:
extend `account/internal/integration_test/social_sessions_test.go` with
offline-recipient delivery after session registration.

## Bounds, retention, operations

- Payload ≤ 1024 B decoded (the console's own
  `FriendInvitationApplicationParameterSizeMax`; the core's 4096 cap is
  looser), receivers ≤ 100/group (H), messages ≤ 16 languages × 256 B,
  inbox page ≤ 100, legacy queue ≤ 8 per receiver (unchanged), unread rows
  pruned at expiry + 7 days (read ones at read + 7 days).
- Store: `$NX_DATA/invitations.json`, temp-file + rename writes, same
  discipline as `baas.json`. **Migration:** none needed — new file. **Rollback:** delete the file or run the previous build; the legacy
  mailbox keeps working from the same file, and the REST surface simply
  disappears with the old binary (no shared-schema change).
- Observability: each create/read/pop logs one line (actor, counts, group
  id); denials and stale-room drops log with ids. No bearer tokens, no
  payload bytes are ever logged (the payload is opaque and stays that way).
- Configuration: `NX_INVITATION_TTL_SECONDS` (optional, ≤ 86400).

## Tests

- `invitations_test.go` — auth binding (expired/wrong issuer/wrong type/
  anonymous grant/cross-account), create shape + numeric ids + durability,
  version skew, validation and the native error strings, core policy denial
  (fake core) including the outage 502, inbox shape fixtures + filters,
  read state across restart (fresh store instance on the same file),
  group-detail authorization, expiry, legacy durability/stale rooms/
  queue bound, event hook firing after commit with stable identity,
  legacy block enforcement.
- `integration_invitations_test.go` (build tag `integration`) — the real
  core: two accounts registered through the core's own gRPC, friended,
  invitation created through the real `CheckInteraction`, blocked through
  the real `Social.Block` and refused with nothing committed, join-time
  session truth through the real session registry, unread count. Run:

  ```
  podman start openpak-pg-test   # postgres://…@127.0.0.1:54329
  go test -tags integration -count=1 -run TestCore .
  ```

- `go vet ./...` and `go test -race ./...` must pass; the shape tests reuse
  the repository's `compareShape` discipline (an extra or missing key is a
  test failure before it is a console error).

## Requirement status (review ledger)

| Requirement | Status | Evidence |
| --- | --- | --- |
| INV-01 REST contracts, per-endpoint versions, principal binding | Implemented; console-parse pending hardware | unit tests, fixtures, F/S provenance table above |
| INV-02 data fidelity, bounded payloads, validated base64, durable read state | Implemented | shape tests, restart tests, bounds above; `acd_index`/`application_id_match` echoed without semantics |
| INV-03 core integration, expiry, duplicates, offline recipients, blocks, stale sessions | Implemented (adapter projection + core policy/session); core store-and-forward filed as C-1 | fake-core and real-core integration tests |
| INV-04 join outcome recording, clean failures, delivery ≠ join | Implemented for the adapter's share (staleness refusal, TTL, provenance recorded); title-level join is hardware-pending | legacy stale-room tests; ledger note |
| J4 send → native alert/inbox → read → explicit join | REST/inbox/read demonstrable; native alert (B) and on-console join **pending hardware** | — |

Native push delivery (B), console parsing, and a successful title join are
separate pending gates; this package does not claim them.
