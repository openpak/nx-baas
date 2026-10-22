# C — Native online-play invitations

Status: ready for agent assignment. Date: 2026-09-11.

## Objective and owned scope

Implement native invitation creation, inbox, read state and supported title joins.
Own INV-01–04 and J4, including invitation-specific privacy/recovery cases in J5/J6.
Deliver REST/core integration independently while B recovers persistent delivery.

## Shared requirements and evidence

Read the [coordination plan](native-switch-parallel-plan.md) before editing. The
[parent PRD](native-switch-social-eshop-prd.md) remains normative for shared scope,
architecture, provenance, security, performance targets, acceptance and review artifacts
(sections 1–3, 6, 8–10). This workstream owns only the requirements listed below;
it does not need to implement the other workstreams to submit its own review package.

Target Horizon 22.5.0; record the actual Atmosphère setup. Use the
[firmware findings](../../docs/switch/firmware-22.5.0-social-eshop-findings.md),
[backend audit](../../docs/switch/native-social-eshop-audit-2026-09-11.md), and public
references linked in the parent. The firmware findings supersede the audit's unknown
friend-list shape. Firmware and Ghidra work remain in the private paths recorded there.
Recheck current source and account contracts before treating historical gaps as current.

Use Go 1.26/project licensing, independent implementation and versioned core APIs;
no direct core database access, copied third-party implementation, secrets or firmware in
commits. Missing core capabilities become concrete contract requests, not adapter-owned
canonical substitutes. Deliver code for review with deployment/rollback instructions;
active deployment and console changes follow the owner's existing authorization.

## Ownership and integration boundaries

Own new invitation handlers, projections/persistence, title-payload adapters, fixtures
and tests. Existing `gameapi.go` is shared legacy code: provide A a narrow replacement/
wiring patch instead of competing edits. A owns shared authentication/router/core client
and core-event polling; B owns Penne encoding and delivery.

Define invitation identity, durable read/expiry state and title payload contracts with
A/B. Commit or reconcile invitation state before emitting an idempotent semantic event.
Use core moderation/session checks through A's shared interfaces. Return lifecycle
outcomes needed for delivery; never build a separate notification socket or friend graph.
Title-server changes stay with their owner through a concrete contract request.

## Functional requirements

### INV: native online-play invitations

- **INV-01 — REST contracts.** Implement the documented `app.lp1.five.nintendo.net`
  route family: v2 invitation-group creation and user inbox for 22.5.0, plus documented
  group-detail and read/mark-as-read operations. Select versions per endpoint, not a
  blanket rewrite of every route to v2. Authenticate BAAS access and bind the principal
  to authorized inbox/group actions.
- **INV-02 — Data fidelity.** Preserve stable invitation/group IDs, sender/receiver IDs,
  application/group IDs, title payload, localized messages, read state and timestamps
  according to the verified contract. Bound receiver counts/payloads and validate
  base64. Research fields such as `acd_index` and `application_id_match`; do not assign
  speculative semantics. Read state must survive restart and synchronize across devices.
- **INV-03 — Core integration.** Use shared invitation/session/moderation contracts;
  define expiry, duplicate sends, offline recipients, blocked users and stale sessions.
  The existing in-memory emulator mailbox is not a native implementation. Notification
  delivery and inbox state must agree even if one operation is retried.
- **INV-04 — Join outcome.** For each supported title, record the source and meaning of
  its opaque payload, compatible version and user-initiated accept/join behavior.
  Expired/unavailable sessions must fail cleanly. Native inbox delivery and successful
  multiplayer joining are separate gates; do not mark either from evidence of the other.

## Milestones and acceptance

1. Verify endpoint-specific v1/v2 contracts against public research/current firmware;
   map existing core APIs and document missing read, expiry or payload semantics.
2. Implement creation/group detail/inbox/read operations, durable IDs, policy and error
   behavior; use the real core in integration tests.
3. Connect semantic events to B; verify inbox/read state across devices and restarts.
4. Validate native recipient alert/inbox and explicit title join separately. Record
   Stardew Valley and Outbound capabilities/dependencies rather than assuming parity.

Acceptance: correct 22.5.0 endpoint versions, localized messages and bounded payloads,
read/read-all, retries, restart, cross-account denial, blocks, offline recipients,
expiry, incompatible title and vanished sessions. Prove send → native alert/inbox →
read → explicit supported join. REST completion can be reviewed before B, but native
push and successful game join remain separate pending gates until demonstrated.

## Review handoff

Return branch/base/commit references, requirement-to-code/test/evidence ledger, contract
changes, migrations/rollback, operator notes and exact reproduction commands. Run
`go vet ./...`, `go test -race ./...` and required affected-repository CI. Retain sanitized
hardware results with firmware/build IDs and timings. Mark missing hardware or dependent
integration as pending; mocks, HTTP success and locally passing tests cannot close native
acceptance gates. Include known blockers and the next reproducible experiment.

## Copyable assignment

> Implement `prds/native-switch-invitations-prd.md`. Read the linked coordination plan and shared
> parent requirements first. Use your own branch/worktree, agree shared interfaces at
> kickoff, and deliver only your owned feature changes plus narrow integration patches
> for A. Return the review handoff with explicit native acceptance and dependency status.
