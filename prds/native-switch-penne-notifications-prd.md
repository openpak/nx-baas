# B — Penne transport and native notifications

Status: ready for agent assignment. Date: 2026-09-11.

## Objective and owned scope

Implement the native persistent notification channel, authenticated registration,
subscriptions, routing, alert eligibility and reconnect recovery. Own NTF-01–06 and
the notification/recovery portions of J1, J4 and J5. This is the highest protocol-risk
workstream; make bounded research progress while the other agents build REST/state.

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
no direct core database access, copied earlier implementation, secrets or firmware in
commits. Missing core capabilities become concrete contract requests, not adapter-owned
canonical substitutes. Deliver code for review with deployment/rollback instructions;
active deployment and console changes follow the owner's existing authorization.

## Ownership and integration boundaries

Own the Penne implementation, binary protocol package, registration/subscription and
delivery storage, protocol fixtures and transport tests. Existing `penne.go` also has
Beach placeholders: own its Penne portions only; coordinate any file extraction with D
and A. Do not independently edit A's common router, recorder, authentication or event
poller. Supply a focused debug-stream wrapper fix and full-router regression test to A.

Publish a semantic delivery interface with persistence/idempotency outcomes and a
subscription/policy contract. A supplies social/presence changes and policy; C supplies
invitation changes. B owns conversion to verified native envelopes, wire delivery,
acknowledgements, retry and recipient revalidation at dispatch. No second core poller.

## Functional requirements

### NTF: Penne transport and social notifications

- **NTF-01 — Durable setup.** Implement authenticated registration, account/device links,
  notification tokens, login tickets, expiry/revocation and frontline discovery. Persist
  associations currently lost by push-channel echo handlers. Isolate accounts, devices
  and application subscriptions; a supplied ID must not authorize its own registration.
- **NTF-02 — Protocol specification gate.** Recover and document the minimum supported
  connection lifecycle, message directions, schemas, framing, subscriptions, sync,
  acknowledgements and resumption before claiming native delivery. Firmware confirms
  protocol header value 4, a SubscribeTopic discriminator of `0x17`, and outbound
  four-byte little-endian length followed by a binary buffer with FlatBuffers-compatible
  structure. Server-to-client framing and complete schema remain unverified. Do not
  infer HTTP/2 server push from library strings or substitute arbitrary newline/JSON
  messages. Implement only evidence-backed parameter defaults and control messages.
- **NTF-03 — Streaming integrity.** Preserve required response-writer capabilities through
  debug middleware and test the full `ServeHTTP` path with debug on/off. Verify the
  deployed TLS/proxy path, cancellation, buffering, idle timeouts and resource cleanup.
- **NTF-04 — Event delivery.** Support firmware-recognized `presence_updated`,
  `friend_invitation_received`, `friend_request_received`,
  `friend_request_authorized` and `friend_deleted`. Recover each payload and its outer
  envelope. Map core acceptance/removal into the native workflows with verified IDs
  and recipients. Timestamp invalidation alone is not delivery.
- **NTF-05 — Recovery.** Persist core-event cursors and required delivery state. Define
  atomicity between committed changes and enqueueing, retry/backoff, deduplication,
  bounded queues, retention and expired-event behavior. Implement protocol-supported
  acknowledgement/replay or reconciliation; do not assume exactly-once transport.
  Offline presence should converge to current state rather than replay stale toasts.
- **NTF-06 — Alert behavior.** Verify eligible request, acceptance, invitation and online
  alerts on the native UI. Record whether each event causes a toast, badge, inbox entry
  or state refresh; do not require a toast for every event type if firmware/settings
  suppress it. Respect quiet settings, per-friend preferences, sleep and privacy.

## Milestones and acceptance

1. Recover and write the minimal versioned protocol specification with provenance,
   direction/framing distinctions and independently sourced fixtures.
2. Implement durable registration, login, authenticated subscription and real native
   connection lifecycle. Send A the required middleware and route integration patches.
3. Implement all five event envelopes with A/C; add policy checks, bounded queues,
   acknowledgements/reconciliation and restart/reconnect behavior.
4. Validate the complete TLS/proxy path and native alert/state outcomes on two consoles.

Acceptance: debug on/off, ticket expiry/revocation and wrong-device denial, malformed/
oversized/partial frames, cancellation/resource cleanup, sleep/wake, network loss,
restarts, duplicates and queue overflow. Observe all five event types with their actual
toast/badge/state behavior and alert suppression. Meet or explicitly report the parent's
latency/convergence targets. A supplies real social events; C supplies real invitations.
A synthetic event source permits development, not end-to-end completion.

## Review handoff

Return branch/base/commit references, requirement-to-code/test/evidence ledger, contract
changes, migrations/rollback, operator notes and exact reproduction commands. Run
`go vet ./...`, `go test -race ./...` and required affected-repository CI. Retain sanitized
hardware results with firmware/build IDs and timings. Mark missing hardware or dependent
integration as pending; mocks, HTTP success and locally passing tests cannot close native
acceptance gates. Include known blockers and the next reproducible experiment.

## Copyable assignment

> Implement `prds/native-switch-penne-notifications-prd.md`. Read the linked coordination plan and shared
> parent requirements first. Use your own branch/worktree, agree shared interfaces at
> kickoff, and deliver only your owned feature changes plus narrow integration patches
> for A. Return the review handoff with explicit native acceptance and dependency status.
