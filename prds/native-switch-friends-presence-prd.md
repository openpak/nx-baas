# A — Native friends, profiles and presence

Status: ready for agent assignment. Date: 2026-09-11.

## Objective and owned scope

Restore native friend lists and durable social actions, then make authorized presence
accurate across users, devices and titles. Own SOC-01–05 and PRE-01–04, journeys J1–J3,
J6–J7 and the state-reconciliation portion of J5. You are also the integration owner
for shared adapter wiring; this does not transfer B/C/D feature implementation to you.

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

Own new social/presence implementation files and their tests. Own common router,
authentication, core-client adapters, shared account/storage models and migrations,
and the single core-event polling/cursor integration. Apply narrow wiring changes
supplied by B/C/D; do not rewrite their modules. The exact existing-file map is agreed
at kickoff because `main.go`, `account.go`, `openpak.go`, `openpak_events.go`,
`services.go` and `gameapi.go` currently mix concerns.

Publish authenticated principal/policy access, social/presence snapshot and event-source
contracts to B/C. Implement canonical mutation integration, token/principal enforcement,
and viewer-aware policy. B owns transport and delivery storage, C owns invitation data,
D owns store data. Each owns its own feature-specific persistence through the agreed
storage interface; A coordinates shared migration registration.

## Functional requirements

### SOC: friends and profiles

- **SOC-01 — Native relationship contract.** Return relationship entries with
  `friendId`, `friend.nickname` and `friend.thumbnailUrl`. The 22.5.0 parser excludes
  entries without these three successfully parsed fields. Keep the nested user renderer
  separate from relationship and search renderers. Implement the single-friend shape,
  real reachable avatars, established envelope fields and client-compatible bounds.
  Verify empty, one-entry and 300-entry lists; specify overflow/pagination behavior from
  evidence instead of inventing a native cursor.
- **SOC-02 — Relationship preferences.** Implement `/isFavorite`,
  `/extras/self/isConfirmed` and the observed online-notification preference contract.
  Persist and project `isFavorite`, `extras.self.isConfirmed` and
  `extras.self.isOnlineNotification` for the viewer. False must remain false. Do not use
  `isFavoriteFriend` or an invented `isNewFriend` field as the native contract.
- **SOC-03 — Complete mutations.** Request, accept, reject, cancel, remove, block and
  unblock must commit through the appropriate core contracts. Use durable request IDs
  consistently across creation and inbox/outbox actions. Define duplicate, concurrent,
  reverse-request and retry behavior; never return success for an uncommitted operation.
- **SOC-04 — Profile and discovery.** Keep nickname/avatar and friend-code resolution
  consistent across supported surfaces, including the adapter's `friend_code`/`code`
  mismatch. Inventory FRS operations exercised by native profiles/recommendations and
  implement those required for supported journeys; document unsupported operations
  explicitly instead of returning blanket empty-success responses.
- **SOC-05 — Synchronization.** Use stable revisions/timestamps when state is unchanged;
  distinguish rapid consecutive mutations. Reconcile cross-platform core events and
  define legitimate Switch projections for friends originating on other platforms.
  Avoid holding a global projection mutex across per-friend network calls.

### PRE: presence and privacy

- **PRE-01 — State model.** Define per-device/account/title lifetimes and deterministic
  aggregation into OFFLINE, ONLINE and PLAYING. Derive timestamps from state changes.
  Reconcile adapter presence with core sessions; stale persisted data must not override
  expired sessions. Define multiple-device and multiple-title precedence in the design.
- **PRE-02 — Lifecycle.** Handle login, renewal, title start/stop, room leave, explicit
  logout, device unlink, account switch, sleep, silent network loss and server restart.
  Measure native renewal cadence before fixing lease durations. Record the chosen
  expiry bound and verify it; the audit does not establish that every client necessarily
  goes offline after the existing 30-second core lease.
- **PRE-03 — Visibility.** Apply relationship, block, account status and presence privacy
  to every read and push payload. Revocation prevents new unauthorized delivery and
  invalidates stale queued visibility. A local preference change alone is insufficient.
- **PRE-04 — Notifications versus state.** A disabled online alert must not prevent an
  authorized friend list from becoming current. Separate synchronization eligibility
  from user-visible toast eligibility and follow native/global console settings.

## Milestones and acceptance

1. Pin baseline and agree shared contracts with B/C/D; enumerate actual core gaps.
2. Fix relationship rendering, preference false values, durable mutation identity,
   errors and authorization. Add independent parser-contract fixtures and core integration tests.
3. Implement measured presence leases, multi-device aggregation, logout/leave expiry,
   privacy and profile updates. Publish semantic changes through B's agreed delivery API.
4. Integrate B/C/D route and dependency patches in order; run common regressions.

Acceptance: empty/one/300-entry lists, required-field omissions, both sides of request
acceptance, reject/cancel/remove/block/unblock, favourite true/false, confirmation,
restart durability and cross-account denial. Two consoles must show current profiles
and lifecycle transitions, including silent disconnect and multiple devices. Turning
off an online alert must preserve authorized list updates. State-only acceptance can
precede B; automatic wake-up/push and reconnect acceptance require B integration.

## Review handoff

Return branch/base/commit references, requirement-to-code/test/evidence ledger, contract
changes, migrations/rollback, operator notes and exact reproduction commands. Run
`go vet ./...`, `go test -race ./...` and required affected-repository CI. Retain sanitized
hardware results with firmware/build IDs and timings. Mark missing hardware or dependent
integration as pending; mocks, HTTP success and locally passing tests cannot close native
acceptance gates. Include known blockers and the next reproducible experiment.

## Copyable assignment

> Implement `prds/native-switch-friends-presence-prd.md`. Read the linked coordination plan and shared
> parent requirements first. Use your own branch/worktree, agree shared interfaces at
> kickoff, and deliver only your owned feature changes plus narrow integration patches
> for A. Return the review handoff with explicit native acceptance and dependency status.
