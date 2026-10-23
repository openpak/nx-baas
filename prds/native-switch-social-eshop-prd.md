# Native Switch friends, presence, notifications, invitations and OpenPak store

Status: umbrella specification; implementation and hardware acceptance pending.
Owner: tobagin. Reviewer: requesting Codex agent. Date: 2026-09-11.
Primary implementation role: Switch adapter owner (`nx-baas`, S1 T4/T5).

**Parallel assignment:** use the [two-/four-agent coordination plan](native-switch-parallel-plan.md)
and its four focused PRDs. That plan supersedes the single-agent ownership/assignment
wording below; this document retains the shared requirements and acceptance criteria.

## 1. Objective and completion boundary

Make OpenPak's social features work through the native Switch profile and supported
games: friends appear after acceptance, profiles and presence stay current, invitations
reach the recipient, and notifications survive normal disconnects and restarts. Deliver
an OpenPak homebrew catalog through the native eShop applet with a proven acquisition,
installation, launch, update and redownload journey.

The first firmware target is Horizon 22.5.0 on the owner's configured Atmosphère
installation. Record the actual Atmosphère version and active configuration before
hardware validation. Other firmware, emulators and games receive separate results;
passing one client does not establish support for the others.

“100% working” means every mandatory scenario in this PRD passes on the declared
support matrix, with reproducible evidence. Unknown protocol behavior, missing core
contracts and unavailable hardware remain explicit open gates. Do not replace native
acceptance with successful HTTP responses, placeholder data or passing unit tests.

Store scope assumes OpenPak's own redistributable homebrew catalog. Nintendo's live
store, purchases, payments and account network are outside this release. This PRD does
not promise compatibility with every title's multiplayer protocol. Existing Switch
expansion requirements for Stardew Valley and Outbound remain in force; record their
invitation/join capabilities individually rather than silently reducing that scope.

## 2. Read first: evidence and working material

1. Firmware 22.5.0 findings (internal research notes)
   are the latest static evidence, including module-relative addresses and parser gates.
2. Backend audit (internal research notes) records
   implementation defects. Its missing-firmware and unknown-list-shape statements are
   superseded by the firmware findings. Recheck source locations against current HEAD.
3. Module inventory (internal research notes)
   pins input hashes and build IDs.
4. [Switch expansion PRD](../../prds/switch-expansion-prd.md), current `account` protobuf/API
   definitions and adapter documentation define architecture and existing contracts.
   The SP-5 draft (internal research notes) is historical; its
   proposed gaps are not proof that those contracts are still missing.

Local firmware: `~/Downloads/Firmware.22.5.0`.
Private analysis: `~/openpak-firmware-audit-22.5.0`, including Ghidra
projects, scripts and extracted modules. Ghidra load base is `0x100000`; add it to
the report's RVAs. These local files are useful research inputs, not repository assets.
The scan covered 238 NCA headers; no live console validation accompanied that scan.

### Public protocol references

| Reference | Use and limitation |
| --- | --- |
| [Penne servers](https://github.com/kinnay/NintendoClients/wiki/Penne-Servers) | Registration, linking, notification tokens, login tickets and frontline discovery; does not supply a complete persistent binary protocol. Penne replaced legacy NPNS in firmware 18.0.0. |
| [Online Play Invitation server](https://github.com/kinnay/NintendoClients/wiki/Online-Play-Invitation-Server) | Invitation REST routes, fields, inbox and read operations; firmware 20+ uses v2 where documented. |
| [Friend services](https://switchbrew.org/wiki/Friend_services) | Console IPC for friends, presence, invitations and notification preferences; IPC is not the network wire format. |
| [NPNS services](https://switchbrew.org/wiki/NPNS_services) | Console subscription and notification receiver interfaces. |
| [BAAS server](https://github.com/kinnay/NintendoClients/wiki/BAAS-Server) | Account and social HTTP research; distinguish newer account hosts from friends-module hosts. |
| [eShop applet](https://github.com/kinnay/NintendoClients/wiki/eShop-Applet-(Switch)) | Applet entry and browser bridge research. |
| [Beach server](https://github.com/kinnay/NintendoClients/wiki/Beach-Server) and [Atum server](https://github.com/kinnay/NintendoClients/wiki/Atum-Server) | Device/rights and content-delivery research for the selected store journey. |
| [FlatBuffers internals](https://flatbuffers.dev/internals/) | Layout reference supporting the firmware's structural evidence; not a recovered Penne schema. |

Record source revision/access date when turning public research into an implementation
contract. Label facts as source-confirmed, firmware-confirmed, runtime-confirmed or
hypothesis. Do not treat guessed fields as established requirements.

## 3. Ownership and implementation rules

This PRD is assigned to the Switch adapter role reserved by `prds/README.md`; it is
not an instruction for unrelated workstream agents to edit `nx-baas`. The assigned
agent owns adapter handlers, native projections, Penne transport and console route
integration. Check repository instructions and concurrent work before editing.

- Keep identity, canonical social relationships, moderation and shared invitation/session
  state behind the account core's versioned contracts. Never access its database directly
  or create a competing canonical friend graph in the adapter.
- Inspect existing contracts first. For missing behavior, prepare a concrete contract
  proposal and separate reviewable core change through the established account workflow.
  Do not let a mock contract count as completed integration. Unrelated website, app and
  title-server changes retain their respective owners.
- Use the project's Go 1.26 and AGPL-3.0-only conventions. Independently implement
  behavior; third-party implementation source is evidence of observable behavior only and must not be
  copied, translated or structurally mirrored into OpenPak.
- Commit no credentials, tokens, keys, firmware, decompiled Nintendo code, ROMs or asset
  dumps. Use synthetic fixtures and sanitized observations with provenance.
- Preserve existing working account linking, News, saves and emulator integration.
  Identify required route changes and run their relevant regression checks.
- This handoff requests implementation artifacts for review. Prepare deployment and
  rollback instructions; do not interpret it as authorization to publish or alter the
  owner's active console configuration. Continue independent implementation if console
  testing is unavailable, and mark hardware gates pending.

## 4. Required player journeys

| ID | Journey | Required outcome |
| --- | --- | --- |
| J1 | A requests B; B accepts | Both native friend lists show the relationship and correct profile; reopen and reboot preserve it. |
| J2 | A favourites, unfavourites and acknowledges B | Preferences and new-friend state persist, without changing B's independent preferences. |
| J3 | B connects, starts a title, leaves it and disconnects | A sees authorized ONLINE, PLAYING and OFFLINE transitions with current title data. |
| J4 | A sends a supported online-play invitation | B receives the native invitation and eligible alert, can read it, and can explicitly enter the supported title's join flow. |
| J5 | B sleeps or loses network while social state changes | Reconnect converges to current state; missed eligible events reconcile without duplicate user-visible alerts. |
| J6 | A removes or blocks B, or restricts visibility | Lists, presence, invitations and delivered payloads consistently obey the new relationship/policy. |
| J7 | A changes nickname/avatar through a supported surface | Authorized profile views update and avatar resources load on the console. |
| J8 | A opens the native store and acquires a homebrew title | Catalog, rights, download, install and launch succeed; update and redownload also work. |

## 5. Functional requirements

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

### SHP: native OpenPak store

- **SHP-01 — Launch and routing.** Prove native shop launch, selected-account handoff,
  required host routing, TLS acceptance and `window.nx.shop` callbacks on the declared
  setup. Start with a diagnostic page and record the actual request sequence. The
  firmware dump does not contain the live storefront or active Atmosphère settings.
- **SHP-02 — Catalog.** Provide controller-usable listing, details, images, language
  fallback, compatibility, size/version and ownership state. Start with one original or
  redistributable homebrew title and record its distribution permission. Provide useful
  empty, loading and failure states; keep protocol diagnostics out of normal store UI.
- **SHP-03 — Acquisition and rights.** Implement idempotent acquisition, durable
  entitlement and required account/device/rights synchronization. Replace relevant
  Beach/license placeholders with actual behavior. Trace which 22.5.0 ticket/device/
  virtual-card operations the chosen journey invokes; implement required operations,
  documenting why unused ones are not release dependencies.
- **SHP-04 — Download and install.** Prove packaging/trust feasibility, metadata/hash
  consistency, authorized content delivery, resumable download and download-task
  lifecycle through install and launch. A web page or available-license flag does not
  prove this gate. Record any required build-specific console changes and their exact
  effects as a reviewable proposal before active installation.
- **SHP-05 — Ownership lifecycle.** Complete update, removal and redownload; handle
  account changes, invalid entitlement, insufficient storage, cancellation, corrupt or
  missing content, interrupted network and backend restart without false ownership or
  success states. Do not claim store completion if native installation is still blocked.

## 6. Integrity, operations and data requirements

Validate token signature, lifetime and applicable issuer/audience/type on protected
operations. Bind path/body IDs to the authenticated principal and authorized device.
Propagate backend failures using verified native error contracts. Test unauthorized
reads, cross-account mutations, blocked invitations and expired/revoked credentials.

Before migrations, document which state belongs to core versus adapter: native ID
mappings and preferences, Penne credentials/links/subscriptions, event cursors/delivery
state, device presence freshness, invitation projections and store entitlements/tasks.
Specify retention, uniqueness/idempotency constraints, migration and rollback strategy.
Avoid generating new canonical IDs on each process start.

Expose sanitized connection/delivery/retry/error counters, queue depth, oldest event
age, stale presence and store-task failures. Correlate a core mutation with native
delivery without logging bearer tokens or full private payloads. Bound connection
buffers and per-client queues; malformed frames must not panic or allocate without limit.

Proposed release targets, to be measured on controlled healthy-network hardware:
eligible awake-client social/invitation delivery p95 ≤5 seconds over at least 30 events;
reconnection convergence ≤30 seconds after authenticated transport/subscription recovery;
silent-disconnect expiry within the documented measured lease bound. These are product
targets, not established Nintendo protocol timers. Record results and any unmet target;
do not silently adjust thresholds to make tests pass.

## 7. Milestones and dependencies

| Milestone | Deliverable | Exit gate |
| --- | --- | --- |
| M0: baseline and contracts | Current repo SHAs, clean/dirty state, firmware/deployment matrix, requirements ledger, core capability mapping and reproducible fixtures | Known defects and unknowns classified; installation/protocol spikes have bounded questions and outputs. |
| M1: social correctness | SOC requirements, authorization/error fixes and debug-stream regression fix | Automated contract/integration tests pass; two-console list, preference and mutation journeys demonstrated. |
| M2: Penne lifecycle | Minimal written protocol specification, durable registration and verified transport/subscription/recovery | Console establishes and resumes a real connection through the full deployment route. |
| M3: presence and notifications | PRE and NTF event delivery/filtering/recovery | Two-console lifecycle and alert matrix passes with latency and expiry evidence. |
| M4: invitations | Native REST, core integration, push/read state and title-specific payload mapping | Send → native alert/inbox → read → explicit supported join; expiry and blocked cases pass. |
| M5: store feasibility and catalog | SHP-01/02 and packaging/rights/download feasibility results | Native applet renders catalog; installation dependencies identified with a demonstrated viable path or explicit blocker. |
| M6: store lifecycle | SHP-03/04/05 | One title acquired, installed, launched, updated, removed and redownloaded on hardware; failure recovery passes. |
| M7: review package | Completed requirements/evidence ledger, CI, runbooks, migrations and rollback | Reviewer can reproduce results; every mandatory gate passes or remains visibly incomplete. |

Proceed with source-confirmed M1 fixes while protocol research continues. Invitation
REST and store feasibility can progress independently; M3 depends on M2, native M4
delivery depends on M3, and M6 depends on M5. Do not delay ordinary fixes until all
reverse engineering is complete. Use separate reviewable commits/PRs per milestone.

## 8. Acceptance matrix and verification

Use two real consoles/accounts for native acceptance, a third account for isolation
tests, and multiple devices/users for aggregation. Record Horizon, Atmosphère, module
build IDs, active redirects/patch hashes, backend commits and title versions. Changes
originating on website/app or a core integration harness must reach native clients too.

| Area | Mandatory cases and assertions |
| --- | --- |
| Native parsing | Empty/one/300 friends; required-field omissions; old flat response rejected by evidence-based fixture checks; single-entry projection; reachable avatar. A fixture check alone is not proof the firmware parsed it. |
| Social lifecycle | Request/accept/reject/cancel/remove; retries and simultaneous requests; durable IDs; favourite true/false; confirmation; reboot; core failure produces no false success. |
| Presence | Online/playing/idle/offline; title/room exit; two devices; account switch; privacy/block change; sleep/wake; silent disconnect; restart with stale persisted state. |
| Notifications | All five native types; sender/recipient effects; toast/badge/state outcome; alerts disabled but state current; multiple accounts; duplicate/reordered events; offline queue/reconnect; cursor restart; queue overflow policy. |
| Transport | Debug on/off through router; real HTTP/2/TLS/proxy path as applicable; expired ticket; wrong device; malformed/oversized/partial frames; cancellation; reconnect; bounded resource use. |
| Invitations | v2 inbox/create plus endpoint-specific versions; localized/title data; read/read-all; restart; duplicate send; offline recipient; expiry; blocked user; incompatible title/unavailable session; explicit join result per supported title. |
| Store | Native launch/account selection; catalog/details; acquire twice; rights sync; install/launch/update/redownload; space failure; interruption/resume; invalid entitlement; missing/corrupt content; cancellation and account switch. |
| Regression | Existing linking, native News and saves routing, emulator friend lookup and current title login/join smoke scenarios appropriate to the changed code. |

Run `go vet ./...` and `go test -race ./...` in each affected Go repository and its
required CI checks. Use real adapter/core integration tests for durable transitions;
test rollback/restart and event reconciliation. Add bounded parser robustness tests
for new binary decoding. Do not assert interoperability using only encoder/decoder
round trips from the same implementation. Use independently sourced fixtures or
sanitized runtime observations, and record the provenance of each.

For every hardware case retain steps, expected/actual screen state, sanitized request/
event order, timings and pass/fail. Hardware unavailable means pending hardware, not
passed. Existing September 8 observations and the September 11 static scan are baseline
evidence, not acceptance of newly implemented code.

## 9. Open questions and contract requests

Resolve these in M0 or the named spike, updating the ledger as evidence arrives:

1. Which current core RPCs cover each mutation, stable request ID, moderation check,
   invitation read state, session renewal and durable event cursor? Propose only missing
   semantics, with idempotency, errors and compatibility requirements.
2. What are the complete Penne message directions, minimal schema, auth/subscription
   lifecycle, server framing, acknowledgement and resume behavior on 22.5.0?
3. What are the precise five event payloads and native alert suppression rules?
4. Which profile/FRS operations and invitation title payloads are actually required by
   the supported console/title journeys?
5. Which active Atmosphère configuration and endpoint trust changes are in use? What
   two-console hardware setup is available for acceptance?
6. What packaging, signatures/trust, rights and device operations permit the chosen
   homebrew title to install through the native workflow? Which dependencies are proven
   and which require further experiments?

Each unresolved item needs an owner, evidence so far, next reproducible experiment and
the milestone it blocks. A failed spike must state the actual blocker and feasible next
step; do not quietly replace native features with an emulator-only or NRO-only flow.

## 10. Required handoff back to the reviewer

Provide:

1. Repository/branch/commit or PR references per milestone, including dependent core
   changes; summarize behavior and migrations rather than just edited filenames.
2. A ledger mapping every SOC/PRE/NTF/INV/SHP requirement and J1–J8 journey to code,
   automated tests, runtime evidence and status: implemented, hardware-verified, pending
   or blocked. Include all gaps and deviations.
3. The independently authored native protocol specification, provenance, fixtures,
   event mapping and a reproducible test harness. Include commands and environment
   prerequisites; keep private keys/captures outside the repo.
4. CI/test results, measured latency/expiry/recovery behavior, and the firmware/device/
   title acceptance matrix with evidence locations.
5. Operator runbook: configuration, migrations, endpoint routing, observability,
   deployment verification and rollback. Document proposed console changes separately.
6. A short reviewer checklist of highest-risk areas: principal binding, native parser
   shapes, preference false values, transport direction/framing, event atomicity/replay,
   privacy, stale presence, invitation expiry/join and entitlement/install consistency.

### Copyable assignment for the implementation agent

For two or four agents, use the coordination plan's assignment instead of this
all-features prompt. The prompt below remains available for a single-agent implementation.

> Implement `prds/native-switch-social-eshop-prd.md` as the Switch adapter owner.
> Read its evidence reports and current repository instructions first. Start with M0
> and source-confirmed M1 fixes; complete the remaining milestones in dependency order,
> advancing independent work when hardware or protocol research is blocked. Maintain the
> requirements/evidence ledger throughout. Use existing account contracts and prepare
> separate reviewable proposals for missing core behavior. Return the review package in
> section 10. Do not claim native interoperability from mocks or HTTP success, and leave
> unavailable hardware gates explicitly pending for the owner/reviewer.
