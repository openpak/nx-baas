# Workstream A review package: friends, profiles and presence

Workstream: A of `../prds/native-switch-parallel-plan.md`; PRD:
`../prds/native-switch-friends-presence-prd.md`. Date: 2026-09-11.

- Repository: `nx-baas`, branch **`a-friends-presence`**.
- Base commit: `e8b7afcd62f69ed0c9bb6f63901b4301dce28ef9` (clean at kickoff).
- Head: see `git log a-friends-presence ^main`.
- Verification: `go vet ./...` clean; `go test -race ./...` passes (existing suite
  retained and extended; new suites listed in §2).

## 1. Requirement → code/test/evidence ledger

Status words: **implemented** (code + tests in this branch), **implemented, hardware
pending** (done as far as source evidence reaches; native acceptance needs consoles),
**pending** (not started, owned elsewhere).

| Req | Status | Implementation | Tests | Native evidence |
| --- | --- | --- | --- | --- |
| SOC-01 | implemented, hardware pending | `social.go` `relationshipObj` (nested renderer `friendObj` kept separate from relationship and search renderers); `friendId` + `friend.{nickname,thumbnailUrl}` gate `relationshipEntryGaps`; 300-entry bound, no invented cursor; avatar route now answers every `/1/<id>` it hands out (default avatar fallback) | `parser_contract_test.go` (fixture `testdata/native-relationship-entry.json`: gate satisfied, flat shape rejected, per-field omissions, 300 bound, avatar reachability), `flow_test.go` `TestFriendListEntriesCarryACountry` (rewritten to the observed shape) | Two-console empty/one/300 list check pending hardware |
| SOC-02 | implemented, hardware pending | PATCH `/isFavorite` (native) and legacy `/isFavoriteFriend` map to one persisted `FriendPreference`; `/extras/self/isConfirmed` acknowledgement persisted; `/extras/self/isOnlineNotification` persisted with native on-default; `isNewFriend` never emitted; single-friend PATCH reply uses the relationship shape | `TestRelationshipPreferencesPersistAndProject` (false stays false across restart; defaults; PRE-04 alert-off keeps state current), `TestListEtagStableWhenNothingChanged` | Favourite star + acknowledge flow on hardware pending |
| SOC-03 | implemented, hardware pending | All mutations commit via core: request (`RequestFriend` + durable `Store.EnsureRequest`), accept/reject (`FriendAccept`→core accept/remove), cancel & remove (`RemoveFriend`), block/unblock (core `Block`/`Unblock` + local mirror). Settled records dropped (no second success). Core failures map through `baasFailure` — never success for uncommitted. Duplicate = idempotent same id; reverse request resolves to the existing pending request; legacy user-id references still honoured (pre-upgrade consoles) | `TestDurableRequestIdentitySurvivesRestart`, `TestRequestAcceptAndTheReverseCase`, `TestRejectCancelRemoveCommitOrError`, `TestSettledRequestCannotBeAnsweredTwice`, `TestCrossAccountDenial`, `TestBlockUnblockCommitAndTakeEffect` | Both-sides acceptance, retries, removal on hardware pending |
| SOC-04 | implemented, hardware pending | Emulator add-by-code fixed (`friend_code`→`code`, normalised); FRS inventory: only `GET /v1/friend_recommendations` evidenced — answered as captured; everything else explicit gRPC UNIMPLEMENTED + NOTICE log, no blanket empty success | `TestEmulatorFriendCodeLookup`; FRS behaviour asserted in `baas_surface_test.go` (recommendations path) — unsupported-op log line is operational evidence | Profile surfaces on hardware pending; other FRS ops need a console trace before implementation |
| SOC-05 | implemented, hardware pending | Stable timestamps and content-hash etag (no render-time values); strictly monotonic `friendsUpdatedAt` (`bumpFriendsUpdated`); projection lock never held across core RPCs (`friendView`/`Resolve` copy under lock); cross-platform core events route through the single poller, extended to account-status events; non-projection accounts stay excluded from Switch lists (documented, SW-04) | `TestFriendsUpdatedAtIsStrictlyMonotonic`, `TestListEtagStableWhenNothingChanged`, lock fix covered by `-race` run | Cross-platform (phone/website-initiated) changes visible on a console: pending hardware |
| PRE-01 | implemented, hardware pending | Per-device presence claims with absolute lease deadlines (`DevicePresence`), deterministic aggregation (PLAYING > ONLINE > OFFLINE, recent-wins), timestamps from state changes, stale persisted data cannot override expired sessions (absolute deadlines; legacy field only when no device entries exist) | `TestAggregatePresencePrecedence`, `TestStalePresenceDoesNotSurviveARestart`, `TestPresencePatchIsPerDevice` | Two-console two-device scenarios pending hardware |
| PRE-02 | implemented, hardware pending | Lifecycle: login (device claim + core session), per-device presence PATCH, device unlink/account switch (`expireDeviceEverywhere`, `devices/me/delete` now ends claims), room leave (`POST /internal/photon-room-leave`), silent loss & sleep (lease expiry), server restart (absolute deadlines + reconciler re-derivation). Lease = 120 s default (`NX_PRESENCE_LEASE_SECONDS`), reconciler sweeps 15 s, core session renewed by heartbeat and expired on departure. **Native renewal cadence not measured — the bound is a documented choice pending hardware (see §4)** | `TestAccountSwitchEndsPreviousClaim`, `TestReconcilerAgreesWithTheCore`, room-leave exercised via `gameapi_test.go` pattern | Silent-disconnect expiry measurement pending hardware |
| PRE-03 | implemented, hardware pending | `presenceVisible`: subject's `permissions.presence` (FRIENDS/FAVORITE_FRIENDS/SELF), directional blocks hide presence, account status via core events + core friend list; applied to every list render (push payloads are B's, contract published) | `TestPresenceVisibility`, `TestBlockUnblockCommitAndTakeEffect` | Privacy toggles vs a second console pending hardware |
| PRE-04 | implemented, hardware pending | `isOnlineNotification` projected per relationship and never consulted by state rendering; contract hands it to B for toast filtering | asserted in `TestRelationshipPreferencesPersistAndProject` | Alerts-off console stays current: pending hardware |
| Shared integration (A-owned) | implemented | Router/auth (`validBearer`, `requireCaller`), core-client adapters (error translation `coreErr`, reverse-pending detection), shared storage models + migration, single core-event poller/cursor + single presence reconciler | expired/foreign-token and cross-account tests; fakes upgraded to mirror core rules (`openpak_test.go`) | — |
| Journeys | | J1 (request/accept, both lists, restart) covered at state level by `TestRequestAcceptAndTheReverseCase` + `TestDurableRequestIdentitySurvivesRestart`; J2 by `TestRelationshipPreferencesPersistAndProject`; J3 (state-only) by presence suite; J6 by block/remove suite; J7 profile updates via existing PATCH surface + stable thumbnails. J5 reconciliation portion = poller + leases + reconciler. J4/J8 pending (C/D) | | All journeys need two-console evidence: pending hardware |

## 2. Test inventory (new/changed)

- `parser_contract_test.go` — SOC-01/02 parser contract against the fixture; avatar
  reachability; 300 bound; etag stability.
- `social_test.go` — SOC-03/04 mutations incl. durable identity, reverse/duplicate,
  cross-account denial, blocks; expired/foreign-token refusals; fixture
  (`socialServer`) with a fake core mirroring the core's pair/block rules.
- `presence_test.go` — PRE-01/02/03 model, per-device, restart, visibility, account
  switch, reconciler agreement (fake core session registry).
- Updated: `flow_test.go` (list entries now relationship-shaped; search carries
  tokens — search is authenticated), `baas_surface_test.go` (authenticated
  documented-method sweep; regenerable-code flow), `openpak_test.go` (fake core
  mirrors reverse-pending/blocks/remove semantics), `shape_test.go`/`gameapi_test.go`
  (interface stubs).

## 3. Contract changes and requests to the core

Published: `docs/social-presence-contracts-v1.md` (principal/policy, snapshot,
core-event dispatch, mutation/error semantics, storage map).

Contract requests (core review workflow, none blocking this branch):

1. **Relationship timestamps**: expose friendship created/updated-at so native
   relationship `createdAt`/`updatedAt` need not fall back to account creation.
2. **Durable request ids core-side**: `RequestFriendResponse` carries no request id;
   the adapter mints and persists the native id mapping. A core-side id would remove
   the adapter's `requests` map.
3. **Pagination**: `ListFriends` has no page contract; >300-friend accounts need one
   before the native bound can be lifted (evidence says the parser caps at 300 and
   shows no cursor).
4. **Legacy stack removal/blocks**: openpak-account has no friend-removal or block
   contract; the adapter maps removal to friend-accept(false) (pending only) and
   blocks stay adapter-local there. The OpenPak core — the target — has both.
5. **Presence events**: no core event fires when a session expires; the adapter's
   reconciler covers its own projections, but other adapters must poll or subscribe.

## 4. Open gates (explicit)

- **Hardware acceptance pending, all native gates.** No console was touched in this
  workstream. Required: two consoles, third isolation account; Horizon 22.5.0 +
  recorded Atmosphère configuration; list/prefs/mutation journeys; presence
  lifecycle incl. silent disconnect and multiple devices; privacy toggles; alert-off
  state-currency check.
- **Lease measurement pending**: the native presence renewal cadence was not
  measurable from static evidence; 120 s (configurable) is the documented bound.
  Measure on hardware, then confirm or adjust `presenceLease` (single constant,
  single env override).
- **Penne delivery (B)**: event *push* and reconnect wake-up need B's transport;
  this branch guarantees the state and publishes the snapshot contract. State-only
  acceptance precedes B per the PRD.
- **FRS unsupported operations**: promoted to implementations only on a console
  trace naming them.

## 5. Operator notes

- Deploy: existing image flow; no new env vars required. Optional:
  `NX_PRESENCE_LEASE_SECONDS` (10–3600, default 120).
- Storage: `baas.json` gains additive fields (`friendPrefs`, `devicePresence`,
  `requests`) with a one-time fold of `favourites` at load. Rollback is safe (old
  binaries ignore unknown fields; post-upgrade preferences invisible to a rolled-back
  build). No deletion, no schema break.
- New observability: presence reconciler logs on register/heartbeat-failure/expiry
  (`presence register|expire`), FRS unsupported-op NOTICE lines, mutation failures now
  log before their native error is returned (correlatable by user id and path).
- Verification commands:
  - `cd nx-baas && go vet ./...`
  - `cd nx-baas && go test -race ./...`
  - Fixture check: `go test -run TestRelationshipEntrySatisfiesTheNativeFixture .`
- Rollback: redeploy the previous image; no data migration must be undone.

## 6. Reviewer checklist (highest-risk areas)

1. Principal binding: every user-scoped route now requires `sub == path id` — check
   the emulator/tooling surfaces were not broken (they live on the internal API port).
2. The relationship renderer change is the native-acceptance keystone: verify the
   fixture test fails if any of the three required fields is dropped.
3. Preference tri-state: `isOnlineNotification` default-on vs persisted-false.
4. Request-id lifecycle: record dropped after settle; stale id ⇒ 404, not double
   success.
5. Reverse-request reply describes the existing incoming request (roles truthful).
6. Aggregate presence precedence and legacy-field demotion (shadow cannot outlive a
   device lease).
7. Error mapping: core failure ⇒ native error, never success.
8. Single poller / single reconciler: B/C must not add competitors (contract §3).
