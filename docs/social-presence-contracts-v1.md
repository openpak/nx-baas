# Switch adapter social & presence contracts — v1

Status: agreed by A (friends/presence workstream), published for B (Penne/notifications)
and C (invitations). Date: 2026-09-11. Base: nx-baas `a-friends-presence` branch.
This document is the semantic contract; the code is the reference implementation.
Changes require a version bump and a note in §7.

## 1. Authenticated principal and policy (consumed by B/C/D)

| Rule | Contract |
| --- | --- |
| Token validation | `validBearer`: RSA signature against the adapter key, `iss == https://e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com`, `typ == "token"`, `exp` in the future. Anything else is 401 `invalid_token`. B must apply the same rule to any BAAS credential it accepts; `bearer()` (signature-only) remains only where the console's *device* token is decoded, never as authorization. |
| Principal binding | A user-scoped path (`/1.0.0|2.0.0/users/<id>/…`, device-account PATCH/DELETE, blocks, profile read/write) must name the token's `sub`. Mismatch is 403 `insufficient_scope`. Re-export this as `requireCaller` semantics for B's delivery endpoints. |
| Principal → core account | BAAS user id → PID via the adapter store; PID → core account id via the projection (`openpakBackend.accountFor`). B receives recipients as **core account ids** from the adapter; it must not guess them from subjects. |
| Policy checks | Interaction/presence policy answers come from the core (`CheckInteraction`, `GetRelationship`) plus the adapter's local mirror for presence visibility (`presenceVisible`: relationship, directional blocks, the subject's `permissions.presence` ∈ {FRIENDS, FAVORITE_FRIENDS, SELF}). Revocation: core events (`credential_revoked`, `link_unlinked`, `account_banned`, …) end presence claims and mark lists stale immediately; B must revalidate policy at delivery time, not trust a queued eligibility decision. |
| Presence vs alerts (PRE-04) | The per-relationship `extras.self.isOnlineNotification` preference (default **on**, persisted; `false` stays `false`) gates **toast eligibility only**. It is projected in the friend list; B consumes it to filter user-visible alerts. It must never gate state synchronization. |

## 2. Social/presence snapshot (consumed by B/C)

- **Relationship entry** (list item of `GET /2.0.0/users/<me>/friends`): `friendId`
  (the friend's BAAS user id, 16 hex), nested `friend` user object (the same renderer
  as a search result) carrying `presence`, plus `isFavorite`, `createdAt`, `updatedAt`,
  and `extras.self.{isConfirmed, isOnlineNotification}`. The 22.5.0 parser counts an
  item only when `friendId`, `friend.nickname` and `friend.thumbnailUrl` all parse;
  `relationshipEntryGaps` is the machine-checkable form of that gate. Bound: 300 items,
  no native cursor.
- **Stable revisions** (SOC-05): entry timestamps derive from state changes, never from
  render time; the list etag is a content hash and is stable across unchanged fetches.
  `friendsUpdatedAt` on the user object is strictly monotonic (second-grain + tie-break),
  so two mutations inside one wall-clock second remain distinguishable.
- **Presence shape**: `presenceObj` — `state` ∈ {OFFLINE, ONLINE, PLAYING} (unknown
  renders offline), `updatedAt` = last state change, `logoutAt` = departure evidence,
  `extras.friends` app metadata when PLAYING.
- **Presence model** (PRE-01): per-device claims with absolute lease deadlines
  (`presenceLease`, default 120 s, `NX_PRESENCE_LEASE_SECONDS` to override — bound
  pending hardware cadence measurement). Aggregation: PLAYING > ONLINE > OFFLINE,
  most-recent state change wins ties. Expired claims decay to OFFLINE with
  `logoutAt = lease deadline`; stale disk data cannot outlive an expired session
  across restarts.
- **B's consumption contract**: for `presence_updated` events, take the recipient set
  from the core friend list of the subject, apply §1 policy, and re-read the snapshot
  (or the presence of the one friend) at send time; a queued event whose snapshot no
  longer authorizes the recipient must be dropped.

## 3. Core-event dispatch (single integration, owned by A)

- One poller (`followCoreEvents`), one durable cursor (`core-events.cursor` beside the
  store), one presence reconciler (`reconcilePresenceLoop`). B/C must not add a second
  poller or a competing cursor.
- Event → adapter effect (current):
  - `friend_requested` / `friend_accepted` / `friend_removed` → both projections'
    `friendsUpdatedAt` bumped (consoles re-fetch).
  - `account_banned` / `account_deleted` / `account_delete_started` /
    `credential_revoked` / `link_unlinked` → subject's presence claims ended + lists
    marked stale.
- **Semantic-change → delivery-work handoff to B (agreed boundary)**: A commits state
  and marks recipients stale; B polls the same store-backed snapshots and delivers.
  The durable handoff for push delivery (outbox vs replayable core event) is B's
  NTF-05 design decision; A guarantees: state committed before `friendsUpdatedAt`
  moves, and snapshots are stable and viewer-correct at any later read. A committed
  change is therefore recoverable by B after any restart by replaying snapshots; do
  not mark an event delivered on a timestamp alone.
- Crash rule: cursor advances only after the poll loop's effects for that page are
  done; effects are idempotent (re-running a page re-bumps idempotently), so at-least-
  once processing is safe.

## 4. Mutations and identity (consumed by C; A-owned surface)

- Durable request ids: `Store.EnsureRequest(fromPID, toPID)` is idempotent per directed
  pair and persisted. Create, inbox, outbox, accept, reject and cancel all name the
  same request by the same id. A settled request's record is dropped; a stale id is a
  404, never a second success.
- Core error → BAAS error mapping (`baasFailure`): invalid → 400 `invalid_params`;
  unknown → 404; blocked / not-pending / reverse-pending → 404 (the console's recovery
  is a re-sync); core unavailable → 503; anything else → 500. **No mutation returns
  success for an uncommitted operation.**
- Reverse request: `POST /2.0.0/friend_requests` when the target already requested us
  answers 200 describing the existing pending request (roles truthful, `state=PENDING`).
  C should expect the same shape from its surfaces.
- Invitation interplay (C): sending requires the sender↔recipient friendship; the
  core's `CheckInteraction` is the gate (blocked ⇒ denied). Recipient identity follows
  §1.

## 5. Emulator / title-server surface (SOC-04)

- `Resolve` speaks keys `code` (SW-DDDD-DDDD-DDDD, normalised) and `baas`. The
  emulator friend endpoint was fixed from `friend_code` → `code`.
- FRS: only `GET /v1/friend_recommendations` is evidenced and answered (200, empty
  gRPC body, content-type `application/grpc`). Every other FRS operation answers an
  explicit gRPC `UNIMPLEMENTED` (grpc-status 12) and a NOTICE log — no blanket empty
  success.

## 6. Storage owned by the adapter (migration map)

`baas.json` additions (additive; older binaries ignore unknown fields):
`users[*].friendPrefs` (per-relationship `isFavorite`/`isConfirmed`/
`isOnlineNotification`), `users[*].devicePresence` (per-device claims with absolute
leases), `requests` (durable request records). One-time migration at load: the old
`users[*].favourites` list folds into `friendPrefs`. Rollback: old binaries ignore the
new fields; preferences recorded after upgrade are invisible to a rolled-back build
(no corruption).

## 7. Changelog

- v1 (2026-09-11): initial version; published with the A workstream implementation.
