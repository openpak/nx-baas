# Firmware 22.5.0 follow-up: notifications and the eShop, 2026-09-12

A second pass over the local audit tree (`~/openpak-firmware-audit-22.5.0`) after the
native workstreams shipped, looking for contract mismatches we are still serving.
Sources: `npns/strings.txt`, `friends/strings.txt` and `friends/decomp*`, `nim/strings.txt`,
`shop/strings.txt`, `offlineWeb/strings.txt`. Addresses are module-relative (Ghidra load
base `0x100000`). Nothing here is runtime-confirmed; each item says what would confirm it.

## 1. The friends module drops any event that is not addressed to an account

`FUN_001a15c0` is the event dispatcher: it matches the five type strings and calls one
handler each. Every handler begins the same way — `friend_request_authorized` at
`001a1bb0`, `friend_deleted` at `001a1c60`:

```c
if (*param_1 != 0 || param_1[1] != 0) {   // two 64-bit words: a 128-bit account id
   ... refresh ...
}
return;                                    // zero id: the event is discarded in silence
```

`param_1` is copied from the notification context at `+0x30`/`+0x38` before the call, so
the id arrives from the NPNS layer with the message, not from the JSON body. It is the
same 128-bit shape the console uses in `/v1/accounts/%016llx%016llx/notification_tokens`
[npns strings, `0x120f4b`].

**We never capture that id and never put it on the wire.** A correctly framed event with
a zero account id reaches the friends module and is dropped before any refresh happens.
This is the most likely reason a delivered notification still changes nothing on screen.

*Action:* record the 128-bit account id from the `notification_tokens` path on the Penne
association and address deliveries with it. *Confirmation:* one accepted friend request
with the id populated makes the sender's list refresh without a reboot.

## 2. Request field names: the console uses two spellings, we accept one

npns carries five request templates:

| String | Endpoint it belongs to |
| --- | --- |
| `{"id":"%s","password":"%s"}` | login_tickets (what we observe on the wire) |
| `{"penne_id":"%s","password":"%s"}` | the same pair, other call sites |
| `{"penne_id":"%s","password":"%s","nsa_id_token":"%s"}` | `/v1/accounts/<id>/links` |
| `{"penne_id":"%s","application_id":"%.*s"}` | application subscription |
| `{"penne_id":"%s"}` | account-scoped calls |

`penne.go` reads `id` only, so a call that spells it `penne_id` authenticates as nobody
and takes the unauthenticated branch. This also closes the "request-side field names"
open item in `docs/penne-protocol.md` §1 with firmware evidence.

*Action:* accept either spelling everywhere a Penne credential is read.

## 3. `X-LoginTicket-TTL` is a header the client knows about

`0x1239cd` sits in the NPNS header block beside `X-Power-State`, `X-Hug`, `X-Login-Try`,
`X-Fro-Result`, `X-Execution`, `X-Network-Type` and the literal `penne`. We send none of
it on the login-ticket response. Whether the client *requires* it is unproven; emitting
`expires_at - issued_at` costs nothing and matches the documented four-day TTL.

## 4. The frontline is HTTP/2 and the client validates the connection preface

`SETTINGS: invalid SETTINGS_ENBLE_PUSH` and `DATA: invalid padding` are npns's own h2
error strings, and the console's ClientHello offers `alpn=[http/1.1 h2]`. Our TLS
terminator must negotiate h2 rather than fall back, and must not send a SETTINGS frame
the client rejects. Worth asserting in the router test rather than assuming Go's default.

## 5. Message vocabulary we have, and the two gates we have not observed

`internal/penne`'s union table already covers the recovered names. Two of them are
lifecycle gates we have never seen exercised, and `subscriptions: 0` in the metrics says
the console has not subscribed to anything yet:

- `SubscriptionListRequest` → `SubscriptionList`: the client asking what it is subscribed to.
- `SyncComplete`: the end of the initial sync.

If the console waits for either before it will accept pushed messages, delivery cannot
work no matter how well an event is addressed. Error names to expect if we get it wrong:
`InvalidSequence`, `UnexpectedAck`, `InconsistentAck`, `AckTimedout`, `ValidationFailed`,
`ProtocolVersionError`, `WarmupTimedout`, `KickedBy*`.

## 6. Friend-list fields we still do not send

From the list parser's own JSON paths [friends strings]:

| Path | Us |
| --- | --- |
| `$.items[*].friend.presence.pf` | **missing** — a number, semantics unknown (platform?). Do not guess a value; capture one. |
| `$.items[*].friend.presence.extras.friends.appInfo:acdIndex` | **missing** — we send `appField`, `appInfo:appId`, `appInfo:presenceGroupId` |
| `$.items[*].friendNote` | **missing** |
| `$.items[*].friend.presence.{state,updatedAt,logoutAt}` | sent |
| `$.items[*].{friendId,isFavorite,createdAt}`, `friend.{nickname,thumbnailUrl}` | sent |
| `$.items[*].extras.self.{isConfirmed,isOnlineNotification}` | sent (SOC-02) |

The request box always asks with `filter.state.$eq=PENDING`
[`https://%s/2.0.0/users/%016llx/friend_requests/inbox?...`]; confirm settled records
cannot leak into it now that answered requests are retained for a week.

## 7. `/v1/apps/<appId>/catalog.json` — the title art behind presence

`https://%s/v1/apps/%016llx%016llx/catalog.json` and `https://%s/v1/apps/%016llx%016llx/%s.jpg`
are fetched by the friends module itself. Nothing of ours serves them, so a friend shown
as PLAYING has no title name or icon to render. Small, self-contained, and independent of
the notification work.

## 8. eShop: two hosts and a search endpoint we do not serve

From `nim/strings.txt`:

- `https://pearljam.hac.%.eshop.nintendo.net/civil` and `/sugar` — unserved entirely.
  Purpose unknown; they are the only eShop hosts in NIM besides dragons/tigers.
- `/v1/acds/search` — ACD search, unserved.
- Unserved NIM paths worth triaging against the chosen store journey:
  `/v1/accounts/in-same-family?accountIds=`, `/v1/accounts/vphyms`,
  `/v1/accounts/vphym-borrowers/candidates`, `/v1/nearness-checks[/prune]`,
  `/v1/devices/redeemed_status`, `/v1/devices/initialize`, `/v1/devices/target/{set,clear}`,
  `/v1/system_update_meta?device_id=`, `/v5/policy.json?context=`, `/v1/direct-messages`,
  `/v1/accounts/notify[-to-family]`, `/v1/a/%016llx/dv`.
- Served already: dragons rights/elicenses, tigers `/v1/etickets/publish` (501 by design),
  beach device links and `digital_bundle`, `bugyo` (the applet host, confirmed in
  `offlineWeb` at `0x8301fc` beside `OfflineWebApplet`), vermillion `accounts/config`.

The eticket gate is unchanged: `/v1/etickets/publish` is the one thing we cannot mint,
and it stays a recorded 501 rather than a fake success.

## Order I would take these

1. §1 — without the account id nothing else in the notification path can work.
2. §2 and §3 — cheap, and both are plain contract mismatches.
3. §5 — the subscription/sync gates, which need one live capture to settle.
4. §6 and §7 — list fidelity, independent of notifications.
5. §8 — store surface triage, after the friend journey closes.

---

# Second pass, same day: what the modules read that we still do not send

Tooling note: Ghidra is not installed on this workstation (the audit's `.gpr`
projects have no tool to open them), so this pass used capstone over
`main.elf` — an ADRP/ADD xref index, a BL call graph, and targeted
disassembly. Addresses below are ELF virtual addresses; Ghidra's are +0x100000.

## 9. The friend-list sync is not throttled — it is untriggered

`nn.friends` reads four values from the **`friends` system-settings section**
(`GetSettingsItemValue` at `0xef050`, section string `0x10e351`):

| Key | Default (from the module's own data) |
| --- | --- |
| `cooldown_time_for_sync_friend_list` | **30 s** (`0x15ea80` = 30,000,000,000 ns) |
| `cooldown_time_for_update_friend_request_count` | 3600 s |
| `cooldown_time_for_update_friend_invitation_count` | 3600 s (`0x15ea88`) |
| `retry_interval_while_sleeping` | read at `0x8f360` |

The list-sync cooldown is a *minimum interval*, and its default is half a
minute. So the sender's console is not rate-limited out of refreshing for
hours: it is willing to sync every 30 seconds and simply never gets asked.
That removes the last alternative explanation for J1's missing half and leaves
notification delivery as the single cause. The two count cooldowns being an
hour explains the slow badge refresh we see in traces.

## 10. Fields the modules parse that we now send

Each is named by a firmware string, not inferred:

| Field | Where | Was |
| --- | --- | --- |
| `$.items[*].friendNote` | friend-list entries | absent |
| `$.items[*].targetUser.{nickname,thumbnailUrl}` | `relationships/<id>` reply | only `targetUserId` |
| `$.summary.nintendo.hasMembership` | `api.accounts…/2.0.0/users/me` | absent — nn.account reads it at `0x18000a`, and capi's `/memberships` already answers "active" |
| `$.content_size`, `$.partitioned_content_hashes[%d]`, `$.partitioning_size` | atum `/d` manifest | `size` and `hashes`, which were this repo's own guesses and NIM reads neither |
| `$.available_elicenses[%u].account_id`, `.come_back_after` | dragons rights | absent |
| `$.original_count` | invitation inbox | absent |

`digest_algorithm_for_partitioned_content`, `available_elicenses[].eticket_id`
and `.release_date` are read by NIM too, but their value spaces are not
recovered and an eticket cannot be minted, so they stay absent rather than
invented.

## 11. Still missing, with the evidence and why they are not done

- `$.items[*].friend.presence.pf` — a number the list's numeric parser reads.
  Value space unknown; a capture settles it. Guessing a platform id here would
  be inventing a wire value.
- `presence.extras.friends.appInfo:acdIndex` — we send `appField`,
  `appInfo:appId` and `appInfo:presenceGroupId` but have no ACD index to put
  in it; the index is a catalog concept we do not model yet.
- The `route:*` extras (`route:name`, `route:name:language`,
  `route:nnid:miiName`, `route:nnid:miiImageUrlParam`, `route:appInfo:*`,
  `route:candidate:catalogId`) on `extras.self`, `extras.sender` and
  `extras.senderAndReceiver` — render data for requests and invitations.
- `mii_image_url_param` on search results, `enable_icons[*]`,
  `application_names.*`, `catalog_id` — Mii/title art we do not serve.
- `client.applicationId`, `client.catalogId`, `clientFriend.nickname`,
  `clientUser.nickname`, `requestedClientFriendId` — the friend-recommendation
  surface, which we answer as an empty success.
- `/v1/apps/<appId>/catalog.json` and `/v1/apps/<appId>/<name>.jpg` — fetched
  by the friends module itself for title art behind presence. Unserved.

## 12. eShop surface the modules reach and we do not answer

- `pearljam.hac.<env>.eshop.nintendo.net/civil` and `/sugar` — the only eShop
  hosts in NIM besides dragons and tigers. Unserved, purpose unrecovered.
- `/v1/acds/search`; `/v1/accounts/in-same-family?accountIds=`;
  `/v1/accounts/vphyms` and `/v1/accounts/vphym-borrowers/candidates`
  (family lending — the module parses a full `candidates[*]` shape including
  `networkServiceAccount.{nsaId,nickname,thumbnailUrl}`, `borrowingLimit`,
  `linkedDeviceCount`); `/v1/nearness-checks[/prune]` (with `rttUpperLimit`
  and `srcDevice.appearance.*`); `/v1/devices/redeemed_status`;
  `/v1/devices/initialize`; `/v1/devices/target/{set,clear}`;
  `/v1/system_update_meta?device_id=`; `/v5/policy.json?context=`;
  `/v1/direct-messages`; `/v1/accounts/notify[-to-family]`; `/v1/a/<id>/dv`.
- What a real eticket response carries, from NIM's parser:
  `cert_chain[%u]`, `common_key_generation` / `commonKeyGeneration`,
  `signing_key`, `payload`, `payload_key_iv`, `wrapped_payload_key`. This is
  the shape `/v1/etickets/publish` would have to produce — and the reason it
  answers 501 instead of pretending.

## 13. Where the Penne receive path investigation stands

The frontline transfer's curl callbacks are `0xb5530` (READFUNCTION, request
body) and `0xb55b0` (WRITEFUNCTION, response), registered from the option
table at `0x16b208`/`0x16b210`. The body producer is a scatter-gather object
(`0xb9560` copy-out, `0xb9630` "finished") built with **no segments** at
connect, which is what makes the connection downlink-only (§2 of
`docs/penne-protocol.md`). The response consumer is attached to the transfer
at `+0x28` by the setter at `0xb6ef0`, reached through `0xb69d0` from both
`0xb5460` and the write callback's own `0xb6880`.

**Open, and the next concrete step:** which consumer class the frontline
transfer installs. That object's feed method is the server→client parser, and
its first bytes-handling decides whether our four-byte length prefix is right.

---

# 14. Unserved surfaces: what is now answered, and what is still missing

Policy applied here: a route a firmware module can ask for gets an answer, and
the answer is either true or clearly refused. An empty collection is a true
answer to "what do I have?". Where a reply would have to carry invented
semantics — a licence, an entitlement, a signed anything — the request is
recorded and refused, because a plausible lie is worse than a clear no.

## Now answered (`nx-baas/eshop_unserved.go`)

| Route | Answer | Why that answer |
| --- | --- | --- |
| `/v1/accounts/vphyms` | `{"vphyms": []}` | OpenPak has no virtual cards |
| `/v1/accounts/vphym-borrowers/candidates` | `{"candidates": []}` | nobody can lend |
| `/v1/accounts/in-same-family` | `{"inSameFamily": false}` | no family groups exist |
| `/v1/nearness-checks`, `/prune` | `{"nearnessChecks": []}` | nothing brokers device-to-device transfer |
| `/v1/devices/redeemed_status` | `{"redeemed": false}` | nothing has been redeemed |
| `/v1/devices/target/{set,clear}` | 200 | accepted; no download targeting implemented |
| `/v1/system_update_meta` | `{"system_update_metas": []}` | **"you are current"** — we serve no system images and must never point a console at an update it cannot get |
| `/v1/direct-messages` | `{"messages": [], "count": 0}` | nothing produces store messages |
| `/v1/accounts/notify[-to-family]` | 200 | accepted; nothing to fan out |
| `/v1/acds/search` | **the shop catalog**, filtered by `q` | the console is asking what this store has, and this store knows; the ACD document's native field names are unrecovered, so the entries use our catalog's own vocabulary |
| `/v1/apps/<appId>/catalog.json` | **the title's real name, localized names, publisher and version** from the shop catalog; an empty name map for a title we do not carry | the friends module fetches this itself for the title behind a friend's presence. The 128-bit application id's upper half is the catalog's 64-bit title id |
| `/v1/apps/<appId>/<name>.jpg` | **the title's own icon**, or the shop's neutral mark when we have none | so a friend shown as PLAYING renders the game rather than a gap |
| `pearljam…/civil`, `/sugar` | 404 with a pointer to this document, full request dumped | the only eShop endpoints in NIM whose contract is entirely unrecovered — the first console to ask writes the spec for us |

`pearljam.hac.lp1.eshop.nintendo.net` is also on the fixed TLS certificate now.
DNS needs nothing: `SSSL_DNS_DEFAULT_ADDRESS` already points every name at the
box, so an unknown host reaches us and is logged rather than failing to resolve.

## Still missing, and not stubbable

- **The Penne record store.** Notifications are records (§4d), so delivery
  needs a store per account and namespace (`c-appearance`, `c-friends`,
  `c-settings`, `c-storage`), the digests that make `RootHash` truthful, and
  `PutRecord`/`DeleteRecord` to move them. Today the adapter mirrors the
  console's digests to reach the steady state and **holds** every event instead
  of sending it. This is the one piece between us and a friend list that
  refreshes itself.
- **The `PutRecord` payload shape.** Known: it carries a name and a payload,
  stored by `0x1dc430` and announced by `0x1d0840`. The slot numbers are not
  recovered; the console's own record messages will give them, the same way its
  `RootHash` gave us the envelope.
- **An ES-trusted eticket.** `tigers /v1/etickets/publish` stays a recorded 501.
  NIM's parser tells us the shape it wants (`cert_chain`, `common_key_generation`,
  `signing_key`, `payload`, `payload_key_iv`, `wrapped_payload_key`) and that is
  precisely the thing we cannot mint.
- **`presence.pf`** and the `route:*` render extras: read by the friends module,
  values unrecovered. Emitting a guess would be inventing a wire value.

---

# 15. Presence, notifications, activity and recommendations, from the module

## Presence: what the console publishes, and in what types

The friends module PATCHes its own device account with these paths [firmware,
friends strings]:

```
/presence/state
/presence/extras/friends/appField
/presence/extras/friends/appInfo:appId
/presence/extras/friends/appInfo:acdIndex
/presence/extras/friends/appInfo:presenceGroupId
/permissions/presence
```

and it builds the JSON itself with these fragments, which fix the **types**:

```
"appInfo:appId":"%016llx",          — a quoted 16-hex string
"appInfo:acdIndex":%d,              — a NUMBER, not a string
"appInfo:presenceGroupId":"%016llx" — a quoted 16-hex string
```

`acdIndex` was on the "missing, do not guess" list in §11. It does not need
guessing: **the console publishes it**, so the adapter now stores what it sends
and echoes it back to that account's friends, and sends nothing when the
console sent nothing. States seen in the module: `ONLINE`, `PLAYING`,
`INACTIVE`, `OFFLINE`.

Still unrecovered: `friend.presence.pf`, which is read but never published in
any string we can find — it is likely set from something other than the
console's own PATCH.

## Friend activity: the play-history document

A root-level JSON array, one entry per title [firmware, `$[*]` paths]:

```
$[*].appInfo:appId, $[*].appInfo:acdIndex, $[*].appInfo:presenceGroupId,
$[*].firstPlayedAt, $[*].lastPlayedAt, $[*].totalPlayCount, $[*].totalPlayTime
```

That is what a friend's "recently played" is made of: per-title first and last
played timestamps, a play count and total play time. **No URL for it appears in
the module's strings**, so the endpoint that serves it is not yet known — the
document shape is, which is half the work. `playLog` (the `extras.*.playLog`
permission we already emit) is the visibility switch over it.

## Notifications: the five event parsers

Each event kind has its own parser object with a required-field mask, and the
dispatcher (`0xa15c0`) routes by type string before handing the body over:

| Event | Handler | Parser |
| --- | --- | --- |
| `presence_updated` | `0xa1790` | `0xa7460` |
| `friend_invitation_received` | `0xa19a0` | `0xa97c0` (mask `0x2f`) |
| `friend_request_received` | `0xa1ad0` | `0xa9c60` |
| `friend_request_authorized` | `0xa1bb0` | — (no body needed) |
| `friend_deleted` | `0xa1c60` | — (no body needed) |

The last two take no payload beyond the account the record arrived for, which
is consistent with what they do: both simply refresh. **That is worth stating
plainly — `friend_request_authorized` and `friend_deleted` need no body at
all**, so the events behind a friend list refreshing itself cannot be got wrong
by sending the wrong fields.

The other two parse bodies whose paths are now recovered in full:

**`presence_updated`** [parser `0xa7510`]:

```jsonc
{ "type": "presence_updated",
  "createdAt": <number>,            // camelCase here
  "value": {
    "userId": "<16 hex>",
    "state": "ONLINE|PLAYING|INACTIVE|OFFLINE",
    "updatedAt": <number>, "logoutAt": <number>,
    "pf": <byte>,                   // still unrecovered in meaning
    "channels": ["…"],
    "extras": { "friends": {
      "appField": "…",
      "appInfo:appId": "<16 hex>",          // string
      "appInfo:acdIndex": <number>,         // number
      "appInfo:presenceGroupId": "<16 hex>" // string
    } } } }
```

**`friend_invitation_received`** [parser `0xa9870`, `0xa99ec`]:

```jsonc
{ "type": "friend_invitation_received",
  "created_at": <number>,           // snake_case here
  "unread_count": <number>,
  "invitation": { "id": <number>, "invitation_group_id": <number>,
                  "application_id": "…", "sender_id": "…" } }
```

The casing differs per event because each follows its own REST surface —
friends is camelCase, invitations is snake_case. Both are implemented:
presence events now nest under `$.value` with the app fields in the types the
console publishes them in, and the invitation event carries its `created_at`.

## Recommendations

`GET /v1/friend_recommendations?id_token=<token>&type=nintendo_account` (and a
`&type=%s` variant). The response is the `items[*]` shape whose unserved fields
were listed in §11: `client.applicationId`, `client.catalogId`,
`clientFriend.nickname`, `clientUser.nickname`, `requestedClientFriendId`,
`nickname`, `thumbnailUrl`, `mii_image_url_param`. We answer it as an empty
success today, which is honest — OpenPak has no recommendation source — and the
shape is now recorded for whenever it has one.


---

# 16. Game invitations, as the console sends them

Mapping each invitation URL to the function that builds it [friends module]:

| Call | Built at | Shape |
| --- | --- | --- |
| `POST /v2/invitation_groups` | `0x1e0230` | `Content-Type: application/json`, `Expect:` cleared |
| `GET /v1/invitation_groups/<id>` | `0x1de060` | group detail |
| **`PATCH /v1/invitations`** | `0x1e24b0` | **`Content-Type: application/x-www-form-urlencoded`**, body **`read=true&ids=<id>%2C<id>…`** |
| `GET /v2/users/<uid>/invitations/inbox` | — | `?invitation_types=friend`, and a `fields=count&read=false` count-only form |
| `PATCH /v1/users/<uid>/invitations/mark_as_read` | — | the documented per-user call |

The third row is the one that mattered: this adapter answered `PATCH
/v1/invitations` only as a **JSON patch**, the shape the wiki documents, so a
real console marking an invitation read would have been told
`invalid_params` — its unread badge would never clear. The body prefix is
assembled inline in the module (`"read=true&ids="`, then the ids joined with an
encoded comma), which is as unambiguous as this gets.

Both shapes are accepted now. `read=false` is refused rather than pretended:
nothing in the module sends it, and unread is not a state this store can return
to.

Two more fields the module reads off an inbox item — `receiver_id` and
`extras.receiver.read` — are sent as of the same pass; `acd_index`,
`application_id_match`, `application_data` and `messages.<lang>` were already
implemented from the create call.

---

# 17. Online-play invitations, mapped end to end

Everything below is from the friends module itself: the URL builders, the JSON
the console writes, and the paths its parsers read back. Addresses are ELF
virtual (Ghidra +0x100000).

## The calls

| # | Call | Built at | Content type |
| --- | --- | --- | --- |
| 1 | `POST /v2/invitation_groups` (also `/v1`) | `0x1e0230` | `application/json`, `Expect:` cleared |
| 2 | `GET /v1/invitation_groups/<groupId>` | `0x1de060` | — |
| 3 | `PATCH /v1/invitations` | `0x1e24b0` | `application/x-www-form-urlencoded` |
| 4 | `GET /v2/users/<uid>/invitations/inbox?invitation_types=friend` | — | — |
| 5 | `GET …/inbox?fields=count&read=false&invitation_types=friend` | — | count only |
| 6 | `PATCH /v1/users/<uid>/invitations/mark_as_read` | — | per-user form |

## 1. What the console sends to create a group

Body keys, all written by `0x1e03d0`:

```jsonc
{ "receiver_ids": ["%016llx", …],   // the friends being invited
  "invitation_type": "friend",
  "application_id": "%016llx",
  "application_group_id": "…",
  "application_id_match": <bool>,
  "acd_index": <number>,
  "application_data": "<opaque, base64>",
  "messages": { "<lang>": "…" } }
```

The language set is exactly sixteen, and they are the keys the module emits:
`en-US, en-GB, es-419, fr-CA, pt-BR, zh-Hans, zh-Hant, fr, es, it, de, ru, pt,
nl, ko, ja`. Our `invitationMaxMessages = 16` matches by luck; it is now
matched by evidence.

**Every one of these is already accepted and stored** (`invitationCreateIn`).

## 2. What it reads back

From the create/detail response: `$.id`, and `$.invitations[]` whose entries
carry `$.invitations[*].receiver_id`. We answer with exactly `{id, receiver_id}`
per entry beside the group's own fields.

## 3. Marking read — the shape that was wrong

`PATCH /v1/invitations`, body **`read=true&ids=<id>%2C<id>…`**, the prefix
assembled inline in the module. We accepted only the JSON-patch form until
v0.12.23, so a console clearing its badge was answered `invalid_params`.
Both are accepted now; `read=false` is refused rather than faked.

## 4. The inbox item

| Field | Us |
| --- | --- |
| `id`, `invitation_group_id`, `sender_id` | sent |
| `receiver_id` | sent (added this pass) |
| `application_id`, `application_group_id`, `application_data` | sent |
| `application_id_match`, `acd_index` | sent when the sender supplied them |
| `messages.<lang>` | sent |
| `read`, `created_at`, `updated_at` | sent |
| `extras.receiver.read` | sent (added this pass) |
| `invitation_type` | sent |
| **`channels[0]` / `channels.*`** | **not sent** — the value space is unrecovered, and an invented channel name is worse than an absent one |

Both query forms are honoured: `invitation_types` (anything but `friend`
answers empty), `read=false` for unread-only, and `fields=count` for the
count-only reply that the badge polls.

## 5. The notification

`friend_invitation_received`, parsed by `0xa9870` / `0xa99ec`:
`$.created_at`, `$.unread_count`, `$.invitation.{id, invitation_group_id,
application_id, sender_id}` — all sent (§15).

## 6. What is left, and where it lives

- **`channels`** — read, never written by the module in any string we can find.
- **`application_id_match`** — carried verbatim; its meaning (does the
  receiver's running title have to match?) is the console's business, not ours.
- **The join itself** — once an invitation is in the inbox, entering the game
  is IPC between the friends module, the applet and the title, using
  `application_data` as an opaque blob. **Nothing more is asked of the server**:
  our obligation ends at storing and returning those bytes unchanged, which is
  what the create/inbox path does. INV-04's "explicit join" gate is therefore a
  console-side test, not a server feature we are missing.

---

# 18. The shop applet's JavaScript bridge

`offlineWeb` — the module behind `bugyo`, the shop applet host — exposes an API
to the page it renders. The page *is* the storefront, so this is the contract a
native OpenPak store has to drive, and none of it was written down before.

Bridge roots: `window.nx.shop`, `window.nx.system`, `window.nx.footer`,
`window.nx.imageViewer`, `window.nx.videoPlayer`, plus `window.nx.EventTarget`
and `window.nx.dispatchEvent` for events.

Methods, grouped by what they are for (255 bridge-shaped names in total; these
are the ones that matter to us):

| Group | Methods |
| --- | --- |
| Tokens | `requestNaIdToken`, `requestNaTokenForProfile`, `requestEdgeToken`, `requestUpdateNsaIdTokenCache`, `startToGetToken`, `setNsaIdTokenAvailableCallback`, `setDeviceAuthTokenAvailableCallback` |
| Account | `getAccountNickname`, `getAccountCountry`, `getAccountBirthday`, `getNintendoAccountIdsOnDevice`, `getAccountIdentificationTiming`, `isPinCodeSetForAccountIdentification` |
| Rights and devices | **`requestSyncRights`**, `requestLinkDevice`, `requestUnlinkDevice` |
| Content and installs | `getApplicationContentMetaStatusArray`, `hasApplicationRecord`, `requestDownloadTaskListOnEnd`, `requestCleanupPreInstalledApplication`, `requestCleanupAllPreInstalledApplications`, `requestUpdateCheckInfo` |
| Virtual game cards | `requestEnableVgcContents`, `requestDisableVgcContents`, `isVgcContentsDisabled` |
| Storage | `getFreeSizeNand`, `getTotalSizeNand` |
| Launching and joining | **`requestToPlay`**, **`requestToJoin`**, `requestToJoinInAdvance`, `requestToResume`, `requestToSuspend`, `requestWakeUp`, `isAnyApplicationRunning` |
| Play activity | **`getFriendPlayLog`**, `getPlayLog` |

Three of these change how open PRD gates should be read:

- **`requestSyncRights`** is a *page* call, not a server one. SHP-03's "rights
  sync pending hardware" is waiting on a storefront page that calls this — the
  server side of it (dragons elicenses) is already answered.
- **`requestToJoin` / `requestToPlay`** are how a page enters a title. The
  invitation join path (INV-04) therefore also ends in the applet, not at an
  endpoint we serve, which matches §17.
- **`getFriendPlayLog`** is the consumer of the play-history document (§15,
  F1). The console builds that JSON itself and hands it to the page, so a
  friend's play log reaches the applet through the bridge — and the only way it
  can reach the console from us is as a record.

Nothing here is a server contract: it is the shape of the client we have to
write against. Written down so the store workstream stops guessing what the
page may call.

---

# 19. Account setup, records, and where a play log is rendered

## Three account routes the console calls and we 404'd

From the account module's own URL table:

| Route | Evidence | Now |
| --- | --- | --- |
| `/connect/1.0.0/term_confirm` (also `/1.0.0/…`) | `0x181077`, form-encoded with `id_token`, `idToken`, `userId` | **answered 200** — there are no terms to accept on a private network, and `users/me` already reports the EULA and privacy policy agreed, so confirming is what keeps account setup moving |
| `/connect/1.0.0/api/term_agreement_token` | `0x181580`, with `$.challenge_src` and `$.errorCode` read nearby | recorded and refused: the document it returns is not recovered, and a token is not a thing to invent |
| `/…/api/transfer_na_tokens[_inherit|/<id>]` | `0x17d920` | refused plainly — this server has no transfer flow, and half-answering one risks an account that exists in two places |

The account module's error vocabulary is also worth having when we need to
answer a failure the console will recognise: `invalid_device_account`,
`invalid_device_certificate`, `account_id_required`, `consent_required`,
`interaction_required`, `id_token_hint_invalid`, `could_not_confirm_membership`,
`edge_token_not_grantable`, `invalid_eticket_template`.

## A record's document shape, confirmed

`ns` reads, right beside the literal `c-storage.summary`:

```jsonc
{ "key":  { "id": …, "type": …, "ownerNaId": …, "userNaId": … },
  "data": { "naId": …, "applicationId": …, "applicationIdList": …,
            "borrowerNaId": …, "ownerNaId": …, "stateUpdates": …,
            "quickResponse": …, "reason": …, "error": …, "errorInfoList": … } }
```

So a record's value is a `{key, data}` document **for the storage topics** —
the `ownerNaId`/`borrowerNaId` pair is virtual-game-card lending. The friends
topic is different: its dispatcher reads `$.type` at the document root, which
is what we write. Worth knowing that the value shape is per topic rather than
universal.

## Where a friend's play log is rendered

`mypage` — the profile applet — carries the UI for it: `SceneFrdCntPlayHistoryList`,
`FrdPlayHistory`, `RecentlyPlayed`, plus the owner's own controls
(`ChangePlayLogPermission`, `ClearPlayLog`, `PlayLogStartDay/Hour/Minute`).

That closes the chain for F1 without a capture: the friends module **builds**
the play-history JSON (§15), the shop/offline-web bridge exposes
`getFriendPlayLog` to a page (§18), and the profile applet renders a friend's
history from it. No HTTP endpoint appears anywhere in any of the three, which
leaves the record sync as the only way a *friend's* log can reach the console.

---

# 20. The News channel, mapped

## What the console actually asks for

From production traffic and the news workstream's own 2026-09-07 capture
(`news/docs/native-news-catchall.md`), the console's News surface is four
routes across two hosts, with `nnNews`/`nnBcat` user agents:

| Host | Path | Parameters |
| --- | --- | --- |
| `bcat-topics-lp1.cdn.nintendo.net` | `/api/nx/v1/topics/catalog` | `l=en-GB`, `c[]=GB` (twice) |
| `bcat-topics-lp1.cdn.nintendo.net` | `/api/nx/v1/titles/<titleId>/topics` | `c[]=GB` |
| `bcat-list-lp1.cdn.nintendo.net` | `/api/nx/v1/list/nx_news_<feed>` | — |
| `bcat-list-lp1.cdn.nintendo.net` | `/api/nx/v1/list/nx_data_<titleId>` | — |

Live in the last two days, the console asked for per-title topics for
`0100000000001000` (the News applet itself) and `01008c9014694000` (a game's
own channel).

## Where those requests land today

Traefik routes `bcat-topics-lp1` to the news service (`news-experiment`,
priority 1000, TLS passthrough). That service logs
**`unhandled news route … /api/nx/v1/titles/<id>/topics`** and the request
falls through to nx-baas, which answers `{"topics":[]}`.

So there is a **path mismatch**: the news service implements
`/api/nx/v1/topics/{catalog,<channel>/detail,<channel>/icon,<id>/article}`,
and the console asks for `/api/nx/v1/titles/<titleId>/topics` and
`/api/nx/v1/list/…`. Nothing is broken — an empty topic list is a valid "no
news" — but no news can reach a console through the routes we implement.

## The part that needs a module we have not dumped

Delivering an actual article is not a JSON problem. The console pulls content
through the **BCAT delivery cache**, whose IPC surface `ns` merely proxies:
`IBcatService`, `IServiceCreator`, `INotifierService`,
`IDeliveryCacheStorageService`, `IDeliveryCacheDirectoryService`,
`IDeliveryCacheFileService`, `IDeliveryCacheProgressService`,
`IDeliveryTaskSuspensionService`. The container format and whatever signature
it carries live in the **bcat sysmodule**, and the audit tree did not contain
it when this was written: fifteen modules were dumped, and `bcat`
(`0x010000000000000c`) and the News applet (`0x0100000000001000`) were not. Both
are dumped now — §21.

`ns` does carry the settings that gate it: `bcat_enabled`,
`auto_update_policy_from_bcat_enabled`, `acceptable_application_delivery_protocol_version`,
`system_delivery_info_id`, `delivery_info_platform`, `delivery_protocol_version`.

**Done:** both modules are extracted and mined — see §21, which answers this.
The delivery-cache container is still unbuilt, but it turns out not to be on the
path to "there is no news": the list document says that on its own.

## 21. News and BCAT, from the modules themselves

Both missing modules are dumped now (`hactool` + `~/REPOS/nx2elf`, the way the
other fifteen were), and they answer W1 and W2 outright:

| Title | Module | What it holds |
| --- | --- | --- |
| `0x010000000000000c` | `bcat` sysmodule | the whole network contract: BCAT **and** the News channel, one binary, `nn.bcat.*` and `nn.news.*` |
| `0x0100000000001000` | qlaunch (Home Menu) | the News **UI** only — no news hosts of its own; it reaches the sysmodule over IPC |

The News channel is not a separate service. It is BCAT with a different mount
prefix (`news-dl:` / `news-sys:` instead of `bcat-dl:` / `bcat-sys:`) and an
sqlite database on top.

### 21a. The four hosts

`%` in a firmware hostname is the environment identifier the module substitutes
(`lp1` on retail), the same convention as `api.hac.%.ctest…`.

| Host | Used for |
| --- | --- |
| `bcat-list-%.cdn.nintendo.net` | the data list, per title and for news |
| `bcat-topics-%.cdn.nintendo.net` | the per-title topic document |
| `fw-api.%.nso.nintendo.net` | `/v1/events` — the NSO event/overlay feed |
| `receive-%.dg.srv.nintendo.net`, `realtime-receive-%.dg.srv.nintendo.net` | prepo (play reports), same binary, see §21f |

All of them already resolve here: the console DNS is a catch-all for
`.nintendo.net` (`nn-sssl-dns`), and unrouted SNIs get an on-demand
certificate. What was missing was the server, not the name.

### 21b. The three routes

```
GET https://bcat-topics-<env>.cdn.nintendo.net/api/nx/v1/titles/<tid:%016llx>/topics[?l=<lang>&c[]=<country>]
GET https://bcat-list-<env>.cdn.nintendo.net/api/nx/v1/list/nx_data_<tid:%016llx>[?u=<uuid>&i=<40 hex>]
GET https://<host from the push>/api/nx/v1/list/<key>[?l=<lang>[&<news id>]]
```

- The list path segment is **not** the raw title id: `FUN_0019f390` formats it
  as `nx_data_%016llx`.
- The query is assembled piecewise — `"?"` is only prepended when the query is
  non-empty (`FUN_00214ed0`, `FUN_00216e80`), so a bare URL with no `?` is a
  normal request, not a truncated one.
- `u=` is a UUID printed `%02x%02x%02x%02x-%02x%02x-…`; `i=` is a 20-byte
  digest printed as 40 hex characters (`FUN_00197fc0`, buffer `0x29`). Both
  appear only when the module is in one particular mode
  (`local_1e0 == 2 && (flags & 1)`), so their absence is expected on retail.
- The topics query shape is confirmed by a hardware capture from 2026-09-08:
  `?l=en-GB&c%5b%5d=GB` — `l=<language>` and `c[]=<country>`.

### 21c. The request

`FUN_001914d0` builds every BCAT/News HTTP request, and it is a plain
conditional GET:

| Header | Source |
| --- | --- |
| `If-None-Match: <etag>` | the etag stored in `<mount>:/etag.bin` |
| `If-Range: <etag>` + `Range: bytes=<n>-` | resuming an interrupted file |
| `X-Nintendo-DenebEdgeToken: <token>` | only when one is held |
| `X-Nintendo-Serial-Number: <serial>` | always |
| User-Agent | `libcurl (nnBcat; 789f928b-138e-4b2f-afeb-1acae821d897; SDK 22.2.0.0)` |

There is **no `Authorization` header**. `news-sys:/passphrase.bin` and
`<mount>:/passphrase.bin` are not HTTP credentials — the curl Digest/Basic
strings in the binary are libcurl's own, unreferenced by this path.

Answers are **msgpack** (`Content-Type: application/x-msgpack`), stored as
`bcat-dl:/applications/%016llx/list.msgpack` and `news-dl:/list.msgpack`, each
beside a `.bafmeta` / `.meta` sidecar.

### 21d. The two documents

**Topic document** (`FUN_00215590` reads): `$.topic_id`, `$.na_required`,
`$.test_distribution`, `$.service_status`, `$.directories[0].data_list[]`.

**Data list** (`FUN_0019a010` reads): `$.required_application_version`,
`$.directories[*].{name,mode,digest}`, and per entry
`$.directories[*].data_list[*].{filename,url,size,digest,data_id}`. The News
variant addresses `$.directories[0]` explicitly and adds per-entry
`news_id`, `default_language`, `publishing_time`, `deletion_priority`,
`conditions.serial[*]`, `version.{format,semantics}` and
`languages[*].{language,url,size,data_id,overwrite}`.

`$.service_status` is a string: **`in_service`** is the only accepted value;
anything starting `exp…` (expired) reads as out of service.

**News item** (`FUN_00208450` reads, one msgpack document per article):
`news_id`, `topic_id`, `language`, `application_ids[*]`, `published_at`,
`expire_at`, `pickup_limit`, `essential_pickup.{pickup_limit,priority_after}`,
`priority`, `deletion_priority`, `age_limit`, `age_limits[*].ratings[*].{age,name}`,
`decoration.type`, `version.{format,semantics}`. It lands in
`news-sys:/news.v3.db` — a real sqlite database whose schema the module carries
verbatim, including the read/newly/displayed/feedback/reputation flags the UI
toggles.

### 21e. How a refresh is triggered — and why this is a Penne question

`bcat` opens **`npns:s`** (the NPNS system port) and runs
`nn.bcat.EventWatcher`. It does not subscribe to a `c-*` topic of its own —
`c-friends.inv.subsTypes`, `c-appearance.*`, `c-settings.LanguageCode` and
`c-storage.summary` are the only topic literals in any dumped module. It reads
pushes and switches on `$.type`:

| `$.type` | Payload | Effect |
| --- | --- | --- |
| `news` | `$.topic_id`, `$.revision`, `$.wait_range`, `$.ha_wait_range_min`, `$.ha_wait_range_max` | refresh that topic, jittered inside the wait range |
| `news_pickup` | `$.url` (≤256), `$.date` (≤20), `$.one2one` | fetch that list URL at that time; `one2one` routes it to a single user |

A third push shape (`FUN_001bd1b0`) is the on-screen overlay:
`$.notification_type`, `$.version`, `$.ovl_type`, `$.event_data_id`,
`$.nsa_id`, `$.application_id`, `$.expires_at`, `$.text` (≤150),
`$.text_scale`, `$.speech` (≤200), `$.jump_to`.

So **the News channel is downstream of the same Penne connection the friends
work is blocked on**: nothing can be delivered until a push reaches the
console. The route work in §21b is the second half, not the first.

### 21f. prepo, found in the same binary

The play-report uploader lives here too and is entirely unserved:

```
POST https://receive-<env>.dg.srv.nintendo.net/post
POST https://realtime-receive-<env>.dg.srv.nintendo.net/api/v1/realtime_reports
```

`Content-Type: application/x-msgpack`, headers `X-Nintendo-Nsa-Id-Token`,
`X-Nintendo-Device-Authentication-Token`, `X-Nintendo-Product-Model`,
`X-Nintendo-Environment`, UA `libcurl (nnPrepo; …; SDK 22.2.0.0; Add-on 22.2.0.0)`.
State in `prepo-sys:/{id,statistics,statistics_srepo,is_user_agreement_check_enabled}.bin`.

### 21g. The connection test, also unserved

`qlaunch`'s `nn::netdiag` names the whole Internet-connection-test surface:

```
GET  https://api.hac.<env>.ctest.srv.nintendo.net/v1/ip     (global IP)
GET  http://ctest-dl-<env>.cdn.nintendo.net/30m             (download speed)
POST http://ctest-ul-<env>.cdn.nintendo.net/1m              (upload speed)
     nncs1-<env>.n.n.srv.nintendo.net, nncs2-<env>.n.n.srv.nintendo.net  (NAT type)
```

The Switch NAT-check hosts are the same pair of services `nn-nncs` already
implements for Wii U, under different names.

### What is implemented now

`nx-baas/bcat.go` replaces the JSON guess with the real contract: both routes,
msgpack documents, `in_service`, empty directories, and an ETag so the second
poll is a 304. That is a true statement about this network — no BCAT container
is published and no article exists — in the encoding the module parses. The
delivery-cache container (W2) does not have to be built to say "nothing to
fetch"; it has to be built the day something is.

`nx-baas/netdiag.go` answers the other two surfaces §21f and §21g named:

- `/v1/ip` reports the address this server sees the console from (the forwarded
  one, since Traefik terminates). The JSON key is the one public research uses;
  the module's SAX handler did not yield it.
- `ctest-dl-…/30m` serves exactly 30 MiB with Range support, `ctest-ul-…/1m`
  accepts the upload. Both are plain HTTP, so they only work where port 80
  reaches this server.
- prepo accepts a play report and discards it. OpenPak keeps no telemetry, and
  refusing the upload only makes the console spool it and retry.

All six HTTPS names are on the fixed certificate now rather than minted on
demand, which is the lesson from 2123-0013.

`fw-api…/v1/events` is deliberately **not** implemented (W3): the URL, method
and auth are known, the body and reply are not, and a guessed shape would read
as a working feature.
