# Penne frontline protocol specification (minimum supported), v1

Status: implemented-against. Supersedes: nothing. Date: 2026-09-11.
Scope: the persistent notification connection ("frontline") of Penne/NPNS on
Horizon 22.5.0, plus the REST registration surfaces that feed it. This document
is the protocol gate required by `prds/native-switch-penne-notifications-prd.md`
(NTF-02): no native delivery is claimed beyond what is stated here.

Every statement carries a provenance label:

- **[firmware]** — recovered from the Horizon 22.5.0 NPNS module
  (`010000000000002F`, NSO build ID `942e27bd…`) by static analysis. Working
  files live in the private analysis directory; no firmware content is
  committed. Module-relative RVAs below are +0 relative to the ELF's own
  addresses; the Ghidra projects load at base 0x100000.
- **[wire-spec]** — the public FlatBuffers wire format documentation.
- **[observed]** — captured console traffic from earlier hardware sessions
  (Fix_Experimental trace), as recorded in the repo docs.
- **[hypothesis]** — best-evidence inference, marked, never to be presented as
  interoperability until a runtime capture confirms it.

## 1. Registration REST surfaces [observed]

Hosts and response shapes are observed; the console bootstraps through them in
order and fails loudly (empty replies, wrong keys) when they deviate.

| Host | Route | Response (shape) |
| --- | --- | --- |
| `god.penne.srv.nintendo.net` | `POST /v1/penne_ids` | `{"id": "p…", "password": "…"}` |
| `god.penne.srv.nintendo.net` | `POST /v1/immigrate` | 404 (nothing to migrate) |
| `god.penne.srv.nintendo.net` | `…/notification_tokens` | `{"notification_token": "…"}` |
| `god.penne.srv.nintendo.net` | `…/links` | `{"nsa_id": "…"}` |
| `val.penne.srv.nintendo.net` | `POST /v1/frontlines` | `{current_time, frontline_fqdn, persistent_connection_params_simple}` |
| `val.penne.srv.nintendo.net` | `POST /v1/login_tickets` | `{ticket, issued_at, expires_at, frontline_fqdn, persistent_connection_params_simple}` |

`persistent_connection_params_simple` [observed]:
`awake/sleep: {count, idle, interval}`, `wait_sec`, `ignore_rst`, `retry_count`.
The firmware also requires `wowl_timeout`, `rtt_max`, and a `disable` boolean in
both awake and sleep settings [firmware, follow-up 2026-09-12]. NPNS RVA
`0xBF100` combines all seven child validation flags; `0xB8B50` requires the
result before accepting a login ticket. Omitting these fields fails validation.
The server now includes the defaults recovered from constructor RVA `0xB82E0`:
`wowl_timeout: 410`, `rtt_max: 300`, `awake.disable: false`, and
`sleep.disable: true`. These values are firmware defaults, not measured operating
limits. Hardware progression past login remains a separate verification gate.

This adapter's server-side semantics (beyond the shapes): registrations are
durable and device/account-bound; notification tokens and login tickets inherit
the binding; everything minted under a registration dies with it on revocation;
a supplied id authorizes nothing without its password [implementation, NTF-01].

**Open:** the request-side field names for `notification_tokens`,
`login_tickets` and `links`. Where a request carries no recognizable
credential, the adapter falls back to the device's newest association; this
fallback is provisional and a hardware capture should settle the real shapes.

## 2. Framing

- **Client → server:** the message routine passes a body reader of
  *four-byte little-endian length, then that many bytes of buffer* to the HTTP
  transport [firmware, send path around RVA `0xD4010`].
- **Server → client:** symmetric length-prefix framing is the working
  hypothesis [hypothesis]. The response is held open and streamed; whether the
  console's parser expects chunked transfer encoding around those frames is
  part of the same open question. The implementation sends
  `Transfer-Encoding: chunked` (hand-written after hijack) so both a
  chunk-aware and a raw reader have a defensible stream.
- Heartbeats: **no content-bearing keepalive is sent.** The newline heartbeat
  this implementation replaced was unvalidated [observed shape, unvalidated
  content], and any stray byte desyncs a length-prefixed decoder. The client's
  own `persistent_connection_params` drive its traffic; TCP keepalive is on.

## 3. Envelope and message slots

The envelope is a FlatBuffers table whose field 0 (first vtable slot) is the
one-byte union discriminator and whose field 1 is the union payload table
[firmware: the send path switches on slot 0 as a byte and dereferences slot 1
as an indirect table]. Table/vtable layout per [wire-spec]. Root fields ≥ 2 are
**not recovered**; nothing may assume them.

The union slot table was recovered from the message-name table at module
RVA `0x168968` [firmware]. Slot value = discriminator. The one slot the earlier
findings had pinned independently (`SubscribeTopic` = `0x17` = 23) matches,
which is what validates the table's interpretation.

| Slot | Name | Slot | Name |
| --- | --- | --- | --- |
| 0x00 | NONE | 0x14 | Idle |
| 0x01 | MessageRequest | 0x15 | PutRequest |
| 0x02 | PublishRequest | 0x16 | DeleteRequest |
| 0x03 | KickRequest | 0x17 | **SubscribeTopic** |
| 0x04 | PutRecord | 0x18 | Nack |
| 0x05 | DeleteRecord | 0x19 | SubscriptionList |
| 0x06 | RootHash | 0x1a | ResendRequest |
| 0x07 | LeafHash | 0x1b | DAPresence |
| 0x08 | SyncComplete | 0x1c | SubscriptionListRequest |
| 0x09 | Ack | 0x1d | MyAccountMessageRequest |
| 0x0a | HandoverRequest | 0x1e | ReloadLink |
| 0x0b | HandoverResponse | 0x1f | SubscriptionUpdated |
| 0x0c | HandoverResult | 0x20 | Hi |
| 0x0d | Reset | 0x21 | Onset |
| 0x0e | PowerState | 0x22 | PresenceNotifyRequest |
| 0x0f | DebugDisconnect | 0x23 | DenySubscribe |
| 0x10 | Ping | 0x24 | TopicRead |
| 0x11 | Pong | 0x25 | CrewNotifyRequest |
| 0x12 | DebugUpdateRecord | 0x13 | DebugDeleteRecord |

Recovered payload shapes (from the send path's per-type logging) — field
positions are vtable slot numbers; **positions, not semantics**, are what the
firmware shows:

- Ping (0x10): three uint64 fields [firmware].
- Pong (0x11): one uint64 [firmware]; echoing Ping's field 0 is [hypothesis].
- Hi (0x20), SyncComplete (0x08), SubscriptionListRequest (0x1c): logged with
  no payload fields [firmware].
- Ack (0x09), ResendRequest (0x1a), ReloadLink (0x1e), DebugDeleteRecord
  (0x13): one field each; scalar vs string not distinguished by the evidence
  [firmware shape, semantics open].
- SubscribeTopic (0x17): the client's builder formats the topic name as
  `%016llx` of a u64 — sixteen lowercase hex characters — when the topic id is
  numeric, plus a second string and boolean flags [firmware, builder at RVA
  `0xEAA10`]. Exact payload vtable slots: **open**. The caller tracks the
  `topic.subscription` operation with a **10-second** confirmation deadline
  [firmware, `0xDD980`], which is the one timeout in this protocol with
  evidence behind it.
- DAPresence (0x1b), Reset (0x0d), PowerState (0x0e), Nack (0x18),
  SubscriptionList (0x19), Onset (0x21), DenySubscribe (0x23), TopicRead
  (0x24), MyAccountMessageRequest (0x1d), SubscriptionUpdated (0x1f): partial
  shapes only [firmware]; see the decoder's field readers in
  `internal/penne`.
- Record-sync machinery (PutRecord/DeleteRecord/RootHash/LeafHash + vectors):
  present with vector-of-table payloads [firmware]; not implemented server-side.

## 4. What the server sends today, and why

| Message | Trigger | Evidence status |
| --- | --- | --- |
| Pong (echoing Ping f0) | inbound Ping | shape [firmware]; echo [hypothesis] |
| SubscriptionUpdated (unix second) | inbound SubscribeTopic | shape [firmware]; meaning of value + whether a reply is required within the 10 s deadline [hypothesis] |
| Hi (0x20), no payload, on connect | connection accepted | **[hypothesis]** — the console held a production connection open for 65 s and sent nothing (frames_in 0, subscriptions 0), so the server greets first; Hi is the slot named for an opening message and the module logs it with no payload fields [firmware]. The client's first frame settles it |
| Event (MessageRequest carrier, JSON string payload f0) | outbox delivery | **[hypothesis] end to end** — the carrier slot and payload field are candidates, chosen because the friends module's event parser demonstrably reads a JSON `type` field from somewhere in this path [firmware, friends module `0xA43B0`/`0xA15C0`], and MessageRequest/PublishRequest are the unplumbed slots |

The five native event kinds the dispatcher recognizes [firmware]:
`presence_updated`, `friend_invitation_received`, `friend_request_received`,
`friend_request_authorized`, `friend_deleted`. The server never invents other
kinds, never answers unknown slots, and never substitutes newline/JSON body
bytes for frames.


## 4a. Addressing: events must name a console account

The friends module's dispatcher (`0xA15C0`) matches the five event names and
calls one handler each. Every handler returns immediately unless the 128-bit
account id it was handed is non-zero — `friend_request_authorized` at
`0x1A1BB0`, `friend_deleted` at `0x1A1C60`, both guarded by
`if (*p != 0 || p[1] != 0)` on two 64-bit words copied from the notification
context at `+0x30`/`+0x38` [firmware, 2026-09-12]. The id arrives with the
message from the NPNS layer, not from the JSON body.

That id is the one the console itself puts in `/v1/accounts/%016llx%016llx/...`
[npns `0x120f4b`]. The adapter records it against the registration that
authenticated the call, and against a BAAS account when the same request proved
one (`NoteAccount`); it is never derived from a device certificate, because one
console holds several accounts and guessing which is which loses events.

**Open:** which field of which carrier puts that id on the wire. Until the
console subscribes to a topic — `subscriptions` is still 0 — the likeliest
mechanism is the topic a message is published to rather than a field in the
event frame, since the console's SubscribeTopic builder formats a topic as
`%016llx` of a u64 [firmware `0xEAA10`].

## 5. Connection lifecycle (implemented)

1. `POST https://<frontline>/` with `Authorization: Bearer <login ticket>`,
   `X-Protocol-Version: 4`, `X-Power-State`, `X-Hug`, `X-System-Version`,
   `X-Network-Type` [firmware header set at `0xD9250`].
2. Server validates the ticket: known, unrevoked, unexpired, device-matched.
   Any failure is a plain 401 before streaming; the console re-registers.
3. Server answers 200 `application/octet-stream`, held open.
4. Frames flow both ways. The server: decodes, counts unknowns, persists topic
   subscriptions, answers what §4 lists, pumps outbox deliveries.
5. On connect the server reconciles: queued, unexpired, unacknowledged
   deliveries are sent before new work; delivered ids are remembered 24 h so a
   reconnect does not re-alert. Delivery is **at-least-once**; deduplication is
   by event id at the recipient.
6. On silence: no invented keepalive bytes; the connection closes on error or
   cancellation, with the chunked terminator written when possible.

## 6. Transport notes (Go server specifics)

- Go's `net/http` server cannot stream a response while the client streams an
  unbounded request body: the first response flush synchronously drains up to
  256 KiB of the request body (`writeHeader` → `body.Close`). The NPNS shape is
  exactly that bidirectional stream, so the frontline handler **hijacks** the
  connection after authentication and carries the HTTP/1.1 chunked exchange by
  hand. [measured against Go 1.26's server, this repo's runtime]
- With TLS, the server's background read holds the `crypto/tls` mutex while
  waiting; a handler flush behind it blocks until the client's first body byte.
  The console speaks first (Hi/SubscribeTopic on connect), so this resolves
  naturally in production — but any proxy in the deployment path must tolerate
  a request body that stays open while the response streams.
- NX_DEBUG's logging wrapper must forward `http.Flusher` and `http.Hijacker`;
  it did neither before this workstream (the audit's reproduced P0).

## 7. Open questions and the next experiment

| # | Question | Blocking | Next reproducible experiment |
| --- | --- | --- | --- |
| 1 | Server→client framing (symmetric length prefixes? chunked? raw?) | native event delivery acceptance | One live capture: connect a 22.5.0 console to this server, log every response byte with SNI+timing; the client's decoder behavior on malformed input will also pin its tolerance |
| 2 | Event carrier slot (MessageRequest vs PublishRequest vs dedicated) and payload field | event envelope correctness | Same capture, plus Ghidra xref on the friends module's event parser entry to find where its input buffer originates |
| 3 | Ack correlation (what the client's Ack field references) | at-least-once → at-most-once tightening | Capture; alternatively server-side experiment: echo candidate ids and observe Acks |
| 4 | SubscribeTopic payload slots; whether SubscriptionUpdated is the expected confirmation inside 10 s | subscription lifecycle | Capture of one natural subscription; log and compare |
| 5 | REST request shapes (§1 open items) | strict authentication of registration | Capture of one clean bootstrap with the current server |
| 6 | Receive-side parser location in the NPNS module (would settle #1/#2 statically) | all of the above | Ghidra session: xref the `LeafHash/RootHash expected` format string (rodata RVA `0x12221e`) to the response-body decoder |

Failure posture until #1–#3 close: malformed or unknown inbound frames are
counted and never answered with invented schemas; outbound event frames are
well-formed per §3 and marked experimental. A console that rejects them closes
the connection — observable, recoverable, and exactly what the capture run
needs to see.
