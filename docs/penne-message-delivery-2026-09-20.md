# Why a kind-1 message is acked and then dropped (2026-09-20)

Clean-room notes: formats, offsets, control flow and field names only. No
firmware code is reproduced.

**Sources.** npns `010000000000002f` full decompile (`/tmp/ndump/all.c`),
friends `010000000000000e` (`/tmp/fdump/all.c`), plus the two production
samples of 2026-09-20 06:03:23 (`friend_deleted`) and 06:07:37
(`friend_request_received`), firmware 22.5.0, one real console, two profiles.

**Addresses** are Ghidra VAs (ELF VA + `0x100000`), the convention the other
docs in this directory use.

**Confidence tags.** **[firm]** = read directly out of the decompilation or a
log line. **[likely]** = one inference step. **[open]** = not settled.

---

## 0. Short answers

1. **The console's `Ack` field 0 is a STRING, not a u64, and our decoder has
   been misreading it.** `0xE00000004` is the 8 bytes at that slot read as one
   u64: low half `4` is the FlatBuffers uoffset to the string, high half `0xE`
   = 14 is the string's own length prefix — `len("friend_deleted")`. The second
   sample proves it: `0x1700000004`, and `len("friend_request_received")` = 23 =
   `0x17`. **[firm]**
2. **That `Ack` means "the PutRecord frame arrived and I read its entry's name".
   It is emitted before anything is known about delivery**, from a name buffer
   the `PutRecord` handler fills *after* the entry handler has already run and
   (in our case) already thrown the message away. It says nothing about a
   listener matching. **[firm]**
3. **The message is dropped inside npns' message parser because our `Meta`
   table has no slot 4.** For a message whose `type` (slot 1) is not `2`, the
   parser dereferences `Meta` vtable index 6 (slot 4) **with no vtable-size
   check and no zero check**. Our builder emits `Meta` with three slots
   (`StartTable(3)`), so that read runs off the end of the vtable, the wild
   string it lands on fails the `length ≤ 39` test, and the parser returns
   false. `FUN_001dc510` then logs and returns without ever calling the IPC
   hub. **This is the root cause.** **[firm]** for the unchecked read and the
   length test; **[likely]** that the garbage always fails the test rather than
   occasionally passing.
4. **The ~5–10 s reconnect is not our frame.** It is the console's own
   request-confirmation watchdog: every console→server request arms a flag and
   a **10-second** deadline, and the only frames that clear it are **`Ack`
   (0x09)** and **`Nack` (0x18)** carrying the exact string the request
   registered. nx-baas answers none of them with an `Ack`. On expiry the steady
   state calls the teardown with reason `4`, detail `0x200000000`. **[firm]**
5. **Nothing about topics, subscriptions or the sync gate is in the way.** The
   friends module does not subscribe to anything to receive events, the
   dispatcher never looks at the message name or at any topic, and the sync is
   already answered correctly. The gate is `Meta`, the account id, and the
   receiver token — nothing else. **[firm]**

---

## 1. How npns parses an incoming `PutRecord`

### 1.1 The envelope

Built and read symmetrically; the console's own builder is `0x1ed1a0`, whose
arguments map one-to-one onto vtable byte offsets (`4`=slot 0 … `0xc`=slot 4).
**[firm]**

| Slot | Type | Meaning | Required |
| --- | --- | --- | --- |
| 0 | `u8` | frame type (`4` = PutRecord) | yes |
| 1 | table | payload | yes |
| 2 | **string** | tag — the console writes `"NX"` | [likely] yes |
| 3 | `u64` | issued, unix seconds | [likely] |
| 4 | `u64` | expires, the console writes issued + `0xe10` (3600 s) | [likely] |

Slot 2 being a *string offset* is settled: `0x1ed1a0` is handed a string
offset for it and every console-side builder feeds it `CreateString("NX")`.
**[firm]**

### 1.2 `PutRecord` payload — `FUN_001dfbb0` (steady state, entered from
`FUN_001df030`, case 4 of `FUN_001dc9e0`)

```
PutRecord { 0: [Entry]   // MUST contain exactly one element
            1: u8 = 1 }  // present in the console's own frames; not read here
Entry     { 0: u8 kind   // 1 = message, 2 = stored record; anything else aborts
            1: → Message | Record }
```

Hard checks, in order **[firm]**:

- The connection's pending-ack-name flag (`conn+0x93a8`) must be **0** on
  entry, else fatal abort. In practice the steady state drains the ack before
  reading another frame, so this only bites a server that manages to get two
  PutRecords into one read.
- `Entry` vector length **must be exactly 1** — anything else is a fatal abort
  (`FUN_001062a0`). One message per frame; no batching.
- `Entry` slot 0 must be present and must be `1` or `2`; any other value is a
  fatal abort (`FUN_00106680`).

After the kind handler returns — **unconditionally, and without looking at
whether it succeeded** — `FUN_001dfbb0` reads slot 0 of the Message/Record
table, copies up to 48 bytes of it into `conn+0x93a9`, and sets
`conn+0x93a8 = 1`. That buffer is the Ack payload (§2). **[firm]**

### 1.3 `Message` (kind 1) — `FUN_001d69f0`

Parsed into a `0x10f8` scratch struct at `conn+0x8cd10`. Vtable slots and the
exact bounds the parser enforces **[firm]**:

| Slot | Type | Bound / behaviour | Required |
| --- | --- | --- | --- |
| 0 | string | length **≤ 47** (`0x2f`), else parse fails | **yes** — read with no presence check |
| 1 | `u16` | the "type". `2` selects a different `Meta` reading (§1.4). Absent reads as 0 | effectively yes |
| 2 | table `Meta` | see §1.4 | **yes** — read with no presence check |
| 4 | string | the JSON body, length **≤ 4095** (`0xfff`), else parse fails | **yes** — read with no presence check |
| 5 | `u64` | `deliverAt`, **unix seconds**. Guarded: only read when the vtable is ≥ 15 bytes, so omitting it is safe and yields 0. Must be non-negative as a signed value (`FUN_001e94b0`). Past values clamp to "now" | no |

Parsed struct layout (offsets from `conn+0x8cd10`) **[firm]**: `+0x00` deliverAt
in the tick domain, `+0x08` `u16` type, `+0x0a` receivers string (≤128),
`+0x90`/`+0x98` the 128-bit account id, `+0xa0` the `Meta` slot-4 string (≤40),
`+0xc8` the name (≤48), `+0xf8` the body (≤4096).

### 1.4 `Meta` — the part that is wrong today

```
Meta { 1: string receivers    // ≤127 chars, must parse, must be non-empty
       2: string accountId    // "" or 32 hex chars, optional "0x" prefix
       4: string              // ≤39 chars, MAY be empty — but MUST EXIST }
```

- **Slot 1, receivers.** Read via `Meta` vtable offset 6. Length must be
  `< 0x80`. Tokenised by `FUN_001af8d0` → `FUN_001af300`/`FUN_001af310`:
  comma-separated, and **an empty string fails immediately**. Each token is
  either
  - a **u64**: starts with the two bytes `0x`, then **exactly 16** hex digits
    (`FUN_001af4f0`; any other digit count is an error), producing a
    `{tag 0, u64}` key; or
  - a **name**: 1–31 chars, first char a letter, the rest letters, digits, `-`
    or `.` (`FUN_001af690`), producing a `{tag 1, name}` key.

  A failed token fails the whole parse and the message is dropped. **[firm]**

  So the "listen keys are `{tag, u64|name}`" note is exactly right, and the
  wire form of a receiver is a **string** that *spells* a u64 — never a binary
  u64 field.

- **Slot 2, accountId.** A **string**, read via `Meta` vtable offset 8.
  `FUN_001e9000` accepts an optional `0x` prefix and then requires
  **exactly 32 hex characters followed by NUL** — not 31, not 33. It splits
  them 16/16 and `strtoull`s each half, high word first, giving the same
  `%016llx%016llx` the console writes in
  `/v1/accounts/<32hex>/notification_tokens`. **[firm]**

  There is **no** 128-bit-binary form and no two-u64 form anywhere on this
  path. **[firm]**

  Three outcomes, and this is the whole of the "account id ends up zero" story
  **[firm]**:

  | `Meta.accountId` | npns | friends |
  | --- | --- | --- |
  | absent or `""` (length 0) | parse **continues**, uid left `{0,0}` | every handler returns immediately (`0x1a1bb0`, `0x1a1c60`, …) — the event is silently lost |
  | present but not 32 hex | parse **fails**, message dropped in npns, never reaches IPC | never sees it |
  | 32 hex | uid = the two words | matched against its per-user slot tables |

  What npns hands its IPC clients is that parsed 128-bit value, written into
  the client struct at `+0x30`/`+0x38` by `FUN_001a7a40`. friends reads exactly
  those two words (`0x1a15c0`). **[firm]**

- **Slot 4.** Read via `Meta` vtable offset `0xc`, **with no check that the
  `Meta` vtable is long enough and no check that the offset is non-zero**.
  - If `Message.type == 2`: this slot is *not* read; instead the Message name
    must contain a `-` at index 1…40 and the prefix before it is used.
  - **Otherwise (our case, type 1) it is read unconditionally** and its length
    must be `≤ 39` (`0x27`), else the parse fails and the message is dropped.
  - Its value ends up at IPC-struct `+0x48`. For `type != 2` an **empty string
    is accepted** all the way through `FUN_001a7a40`; only `type == 2` aborts
    on an empty one.

  **Our builder (`internal/penne.BuildMessage`) calls `StartTable(3)` for
  `Meta`, so the vtable has three entries and index 6 is past its end.** The
  bytes read there are whatever the FlatBuffers builder happened to place after
  the vtable; the resulting wild pointer's first `u32` is read as a string
  length and compared against 39. That is where both live samples died.
  **[firm]** on the mechanism; **[likely]** that it fails 100 % of the time
  rather than *almost* always.

  Semantically slot 4 looks like a channel/topic tag (for `type == 2` it is the
  record name's namespace prefix). Nothing on the friends path reads
  IPC-struct `+0x48`. **[firm]** — so `""` is a safe value, and any ≤39-char
  ASCII tag is equally safe. **[open]**: what Nintendo actually puts there.

### 1.5 What happens after a successful parse — `FUN_001dc510`

1. If `deliverAt > now`, the message is inserted into a delay queue sorted by
   `deliverAt` and the steady state re-checks it later. Otherwise:
2. `FUN_001d6070` gives npns first refusal: if the receiver list contains the
   token `penne`, the **body** is matched against npns' own control strings
   (`onset`, `presence:penne`, `presence:nxbaas`) and consumed. Any other
   receiver falls through to delivery. **[firm]**
3. Delivery: `FUN_001a7a40` formats the `0x10a0` IPC struct (`+0x00` u16 = 2,
   `+0x06` u16 body length, `+0x30`/`+0x38` uid, `+0x48` Meta-4, `+0x70` name,
   `+0xa0` body) and then, **once per receiver token**, calls `FUN_001a0560`.
4. `FUN_001a0560` → `FUN_001a09a0` walks the session ring and stops at the
   first session whose key set holds that token; on a miss it retries with the
   fixed wildcard token `{tag 0, value 0}`; on a second miss it parks the
   message on the hub's undelivered queue (`FUN_0019f4c0`, nodes of `0x10b0`,
   **evicted down to seven**, overflow flagged). A later matching `Listen`
   drains it. **[firm]**
5. `FUN_001d6250` files the message into a ~10-deep per-connection history
   ring (name, first 127 body bytes, deliverAt). This is bookkeeping, not
   delivery. **[firm]**

If step 2's parse (`FUN_001d69f0`) returned false, **none of 3–5 happen** —
but §1.2's ack-name capture still does. Hence: two frames in, two Acks out,
nothing delivered. **[firm]**

---

## 2. The Ack, decoded

Built by `FUN_001eb990(builder, conn+0x93a9)` and sent by `FUN_001dd1f0`
(reached from the steady state `FUN_001dc9e0` the moment `conn+0x93a8` is 1).
**[firm]**

```
Ack (type 9) { 0: string }        // envelope slot 2 = "NX", 3 = now, 4 = now+3600
```

The string is `conn+0x93a9` — the 48-byte buffer `FUN_001dfbb0` filled from
**slot 0 of the entry's Message (or Record) table**. Its only meaning is
*"a PutRecord/DeleteRecord/SubscriptionUpdated arrived and this was its
name."*

### Why the samples read as `0xE00000004` / `0x1700000004`

A FlatBuffers table slot holding a string contains a 4-byte `uoffset`; the
string itself is a 4-byte length followed by the bytes. A tiny `Ack` table puts
the string immediately after itself, so the uoffset is `4`. Reading **eight**
bytes at that slot therefore yields `uoffset | (length << 32)`:

| Sample | Message name | `len` | Ack u64 as we logged it |
| --- | --- | --- | --- |
| 06:03:23 | `friend_deleted` | 14 | `0x0000000E_00000004` = 60129542148 |
| 06:07:37 | `friend_request_received` | 23 | `0x00000017_00000004` = 98784247812 |

Exact, both times. **[firm]**

`penne_conn.go` reads `payload.U64(0)` first and only falls back to
`payload.String(0)`, so it never took the string branch. Fix: read slot 0 as a
string. The delivery-ack bookkeeping that the string branch does
(`store.AckDelivery`) is then keyed on the message **name** — which for us is
the event kind (`friend_deleted`), not the event id, so that correlation is
still not available. Put the id in the name, or accept at-least-once.
**[open]**: nothing in the firmware ties an Ack back to a message id; the name
is all that comes back.

**It does not mean "delivered to a listener", and it does not mean "parked".**
It means "frame received and its entry name read". **[firm]**

---

## 3. Everything between "frame arrives" and "friends' handler runs"

In order. Anything not listed here is not a gate.

| # | Condition | Where | Status for us |
| --- | --- | --- | --- |
| 1 | Connection in the steady state (`conn+8 == 8`) | `FUN_001dc9e0` | OK — the sync answer is settled (`penne-protocol.md` §4f) |
| 2 | No ack/pong/request already pending; the console reads a frame only when its own outbox is empty | `FUN_001dc9e0` | OK |
| 3 | Frame passes the FlatBuffers verifier (`FUN_001d2100`); failure ⇒ immediate teardown, reason 3 | `FUN_001dc9e0` | OK — we got Acks |
| 4 | Frame type is in the steady-state accept set (`4, 5, 9, 0xd, 0x10, 0x11, 0x14, 0x18, 0x19, 0x1f, 0x20`); anything else ⇒ *"Unexpected command …"* + teardown | `FUN_001dc9e0` | OK — PutRecord is 4 |
| 5 | Entry vector length exactly 1, entry kind 1 or 2 | `FUN_001dfbb0` | OK |
| 6 | Name ≤ 47 | `FUN_001d69f0` | OK |
| 7 | `Meta.receivers` present, ≤ 127, non-empty, every token well-formed | `FUN_001d69f0`/`FUN_001af310` | OK |
| 8 | `Meta.accountId` `""` **or** exactly 32 hex | `FUN_001e9000` | OK |
| 9 | **`Meta` slot 4 present and ≤ 39** (for `type != 2`) | `FUN_001d69f0` | **FAILS** |
| 10 | Body present, ≤ 4095 | `FUN_001d69f0` | OK |
| 11 | `deliverAt` absent or ≤ now, else queued | `FUN_001dc510` | OK |
| 12 | Not claimed by npns itself (receiver token `penne` + a known control body) | `FUN_001d6070` | OK |
| 13 | A session's listen key matches a receiver token, or the wildcard `{0,0}`, else parked ≤ 7 deep | `FUN_001a0560`/`FUN_001a09a0` | Expected OK — friends registers `0x010000000000000e` |
| 14 | Body length at IPC `+0x06` non-zero | friends `0x1a15c0` | OK |
| 15 | Body parses and `$.type` is present and one of the five kinds | friends `0x1a4300`/`0x1a4d00` | OK |
| 16 | uid at `+0x30`/`+0x38` non-zero | friends `0x1a1bb0`, `0x1a1c60`, … | OK **only for the profile whose Uid we address** |
| 17 | That uid is in the module's per-user slot tables (sync manager `0x189ef0`, count cache `0x18a070`, cooldown `0x353000`); an unknown uid matches nothing and is silently ignored | friends | See §5 |
| 18 | For the on-screen toast only: the uid must be an **open** user (`0x1903e0`) | friends | The list refresh does not need it |

Notes on the things the question asked about specifically:

- **Listen keys / max 8 / 7-deep queue.** Unchanged from
  `penne-record-shape-2026-09-16.md` §3 and re-verified here: `FUN_001a03e0`
  caps a session at eight keys (`0xa9a` on the ninth), `FUN_0019f4c0` keeps the
  undelivered queue at seven and evicts the oldest. A wrong token delivers
  *late* (on the next matching `Listen`), not never. **[firm]**
- **Subscriptions are irrelevant to this path.** A kind-1 message is routed by
  `Meta.receivers` against IPC listen keys. It is not routed by a topic, it
  does not have to ride a topic the console subscribed to, and the friends
  module subscribes to nothing in order to receive events — its one
  `c-friends.inv.subsTypes` call is a record *upload*. The `c-appearance`,
  `c-friends`, `c-settings` and `nx_data_*` names belong to the record-sync and
  BCAT halves. **[firm]**
- **The sync gate.** `SyncComplete` is sent **by the console to us** at the end
  of the Merkle exchange; it is not in the steady state's accept set and needs
  no answer. What the console does require before it will accept pushes is that
  the sync ended — which our empty-entry-vector `RootHash` already achieves.
  No answer to `SyncComplete` is expected or possible. **[firm]**
- **Expiry / issued.** Envelope slots 3 and 4 are read by the builder side; no
  check on them was found on the receive path. `deliverAt` (Message slot 5) is
  the only time gate, and a past value simply delivers now. **[firm]** for
  `deliverAt`; **[open]** whether the verifier looks at slots 3/4.
- **Dedup by message id.** There is none in npns. The IPC struct carries no id
  field and the history ring (`FUN_001d6250`) is not consulted before delivery.
  Deduplication, if any, is the friends module's business — and its
  `friend_deleted` / `friend_request_authorized` handlers read nothing but
  `$.type`. **[firm]**
- **The per-user "open user" check** is friends-side and gates the **toast**
  (`0x1903e0` enumerates open users through `acc`), not the list refresh.
  **[firm]**

---

## 4. The ~10 s reconnect: named, and not our fault

**Firmware check:** `FUN_001dc9e0`, second guard —

> if `conn+0x9368 == 1` and `now > conn+0x8cce8` → `FUN_001d99b0(conn, 4,
> 0x200000000)`

`FUN_001d99b0` clears every per-connection flag and returns the teardown state
function; the console then reconnects and replays `RootHash` + `SyncComplete`.
**[firm]**

`conn+0x9368` is *"I have a request outstanding"*. **Every console→server
request** sets it, stores the string it expects back at `conn+0x9370`, stores a
request-kind enum at `conn+0x93a0`, and sets `conn+0x8cce8 = now + 10 s`
(`thunk_FUN_001280e0(10000000000)`, identical in all of them). **[firm]**

| kind (`conn+0x93a0`) | sender | frame it sends | string it expects back |
| --- | --- | --- | --- |
| 0 | `FUN_001dd590` | **PutRecord (0x04)** — the console uploading a record | the record name (`conn+0x94b8`) |
| 1 | `FUN_001dd7c0` | DeleteRecord (0x05) | the record name |
| 2 | `FUN_001dd980` | SubscribeTopic (0x17) | literal **`topic.subscription`** |
| 3 | `FUN_001ddb50` | DenySubscribe (0x23) | [open] |
| 4 | `FUN_001ddd50` | SubscriptionListRequest (0x1c) | [open] |
| 5 | `FUN_001ddf50` | MyAccountMessageRequest (0x1d) | [open] |
| 6 | `FUN_001de140` | DAPresence (0x1b) | `"%016llx/%016llx"` of device-account id and NSA id — 33 chars |
| 7 | `FUN_001de340` | Ping (0x10) | cleared by **Pong (0x11)** instead |
| 10 | `FUN_001de5b0` | TopicRead (0x24) | [open] |
| 0xb | `FUN_001dd2f0` | PowerState (0x0e) | **`Awake`** or `Asleep` |
| — | `FUN_001de780` | ResendRequest (0x1a) | [open] |
| — | `FUN_001de920` | ReloadLink (0x1e) | [open] |

Only three frames clear it **[firm]**:

- **`Ack` (0x09)** — `FUN_001deab0`. It **fatally aborts** if `conn+0x9368` is
  0, and **fatally aborts** if its string does not `strcmp`-equal
  `conn+0x9370`. Those are the `UnexpectedAck` / `InconsistentAck` result names
  in the module. So an Ack must be sent *only* in reply to a request, and must
  echo the expected string exactly.
- **`Nack` (0x18)** — `FUN_001dedd0`, same dispatch, failure semantics.
- **`Pong` (0x11)** — `FUN_001df9e0`, for the Ping case; it too aborts if no
  request is outstanding.

**`SubscriptionUpdated` (0x1f) does not clear it.** `FUN_001df670` merely hands
the payload to a callback and then queues an *Ack of its own* back to us. So
nx-baas's current reply to `SubscribeTopic` is not the confirmation the console
is waiting for, and the console dies 10 s later. **[firm]**

Two further hazards found while reading this:

- `FUN_001df670` reads `SubscriptionUpdated` payload **slot 0 as a string** and
  copies up to 48 bytes of it. `penne.BuildSubscriptionUpdated` writes a `u64`
  there, so the console dereferences that integer as a `uoffset`. Stop sending
  it, or make slot 0 a string. **[firm]**
- The other watchdog — `conn+0x8ccd3 && conn+0x93dc && conn+0x93de == 0 &&
  now > conn+0x8cce0` → teardown reason 4 / `0x200000001` — is armed only once
  the server has sent an **`Idle` (0x14)** frame, whose payload slot 0 is a
  `u16` **interval in seconds**; the deadline is then `now + 2 × interval`, and
  it is refreshed by `Idle`, by an inbound `Ping`, and by an `Ack` of a
  PowerState `Awake`. We never send `Idle`, so this watchdog is currently
  disarmed. If we ever start sending `Idle`, we must also keep the connection
  fed. **[firm]**

**Verdict:** our `PutRecord` frames are not what closes the connection —
nothing on the PutRecord path touches either deadline. The console makes its
own requests (its record uploads, its `SubscribeTopic`, its `DAPresence`) and
we answer none of them with an `Ack`; the correlation with our frames is that a
delivered notification is exactly what makes a module write a record and
therefore makes the console send the request that then times out. **[likely]**

---

## 5. What nx-baas must change

In order of what unblocks what.

### 5.1 Add `Meta` slot 4 — this is the one that makes delivery possible

`internal/penne.BuildMessage`: build `Meta` with **four** slots, writing slot 4
as a string of at most 39 chars. `""` is accepted by every check on the
`type != 2` path, so the minimal change is a `CreateString("")` at slot 4 and
`StartTable(5)`. A short constant tag (e.g. the event's namespace) is equally
safe and easier to spot in a capture.

Everything else about our message is already right: name ≤ 47, `type` 1,
receivers `0x010000000000000e`, accountId 32 hex, body ≤ 4095, `deliverAt`
omitted.

### 5.2 The required frame, complete

```
Envelope  { 0: u8 = 4 (PutRecord)
            1: → PutRecord
            2: string "NX"
            3: u64 issued  (unix seconds)
            4: u64 expires (issued + 3600) }

PutRecord { 0: [Entry]  with EXACTLY ONE element
            1: u8 = 1 }

Entry     { 0: u8 = 1            // kind: message
            1: → Message }

Message   { 0: string name       // ≤47; free-form, friends never reads it;
                                 //   it is what the console's Ack echoes
            1: u16  = 1          // must not be 2
            2: → Meta
            4: string body       // the event JSON, ≤4095, must be non-empty
            5: u64 deliverAt }   // OPTIONAL — omit entirely

Meta      { 1: string receivers  // "0x010000000000000e" — non-empty, ≤127,
                                 //   "0x" + exactly 16 hex, comma-separated
            2: string accountId  // the recipient profile's Uid as EXACTLY
                                 //   32 hex chars (optional "0x" prefix);
                                 //   "" delivers with uid 0 and friends drops it
            4: string tag }      // ≤39, MAY be "", MUST BE PRESENT
```

### 5.3 Address the right profile — the two-profile part

`Meta.accountId` must be the **Uid of the profile the event belongs to**, not
"every Uid we have seen on this console". Today `penneMessageFrames` fans out
over `AccountsFor(userID)` and `penne.json` records **both** of this console's
Uids against <user-b>, so:

- <user-b> gets two frames, one of them addressed to <user-a>'s Uid. Once §5.1 is
  fixed that frame reaches friends with a uid that is not in <user-b>'s slot
  tables, and is silently ignored (gate 17).
- <user-a>'s own events are addressed to <user-b>.

The mapping to trust is the one that repeats every session
(`friends-notifications-firmware-2026-09-19.md` §1.2): bind
`Uid → notification_token` when npns mints it, then `token → NSA` when olsc
posts it to `…/network_service_accounts/<nsa>/notification_tokens`. Fix the
binding and send **one** frame per event, to one Uid.

The fan-out is still useful as a probe, but it costs an undelivered-queue slot
each time (seven deep) — do not run more than a few.

### 5.4 Answer the console's requests with `Ack`, or it keeps reconnecting

Add an `Ack` builder: envelope type 9, payload `{0: string}`, envelope slot 2
`"NX"`, slots 3/4 issued/expires. Then, in `penne_conn.go`:

- inbound **PutRecord (4)** / **DeleteRecord (5)** from the console → `Ack` with
  the record name it sent;
- inbound **SubscribeTopic (0x17)** → `Ack` with the literal
  `topic.subscription` (and stop sending `SubscriptionUpdated`, or at minimum
  make its slot 0 a string);
- inbound **DAPresence (0x1b)** → `Ack` with `<deviceAccountId>/<nsaId>`,
  16 hex `/` 16 hex, 33 chars, in that order;
- inbound **PowerState (0x0e)** → `Ack` with `Awake` / `Asleep` as sent;
- inbound **Ping (0x10)** → `Pong` (already correct).

**Never send an `Ack` unsolicited, and never send one whose string differs from
the request's** — both are fatal aborts inside npns.

### 5.5 Read the console's `Ack` as a string

`penne_conn.go` `case penne.TypeAck` must try `payload.String(0)` **first**.
The current `U64(0)`-first order is what produced `ack=60129542148`. The string
is the message *name*, so if we want per-delivery correlation the name has to
carry the id (it has 47 characters to spend) — the firmware offers nothing
else.

### 5.6 Then re-run the two-console test

With §5.1 and §5.3 in place a `friend_deleted` / `friend_request_received` /
`presence_updated` should produce, on the receiving console and with no reboot:

- the `Ack` echoing the message name (as now), and
- an unsolicited `GET /2.0.0/users/<uid>/friends?count=300` within the 30 s
  cooldown, plus the ovln toast for `friend_request_received` if that profile
  is open.

If the Ack arrives and the GET does not, the remaining suspects are, in order:
the receiver token not matching friends' session (watch for the undelivered
queue, and note it drains on the next `Listen`), and the Uid not being in that
profile's slot tables.

---

## 6. Why presence is published for the profile that is NOT playing

Live: one console, two profiles. **<user-b>** (`aaaaaaaaaaaa0002`, Uid
`1000000000b200020000000000000001`) is in the foreground playing Kirby's Dream
Buffet. Every `DAPresence` we receive is for **<user-a>**
(`aaaaaaaaaaaa0001`), `INACTIVE`, no app, empty appField, every ~10–60 s. Over
72 h, essentially nothing for <user-b>.

That is not a bug in what the console *sends*. It is the per-profile publish
gate, and it is **local console state**, not anything we serve.

### 6.1 The gate, followed to the bottom

`friends-presence-firmware-2026-09-19.md` §2.1 had this as an inference
("account is network-ready"). It resolves, and the flag has a concrete meaning.

1. **Publish** — `FUN_0018bb40(mgr, uid)` finds the user's slot in the sync-task
   manager (Uid table at `mgr+0x220`, stride `0x10`; bodies stride `0x278`) and
   **returns without queuing anything unless `slot+0x2a1 == 1`**. **[firm]**

2. **Who sets `+0x2a1`** — exactly one function, `FUN_0018db10`. It is not
   called directly anywhere; it is slot **`+0x48`** of the vtable at Ghidra
   `0x2568e0` (friends `main.elf` file offset `0x155504`; the module's
   account-observer interface). Nothing anywhere clears `+0x2a1` on its own —
   the adjacent `+0x2a0` is what the other observer callbacks toggle. **[firm]**

3. **Who calls slot `+0x48`** — the account-observer hub `PTR_DAT_0025bfc8`,
   from `FUN_0018fce0`, for each Uid that **enters** its third tracked set.
   The hub tracks three Uid sets and calls an "added"/"removed" pair per set on
   every registered observer:

   | Set | Cache / count | Refilled by | "added" slot | "removed" slot |
   | --- | --- | --- | --- | --- |
   | A | `hub+0x18` / `hub+0x198` | `FUN_00172240` → acc proxy vtable `+0x30` | `+0x18` | `+0x20` |
   | B | `hub+0x98` / `hub+0x19c` | `FUN_00172410` → acc proxy vtable `+0x38` | `+0x30` | `+0x38` |
   | C | `hub+0x118` / `hub+0x1a0` | `FUN_0018fce0`, **filtering set A** | **`+0x48` = `FUN_0018db10`** | `+0x50` |

   The three are driven by three account notifier events the friends worker
   (`FUN_001a0e10`) opens at start-up from the same account proxy —
   `FUN_001725e0` (vtable `+0x78`), `FUN_00172670` (`+0x80`), `FUN_00172700`
   (`+0x90`). **[firm]** on the wiring; **[likely]** that they are the
   user-registration, user-state-change and BAAS-account-status notifiers, in
   that order.

4. **The filter** — `FUN_00190510(uid)`, and this is the whole gate: **[firm]**

   - `GetBaasAccountManagerForSystemService(uid)` — account proxy vtable `+0x88`,
     `(out interface, uid)`;
   - then the returned manager's vtable `+0x20`, **no arguments, Result only**
     — a `CheckAvailability`-shaped probe;
   - `Result == 0` ⇒ available ⇒ the uid joins set C ⇒ `+0x2a1 = 1` ⇒ it
     publishes. A `nn::account` (module `0x7c`) result whose description is in
     roughly **200–269** ⇒ *cleanly* unavailable (no error propagated, just
     `false`). Anything else ⇒ also false.

5. **What that probe actually reads**, from the account module
   (`010000000000001e`, `FUN_001b8760`): a **per-profile file on the console's
   own account save**, path `"%s/baas/%s.dat"` where the second `%s` is the Uid
   printed as a GUID (`%08x-%04x-%04x-%02x%02x-%08x%04x`), and the file must be
   **exactly 0x50 bytes**. **[firm]**

   - file missing (fs `0x202`), or short/long ⇒ **`0x1907c`** = nn::account
     description **200** — which is the first code in the band friends accepts
     as "unavailable". **[firm]**
   - present but its state word is not 1, or it carries no NSA id ⇒
     `0x1a47c` (210), `0x1a67c` (211), `0x1b87c` (220) from `FUN_001b8d20` —
     all inside the same band. **[firm]**

   The record is written by `FUN_001b8970`: it validates a **32-character hex**
   device-account id, then writes `{nsaId (u64), state = 1, …, deviceAccountId
   (32 hex)}` into that file. Those are exactly the two values in the account
   module's `PUT <baas>/1.0.0/push_channels/%016llx/%016llx` — NSA id, then
   device-account id (`friends-notifications-firmware-2026-09-19.md` §1.2(b)).
   **[firm]** on the record contents; **[likely]** that the link/push_channels
   flow is what writes it.

### 6.2 So: why <user-a> and not <user-b>

- The gate is **per profile** and has **nothing to do with foreground, playing,
  or being the open user**. `FUN_0018bb40` never looks at the app state; it
  looks at `+0x2a1`.
- **<user-a>'s `baas/<uid>.dat` is valid** ⇒ he is in set C ⇒ his slot publishes
  on every change and on the manager's heartbeat. He has no application
  running, so his state is `INACTIVE` (1 on the wire). That is a correct
  report, not a stuck one.
- **<user-b>'s is missing or invalid** ⇒ she never enters set C ⇒ `+0x2a1` is 0 ⇒
  `FUN_0018bb40` returns immediately, for every update, including the ones
  Kirby generates. **[likely]** — the branch is proven, which profile fails is
  inferred from the observation that only hers never appears.

  The two frames ever seen for her over 72 h are consistent with her record
  having been valid briefly and then not.

  This also fits the timeline already on record: the account module's link
  sequence (`POST /v1/accounts/<uid>/links` → `PUT /1.0.0/push_channels/<nsa>/
  <deviceAccount>` → `PATCH …/links`) was last seen **Sep 08**, and the BAAS
  user ids from that day are stale — `aaaaaaaaaaaa0002` is not one of them.
  **[likely]**

### 6.3 Answer to "can the server flip it?"

**No, not directly.** **[firm]**

- There is no field in `/2.0.0/users/me`, no `permissions.presence`, no
  friend-list response and no Penne push anywhere on this path. friends asks
  `acc`; `acc` reads a local file. Nothing we serve is consulted at
  publish time.
- The notification-token flow (`/v1/accounts/<uid>/notification_tokens`) does
  **not** write this record — that is npns, on behalf of olsc, and it happily
  runs for a profile whose BAAS record is missing. Which is exactly what we
  observe: both Uids mint tokens every session, only one publishes presence.
  **[firm]**

**Indirectly, yes — via the link flow that writes the file.** **[likely]**
The record holds the NSA id and the 32-hex device-account id, so the write is
the tail of the account module's NSA registration. Everything on that path is
served by us and is therefore ours to get right for *that* profile:

- `POST god…/v1/accounts/<user-b uid>/links` with `{penne_id, password,
  nsa_id_token}` — must return a non-empty 2xx body (any non-empty 2xx counts
  as success, per §1.2(b) of the notifications doc);
- `PUT <baas>/1.0.0/push_channels/<nsaId>/<deviceAccountId>` with
  `deviceToken`, `service`, `deviceAttributes`;
- the BAAS `/1.0.0/login` and id-token issuance for *that* Uid's NSA.

If any of those fail or return something the account module rejects, the record
is not written and presence for that profile is dead, silently, forever.

There is one other server-side switch already documented and worth checking
while here: even for a profile that *is* in set C, the publish task forces
`state = 0 (INACTIVE)` when `mgr+0xfc0` ("npns connected", set from npns
state `== 8` through `FUN_00195e50`) is clear
(`friends-presence-firmware-2026-09-19.md` §2.1). A frontline that keeps
dropping every 10 s (§4) flaps that bit. **[firm]**

### 6.4 Answer to "does a game publishing while gated put anything on the wire?"

**No. Nothing at all.** **[firm]**

`UpdateUserPresence` (friend:u cmd 10610 → `FUN_001d5f10` → `FUN_00194a00`)
succeeds normally: the Uid check passes, the caller is resolved to the
foreground application, the 0xC0 app-field blob and the
`DeclareOpen/CloseOnlinePlaySession` byte are stored in the slot, the state
becomes `PLAYING`/`ONLINE`, the time is restamped, and the **local** state
callback (`mgr+4000` → `FUN_0018a220`, the overlay/notification path) runs.
Then the publish callback `mgr+0xfb0` → `FUN_0018a250` → `FUN_0018bb40` finds
`+0x2a1 == 0` and returns. No task is queued, no REST `PATCH
…/device_accounts/…`, no `DAPresence` frame. The game gets `ResultSuccess` and
sees nothing wrong.

So Kirby calling `DeclareOpenOnlinePlaySession` / `SetDescription` / `Commit`
as <user-b> is, from our side, indistinguishable from Kirby never calling them.

### 6.5 Tests the console owner can run

In order, cheapest first. Each one is a clean yes/no.

1. **Isolate it to the profile (5 min, no settings changed).** Switch the
   foreground profile: launch any online game **as <user-a>** and leave <user-b>
   out. Watch nx-baas for `DAPresence user=aaaaaaaaaaaa0001`.
   - state changes to `ONLINE` (2) or `PLAYING` (3) ⇒ the whole pipeline works
     and the fault is <user-b>'s profile state alone. This is the expected result.
   - still `INACTIVE` ⇒ the fault is the `mgr+0xfc0` npns-connected bit or the
     frontline flapping (§4), not the per-profile gate.
2. **Confirm <user-b> has no usable network service account.** As <user-b>, open
   anything that needs her NSA — the Friends list / "Add Friend" / friend code
   screen, or the eShop. If those refuse or ask her to link an account, the
   `baas/<uid>.dat` record is missing, which is the same gate. **[likely]** —
   this is the user-visible face of the same check, not the identical call.
3. **Rewrite the record.** As <user-b>, unlink and re-link her Nintendo Account
   (System Settings → Users → <user-b> → Nintendo Account), or sign her out of and
   back into the online service. While doing it, watch nx-baas for, in order:
   - `POST /v1/accounts/1000000000b200020000000000000001/links`
   - `PUT /1.0.0/push_channels/aaaaaaaaaaaa0002/<deviceAccountId>`
   - `PATCH …/links` about 40 s later

   All three must return success. If the `links` call is missing, the console
   never got that far; if it 4xx/5xxs or returns an empty body, we broke the
   write.
4. **Re-test.** Launch Kirby as <user-b> and watch for `DAPresence
   user=aaaaaaaaaaaa0002` with a non-`INACTIVE` state and a non-empty appField.
   If it appears, the record was the gate and the fix is to keep that link flow
   healthy for every profile.
5. **If step 3's requests never appear at all**, the console thinks <user-b> is
   already linked and will not redo it. Force it: sign <user-b> out of the console
   entirely (remove the Nintendo Account link), reboot, then link again. That
   deletes and rewrites `baas/<uid>.dat`.

Note for whoever runs this: fixing §5.1 (the `Meta` slot 4) and fixing this are
independent. Presence *in* (us telling the console about friends) is the
message path; presence *out* (the console telling us about itself) is this
gate. Neither unblocks the other.
