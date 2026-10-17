# Changelog — nx-baas

> **Current Switch client (2026-10-13): Harbor**, at
> `~/REPOS/Openpak/emulators/harbor`. Harbor is an independent
> OpenPak project based on Eden. Citron, Ryujinx (desktop and Android), and
> the former OpenPak Eden checkouts have been removed. References to those
> forks below record historical evidence only: do not run their commands,
> reinstall them, or select them for current work. Use Harbor's README and
> current handoff for builds and testing; old results do not establish Harbor parity.

Generated from git history on 2026-09-15. `git log` stays the source
of truth; this file is the readable summary.

## v0.54.19 — 2026-10-17

- **Every core account has a Switch identity, not just the ones that touched a Switch.** A minute
  after start and every minute after, `provisionAllAccounts` walks the core's account directory
  (`Identity.ListAccounts`) and mints the pid, BAAS id and friend code of any account without one,
  so a new account is on the Switch network within a minute, with its display name.

## v0.54.18 — 2026-10-16

- **Presence on another platform arrives as a core event, not a poll.** The core (v0.16.0) now sends
  `presence_changed` to each friend online on a network, scoped to it. `followCoreEvents` handles
  those addressed to `switch` and sends the viewer one `presence_updated` for the account that moved
  (`notifyCorePresence`). The 5 s poller from v0.54.17 is gone.

## v0.54.16 — 2026-10-16

- **A news push now makes consoles fetch the channel.** bcat registers its npns listen key by
  name (`ListenToByName("bcat")`), so `/internal/news/push` frames are addressed to `bcat`
  instead of the program id, and `revision` goes out as a JSON string, which is what bcat's
  parser reads and hashes. Proven on Harbor: push, `nn.bcat.EventWatcher` receive, list fetch
  two seconds later. `NX_PENNE_NEWS_RECEIVER` still overrides the token.

## v0.54.17 — 2026-10-16

- **A friend coming online on another platform (Pier, Xbox, Wii U) now notifies the Switch.** The core
  announces no presence change, so the console read such a friend only when it re-fetched its list
  and never got the "is online" pop-up. `followCorePresence` polls the core's presence for every
  Switch user's non-Switch friends every 5 s and submits a `presence_updated` on each change
  (online, game, offline), with the same visibility rules as a Switch friend. First sight of an
  offline friend and friends with live Switch presence are skipped.

## v0.54.15 — 2026-10-16

- **A picture set on the website reaches a console that already cached the default.** A friend known
  only to the core had an unversioned thumbnail URL, so a console that fetched the default once
  never asked again. `friendView` now reads the picture's Last-Modified from the website and
  `friendObj` appends it as `?v=`.

## v0.54.14 — 2026-10-16

- **A friend who never used a Switch now shows their name and picture.** `friendView` and `Resolve`
  fall back to the account's display name when the projection has none, and the `/1/<baas id>`
  thumbnail route resolves the account through the core when no console record exists, instead of
  serving the default image.

## v0.54.13 — 2026-10-16

- **Every friend gets a Switch identity, whether or not they have used a Switch.** The console's
  friend list skipped any core friend without a Switch projection, so a friend who only plays on
  Xbox or PlayStation never appeared, and neither did their online state. `friendView` now mints
  the pid, BAAS id and friend code on first sight (`ensure`, core-linked), so cross-platform
  presence reaches the console.

## v0.52.0 — 2026-10-10

- **A Switch now gets "<friend> is online" for friends on Harbor (and for every friend).** The
  console's `presence_updated` parser fails the whole event unless `userId`, `state`,
  `appInfo:appId`, `appInfo:presenceGroupId`, `appField`, `updatedAt`, `logoutAt` and
  `$.createdAt` are all present (field mask `0x3eb`, friends 22.5.0 `0x1a74a0`, 23.0.1
  `0x1aaea0`). Events without a game left the two app ids out, so the console dropped every
  INACTIVE, OFFLINE and title-less ONLINE, never saw a friend leave, and so never saw them
  come back: the pop-up needs a cached Offline before the Online. "No game" is now the
  all-zero id the console itself publishes.
- **Sign-in is INACTIVE, not ONLINE.** A login claimed ONLINE with no title, which a console
  never publishes; the device's own INACTIVE then landed in the same second and the console,
  which applies only a later `createdAt`, kept the ONLINE.
- **`createdAt` is strictly increasing per friend and viewer**, so two changes inside one second
  (PLAYING to ONLINE as a session closes) are both applied.
- **Signing in at HOME keeps the last departure as `logoutAt`.** overlayDisp shows the pop-up only
  for a friend offline more than 1799 s (23.0.1 `0x31b2f0`), counted from the `logoutAt` the
  console cached; stamping "now" at sign-in silenced every game started within half an hour.

## v0.51.3 — 2026-10-10

- **No personal data in logs.** Account, NSA, device and pairing ids, pids, nicknames, e-mail
  addresses, friend and pairing codes, tokens, tickets, Authorization headers, request
  paths and queries, and client addresses are no longer logged. An id appears as a short
  per-process tag (`redact.Tag`: keyed HMAC prefix, key random per start), so two lines about
  one console still match within a run and cannot be compared across restarts. Paths keep
  their route words, queries keep only parameter names, and user agents keep their firmware and
  platform text with every id-shaped run tagged. Title ids stay readable.
- Request and response bodies, header values, query values and raw Penne frames are logged
  only with `NXBAAS_TRACE_BODIES=1`, which is for local debugging and never production. The
  net/http servers use a scrubbing error logger, so a TLS handshake error no longer names the
  client address.
- `TestLogsCarryNoPersonalData` sends a request carrying those values and fails if any of them
  reaches the log.

## v0.48.0 — 2026-09-27

- **Confirmed on hardware: the push.** A parent's save was pushed, acknowledged, fetched and
  receipted by the console inside a second, six times out of six, with nobody touching it. The
  editor's play-timer document is accepted, and per-title play time arrives as the firmware's
  serialiser said it would.
- **A parent can name a console.** The console never names itself — its `activate` body carries a
  serial number, region, language, time zone and firmware, and no name — so two consoles under one
  account were both "Console". `PUT /internal/pctl/devices/<moon_id>/name {"name"}` sets up to 32
  characters and an empty name clears it. Until it is named, a console goes by the last four
  characters of its serial number, which is printed on it.
- **Play activity says who played.** A played title's event splits its time by the console's own
  player ids, plus the part played with no user selected (hardware: Moving Out 2, 790 s, 769 of
  them one player's). Each title in `…/activity` now carries `players: [{id, minutes}]` and
  `anonymous_minutes`; the ids are the ones the device's `players` list names.
- The list carries `named`, `serial_number` and `firmware`, kept from `activate`. A console paired
  before this release has neither until it pairs again.

## v0.47.0 — 2026-09-27

- **A parent's save tells the console to fetch at once.** Without a push the console fetches its
  setting only when someone presses "update settings" or when its retrieve task runs, and that
  task's default interval is 21600 s (`pctl!intermittent_task_interval_seconds`, six hours).
  After every `PUT …/setting`, nx-baas now writes one npns message on the console's own Penne
  frontline connection: receivers `pctl`, no account id, and the body
  `{"deviceId":"<moon id>","eventId":"DID_CHANGE_PARENTAL_CONTROL_SETTING"}`. That is the shape
  pctl 22.5.0 listens for and parses. It listens under the name `pctl`, drops a message naming
  any other device, and on this event runs its retrieve-settings task at once. The push is best
  effort: with no live connection the save still succeeds, and the log says so. It has not yet
  been run on hardware.
- **The console's `notificationToken` is kept.** It is the console's Penne registration id, so it
  names the connection a push goes out on. It is read at `activate` and from any device update
  that carries it. A console paired before this version is reached through the Penne
  registration made under the same device certificate.
- **No PIN in the debug log.** With `NX_DEBUG` set, the request and response dumps logged the
  PIN in full: in `activate` and receipt bodies, and in the setting and activate answers. Both
  directions now mask `unlockCode`, `synchronizedUnlockCode` and `unlock_code`, the same way the
  `[moon]` dump does. Lines already in the journal are not changed.

## v0.46.0 — 2026-09-27

- **Play time per day, for the parent.** `GET /internal/pctl/devices/<moon_id>/activity?account_id=…&days=1..30`
  (default 7) answers `{"days":[{"date","total_minutes","titles":[{"title_id","minutes"}]}]}`:
  newest day first, the date in the console's own calendar (each event carries its UTC offset),
  title ids in lowercase hex, titles by minutes descending, and a day with nothing counted left
  out. Another account's console, or an unknown one, is a 404.
- **What the console's times mean, from its uploads.** Every event carries running totals in
  seconds, not the time since the last event: `elapsedTime` grows second for second with the
  timestamps, stands still while the console is temporarily unlocked (`disabledTime` grows
  instead), and restarts near zero shortly after pairing. A day's time is therefore the gain
  between consecutive events — the whole value after a restart — and never more than the clock
  allows between them. `total_minutes` is `elapsedTime`, what the play timer counts, HOME menu
  included. Per-title times come from `applicationTimes`, which has been empty in every upload so
  far because nothing was played; its shape (title id as `%016llX`, each with an `elapsedTime` in
  seconds) is read from the firmware and is unproven until a console uploads one. An event of any
  other shape counts for nothing.

## v0.45.2 — 2026-09-27

- **Confirmed on hardware: a PIN and a restriction set on the server both reach the console.**
  A served `unlockCode` came back in the receipt as `synchronizedUnlockCode`, the console showed
  "PIN changed", and the new PIN worked; serving `NONE` again let titles launch. The parent's
  picture is drawn now that it is a PNG.
- **A parent's PIN is exactly four digits.** The console's parser takes up to eight, but its entry
  field has four places, so anything longer could never be typed. `PUT …/setting` refuses any
  other length. A code the console reports is still taken as it comes.
- **Each number has its own bound.** Every integer was capped at 255, which is the rating age's
  limit and nobody else's: a play-time limit of five hours was refused. The bounds are the ones
  the console's handlers enforce — `limitTime` 360 minutes, `hour` 23, `minute` 59, `ratingAge`
  255 — since a value past one ends the console's parse.
- **The PIN is masked in the request dump.** The console sends it in `activate` and in every
  receipt; the log shows `****` in its place and everything else in full.

## v0.45.1 — 2026-09-27

- **Confirmed on hardware: a restriction set on the server blocks games on the console.** Level
  `CUSTOM` with `ageRestriction{RESTRICTED, ratingAge 3}` was fetched by the console's "update
  settings" button, the receipt carried the served ETag, and titles stopped launching. The
  receipt's `synchronizedAt` is the document's `updatedAt` echoed back, not the time of the sync.
- **A parent can remove a console.** `DELETE /internal/pctl/devices/<moon_id>?account_id=…` drops
  the record. The console is not told; it is for one that has already left or been reset, such as
  a record stranded by an unlink made before v0.43.1.
- **Confirmed on hardware: the console names the parent.** With v0.43.0 the pairing screen showed
  the account's display name instead of "OpenPak".
- **The parent's picture is a 128 px PNG, under a new name.** The console showed no picture for
  the JPEG: it had fetched `console.jpg` once, filed it, and at the next pairing neither asked
  again nor drew it. Nintendo's own are small PNGs, so the relay now re-encodes the website's
  console JPEG and serves it as `face.png` — the console files a picture under the URL's last
  segment, so the new name is what makes it fetch again. Unproven until a console draws it.

## v0.45.0 — 2026-09-27

- **A parent can set the setting and the PIN**, for the hardware experiments first (the
  parent-surface PRD's Q1–Q3): `PUT /internal/pctl/devices/<moon_id>/setting?account_id=` takes
  `{setting, unlock_code}`, either optional. A document is refused, not thinned: anything the
  console's parse table would drop or change is a 400 naming its path, and nothing is stored. A
  code must be four to eight digits. Answers `{etag, updated_at}`; another account's record is a
  404. The code is never logged.
- **The setting GET carries `unlockCode` only once a parent has set one.** A console whose code
  came from the console itself gets exactly the document it got before.
- **The ETag is a hash of the document as served**, `unlockCode` included, so a new code alone
  moves it; the activate answer's `synchronizedEtag` is computed the same way. It was a hash of
  the stored document, which differed from the served one whenever the console's own document was
  stored; no record in production had one.
- **A parent-set code survives the console.** A receipt naming another code means the console has
  not applied it yet, and neither the receipt nor the console's own setting `PUT` overwrites it.
  The code a receipt reports is kept beside it.
- **A console that unlinks is removed.** Deleting its last owner, or the device, deletes the
  record with its players, events, setting and PIN; pairing again starts fresh and the parent's
  list no longer shows it. The console gets the same 204.
- **Events are held one each, for 30 days**, with a hard cap of 5000 per console, instead of the
  newest 200 uploads. An upload is a JSON array; a store holding whole uploads still loads and is
  split on the next upload.
- **Wrong-PIN attempts reach the parent.** The internal device list adds `wrong_pin_attempts`: the
  `eventTimestamp` of each `DID_WRONG_UNLOCK_CODE` event, newest first, at most 20. No other event
  type is read.

## v0.44.0 — 2026-09-27

- **The sync receipt is kept.** After a setting `GET` the console `POST`s `/devices/<id>` with
  `synchronizedUnlockCode` and `synchronizedParentalControlSetting{synchronizedEtag,
  synchronizedAt}`; only `nickname` was read from it. The etag and time are stored, and the
  console's code replaces the record's: there is no parent-set code yet, so the console's is
  authoritative. A record paired before v0.43.0 held a minted code; its first receipt corrects it.
  Nothing the console is answered changes, except that such a record's device object now names
  the console's own code instead of the minted one.
- **The parent side reads what it needs.** `GET /internal/pctl/devices` adds, per record,
  `nickname`, `setting` (the document as served), `players` as `{id, nickname}`, the served
  `etag`, `synced_etag`, `synced_at`, and `synced` (the receipt names the served etag). A paired
  record carries `unlock_code` once the console itself has named it, at `activate` or in a receipt;
  a minted code unlocks nothing and is not shown. The code is never logged.
- **`GET /internal/pctl/devices/<moon_id>/players/<id>/image?account_id=`** returns the player's
  JPEG, decoded from the console's upload. A record another account manages is a 404, like one
  that does not exist.

## v0.43.1 — 2026-09-27

- **Confirmed on hardware: the console's `unlockCode` is its PIN** (8759 unlocked it), the owner's
  picture link is followed (`GET /moon/v1/mii/…/console.jpg`), and players upload.
- **A console that removes its last owner is unlinked.** Unlinking on the console is not a
  `DELETE` of the device: it lists the owners, deletes each, and says nothing more. The record
  stayed bound to the console after the 204. It is now released when no owner is left, and its
  players go with it.

## v0.43.0 — 2026-09-27

- **Confirmed on hardware: a console pairs.** With v0.42.0 the console ran search, owners and
  `activate`, and reported itself managed. Its activate body is its whole state, and its
  `parentalControlSetting` matches the parse table key for key.
- **The activate body is kept.** It was read for nothing but the bearer. The setting in it is now
  stored as the record's document, and the console's own `unlockCode` replaces the one minted with
  the record — that is the PIN the console asks for, so it is the one the parent has to be shown.
- **The parent is named, and pictured.** The owner the console shows as Parent/Guardian was the
  placeholder "OpenPak". `/internal/pctl/pairing` takes `display_name`, the owner carries it (cut
  to the 32 bytes the console copies), and `user.miiUri.small` links to
  `/moon/v1/mii/<account>/console.jpg` on the same host, which relays the account's console JPEG
  from the website. The console keeps at most 64 KiB of it.
- **The console's players are accepted.** After pairing it PUTs each of its users to
  `/devices/<id>/players/<user>` with a nickname and a base64 JPEG; that was answered 404.
  `PUT` stores one, `DELETE` forgets one, eight at most per console.

## v0.42.0 — 2026-09-27

- **Confirmed on hardware: `id` as a hex string gets the console past the search.** With v0.41.0
  the console parsed the answer and asked for `/devices/0000335384296553/owners` with the right
  id. 2142-0234 on pairing is closed.
- **The owners read answers before `activate`.** That request is the console asking whose record
  it found, and it comes before anything is claimed; the claimed-console check refused it with
  `403/forbidden`, which the console shows as 2142-2008. An unclaimed record now answers any
  console holding a device token. A claimed one still answers only its own console.
- **Owners take the shape the console parses** (table `0x13d240`): `{deviceId, user{
  nintendoAccountId, nickname}}`, both ids as hex strings. A record nobody is linked to yet names
  the account that minted its code, under an id derived from it and the nickname "OpenPak". An
  owner id that is not hex is left out, since it would end the parse.
- **A stored setting is served only in the parsed shape.** The console's own PUT uses its
  serialiser's layout, and serving that back would put wrong types on keys the parser knows.
  The document is filtered through the parse table's keys, types and enums; one with no
  `functionalRestrictionLevel` left is served as the default.
- **The polled setting carries `etag` and `updatedAt` in its body**, as the table names them.
- **The activate answer carries `synchronizedParentalControlSetting{synchronizedEtag,
  synchronizedAt}`**, which is all the console reads from it (table `0x13c580`).
- **Refusals use the console's five error keys** (table `0x13bb20`): `type`, `title`,
  `errorCode`, `status`, `detail`. `code` was never one of them.

## v0.41.0 — 2026-09-27

- **2142-0234 is a JSON parse abort, and `id` is a hex string.** The result is not a restriction
  verdict: pctl maps RapidJSON's parse error codes through an 18-slot table (`.text 0x47c30`), and
  slot 16, `kParseErrorTermination`, is 2142-0234 — its handler refused a token in a body we
  answered with 200. The search answer's parse table (`0x13c6f0`) reads exactly `count` (integer)
  and `items[].id` (**string**), and the `id` handler takes at most sixteen hex digits through
  `strtoull` base 16 (`0x50f00`). That fits every hardware round: builds carrying a numeric `id`
  aborted with no request behind them, builds without `id` parsed cleanly and read zero. `id` is
  now the `%016x` string; `deviceId` is untouched, since that table skips it.
- **The setting document follows the console's parse table, not its serialiser tables.** The typed
  table for this document (`0x13c8c0`) has `snsPostRestriction` and `vrRestriction` as bare
  strings, `ratingOrganization` inside `customSettings`, and `applications` as an object keyed by
  title id inside `ugcRestriction`. The v0.38.0 shape put objects where strings are parsed, which
  would have been the next 2142-0234 once the search got through. This is a later stage than the
  search — the search parser never reads the embedded setting — so the traffic log tells the two
  apart: a failure with no request after the search is the first change, one after it is this.
- Server error identities were never in play: they map to 2142-2001…2017 (`.text 0x5ab80`).

## v0.40.0 — 2026-09-27

- **The default level is `NONE`, not `CUSTOM`.** CUSTOM was the guess for two builds and failed both
  times with nothing else in play: no unlock code in the response, a fully permissive
  `customSettings`, and the console reporting parental controls as not set up. pctl's check permits
  everything while the restriction state is empty, so a level meaning "restricted, with custom
  rules" is what makes it non-empty and sends the console into the age comparison at all. The
  permissive `customSettings` stays underneath in case the level is not the only thing read.

## v0.39.0 — 2026-09-27

- **`unlockCode` is withheld until a console has claimed the record.** The restriction check returns
  "permitted" unconditionally while pctl's eight-byte slot at `+0x799` is empty, and an eight-digit
  code is exactly what fills it — so sending one during setup switches restrictions on before the
  console has an allowance to judge against, which is 2142-0234. The console reports parental
  controls as *not* set up, so nothing else can be filling that slot. The code stays on the record
  and now travels only once `activated` is true, where it does its real job: lifting a restriction.

## v0.38.0 — 2026-09-27

- **The setting document had the right names from the wrong schema.** `safetyLevel` and the
  `is...Restricted` booleans come from pctl's *local savedata* table; the moon document's own table
  nests differently, and the console refused the flat version with 2142-0234 again. It now sends
  what that table spells: `parentalControlSetting` holds `functionalRestrictionLevel` and
  `customSettings`; `customSettings` holds `ageRestriction{restriction, ratingAge,
  ratingOrganization}`, `ugcRestriction{restriction}`, `snsPostRestriction{restriction}`,
  `vrRestriction{restriction}` and `applications`.
- The level is `CUSTOM` with an explicit age of 18, not `NONE`. `NONE` may leave the allowed-age
  byte unfilled, and that is the exact branch that refuses — so the permission is stated rather
  than implied.
- Confirmed by the same attempt: `id` is read correctly now. The console made no zero-id request,
  so it got past the device id and failed only on the setting.

## v0.37.0 — 2026-09-27

- **`id` is the field the console reads the device id from**, and v0.36.0 removed it on a wrong
  hunch. Three attempts on hardware settle it: a hex string in `deviceId` was read as zero; a
  number in `deviceId` alone was *still* read as zero; only the build that also carried `id` got
  past the id and on to judging the setting. `deviceId` does not appear in pctl's device field
  table at all, which fits. Both keys now travel, carrying the same number.
- **A record states "nothing is restricted" instead of leaving it absent.** 2142-0234 is pctl's own
  restriction refusal, raised locally with no request behind it: its check returns success while the
  PIN slot is empty, and past that it reads an allowed age and refuses when the byte is unset. So
  silence reads as block-everything. The record now embeds `parental_control_setting`, because the
  console read it from the search answer and made no second call, with names and values from pctl's
  own tables — `safetyLevel` NONE, `ratingOrganization` PEGI, `ratingAge` 18, the three booleans
  false. `activated` travels too; it sits beside the setting in the same table.
- **Each record mints an eight-digit `unlockCode`.** pctl copies at most eight bytes into its PIN
  slot and validates the eighth as a digit. Because the parent side holds that code, a forgotten
  console PIN is recoverable through OpenPak rather than through Nintendo support.

## v0.36.0 — 2026-09-27

- **One live pairing code per account.** Asking for a code now replaces the last unclaimed one
  instead of adding another record: the app was listing four, only the newest was being typed, and
  every one of them was a way to attach a console. Records a console has already claimed are
  consoles, not codes, and are left alone.
- **The extra `id` key is gone from the device object.** v0.35.2 made `deviceId` a number *and*
  added `id` beside it; the console answered 2142-0234 with no request behind it, which is a parse
  failure rather than a network one. Two changes in one build, so the guess is being unwound one at
  a time — pctl's reader looks strict, and a field it has no slot for is the likeliest thing it
  refused. A test now fails on any field pctl's own strings do not name.

## v0.35.2 — 2026-09-27

- **`deviceId` is a number, and that is what error 2142-2009 was.** On hardware the pairing-code
  search succeeded — the console accepted the `{items,count}` envelope and read the record — and
  then asked for `/moon/v1/devices/0000000000000000/owners`. It had parsed the hex *string* we sent
  as zero, got a 404, and raised 2142-2009 (module 142 is pctl). The id now travels as a JSON
  number, and `id` carries the same value beside `deviceId` in case that is the field it reads: an
  extra key costs nothing, another trip to the console costs a day. This settles §7 P2.
- New device ids are capped at 48 bits. A reader that keeps JSON numbers in a double rounds
  anything past 2^53, which would send the console after a device that does not exist. 2^48 is
  still 281 trillion ids and formats as the same sixteen hex digits its paths use.
- Confirmed on hardware and not changed: the search envelope, the `filter.links.pairingCode.code.$eq`
  query, six-digit codes, and the bearer being the dauth device token.

## v0.35.1 — 2026-09-27

- **The pairing code is six digits.** The console's entry field takes nothing else — the first
  hardware finding of the parental-controls work, and it settles the open question the firmware's
  strings could not (the base32 and base64 tables in pctl's rodata belong to something else). The
  first cut minted six characters from a no-ambiguous-glyphs alphabet, which produced codes that
  could not be typed at all. Codes are now drawn uniformly over the whole 10^6 range, leading
  zeros kept.
- **The code search caps blind guessing** at 30 misses a minute, refusing even a valid code for
  the rest of the minute once tripped. A million codes is small when the host is reachable from
  the internet, and a guessed code attaches a stranger's console to someone else's record. One
  global counter, not per-IP: Traefik splices the console connection, so no handler here sees a
  source address. Per-IP when PROXY protocol lands.

## v0.35.0 — 2026-09-26

- **moon: a console can pair.** The console-facing endpoints of the parental-controls API are
  served, not just logged: the pairing-code search, `activate`, the device read/update/unlink, the
  owners pair, the `parental_control_setting` document with an ETag and a `304` for
  `If-None-Match`, `whitelisted_applications`, the events upload and `players`. Only `copy` still
  refuses — there is no second console to copy from yet, and inventing a source would be a lie.
  Field names come from the firmware's own strings (the docs repo's switch study, §4); the shapes
  are **unproven**, so the phase-0 dump stays on beside every answer and the first on-console
  pairing is what corrects them.
- Two unknowns are made self-correcting instead of fatal. A device id resolves whether the console
  spells it as the hex its own paths use or as decimal, so a wrong guess costs a log line rather
  than a failed pairing. An unknown pairing code answers an empty `{items,count}` list rather than
  a 404: "which device has this code" is a question, and "none" answers it — a 404 reads as an
  outage.
- Authorisation is the dauth device token, whose `sub` this server already mints. `activate` is the
  only call a console may make before it has claimed a record; afterwards a record answers only to
  the console bound to it, so one household cannot read another's restrictions, and a claimed
  record does not change hands on a second `activate`.
- Play-time uploads are kept as received, newest 200, and not interpreted: the parent side has
  nothing to show from them yet, and a console that cannot hand them over spools retries forever.

## v0.34.1 — 2026-09-26

- tls: `api-lp1.pctl.srv.nintendo.net` joins the fixed multi-SAN cert, for the same reason
  `api-lp1.frs.srv.nintendo.net` did one release ago. It was still on the on-demand path, and a
  console that authenticates the name strictly answers an on-demand leaf with a handshake EOF
  before sending anything — which would leave moon's phase-0 gate waiting for a log that can
  never arrive, looking like a console that never tried. Added ahead of the first on-console
  pairing attempt rather than after it.

## v0.34.0 — 2026-09-26

Merges the two lines that had diverged since v0.31.0: the presence releases (v0.32.0, v0.33.0)
were tagged off a branch that never reached `main`, so `main` and the released images each held
work the other lacked. Everything is on one line again and the released content is unchanged —
this release adds to it rather than replacing anything.

- moon: parental controls, phase 0. `api-<env>.pctl.srv.nintendo.net/moon/v1/…` is the only thing
  the pctl sysmodule needs from a server; the PIN, restriction level, play timer and bedtime alarm
  all live in pctl's own savedata and work offline, so what dies without us is pairing with the
  parent app and the settings sync. This phase logs what the console sends and refuses in the
  shape pctl recognises, including its literal error identities, plus the pairing store and the
  app's two calls. The ten paths and their bodies are meant to be *read off* one on-console
  pairing attempt, not invented — later phases are written against that log.
  Contract: `docs/switch/parental-controls-firmware-2026-09-26.md`, PRD
  `prds/native-switch-parental-controls-prd.md`.
- ci: the release workflow pins its runner image and moves to `actions/checkout@v5`.
- frs: the comment claiming an empty recommendations body failed the console's parse is corrected.
  The result table at `0x222448` maps rapidjson error 1 (document empty) to success with 0 items;
  a *malformed* body is what fails, as 2121-0101/-0102/-0103.

## v0.33.1 — 2026-09-26

- tls: `api-lp1.frs.srv.nintendo.net` joins the fixed multi-SAN cert. It was never on it, so
  every process minted the FRS host a fresh self-signed leaf on demand — and the friends module
  authenticates that name strictly. On 2026-09-26 the id_token step finally started working and
  the suggestions chain completed once at 05:08; by 16:23, after a restart regenerated the cert,
  the console opened TLS and answered `TLS handshake error: EOF` without sending a request. The
  same lesson is already recorded here twice, for the dauth names (2123-0013) and pearljam.
- na: `/2.0.0/users/me` advertises a `links.nintendoNetwork` entry. The Add Friend applet has
  never asked FRS for `type=nintendo_3ds` or `nintendo_network_id` in 30 days although IPC 20301
  is reachable, and an empty `links` object was the one precondition we were visibly failing. The
  id is the core PID as a stand-in; the real shadow PNID is the follow-up if the panes appear.

## v0.33.0 — 2026-09-26

- presence: a game server's login is the playtime signal. After a successful
  `POST /internal/switch/identity` (NEX, NPLN, Demonware) or `POST /internal/photon-identity`
  (Photon), the player is sent to the core's `Sessions.MarkOnline` (account id, namespace
  `switch`, no title), which starts the playtime clock on their live titled session. Fire and
  forget on its own goroutine with a 5 s timeout, so a login is never slowed or failed by it;
  failures are logged at most once a minute. Nothing is sent without a core client or for a pid
  with no account, and a failed lookup marks nobody.
- accountpb: refreshed `sessions_invitations` from account v0.12.0 (`Sessions.MarkOnline`).

## v0.32.0 — 2026-09-26

- presence: the emulator's OS rides into the core session. `X-OpenPak-Client` is now
  `<client>/<version> (<os>)`; the `(<os>)` part (windows, macos, linux, android, ios, any case,
  stored lower case; anything else or missing is "") is kept on the device claim beside the
  client and sent as `RegisterSessionRequest.os` on every registration — the login's title-less
  session, the presence PATCH and the reconciler's re-registrations — so the website can mark a
  title tested per emulator and OS from playtime. A change of OS re-registers the session like a
  change of client does. Real consoles and older emulators send no OS.
- accountpb: refreshed `sessions_invitations` from account v0.11.0 (`os` on
  `RegisterSessionRequest`/`Presence`, `Sessions.GetPlaytime`).

## v0.31.0 — 2026-09-26

- t17: removed. Team17's backend now has its own service, **`servers/t17`**, which Traefik routes
  the three `*.t17service.com` names to directly. The capture spike here said from its first commit
  that it should move once the protocol was known; it is known (`servers/t17/docs/protocol.md`),
  so it has. `T17_SELF_HOST` is no longer read.

## v0.30.0 — 2026-09-25

- t17: `displayName` carries a `#` tag. T17BE splits `displayNameFull` at `'#'` to derive the
  short name, and the split helper (0x6975a0) **returns false when the separator is absent** —
  which sends `PreInitialise` down "Problem splitting the displayNameFull into short!!" and fails
  the entire init. That path has no error string of its own, so it produced exactly the observed
  symptom: auth succeeds, then nothing, no socket and no diagnostic. A plain `"<user-a>"` could
  never have worked. Names without a tag now get a stable four-digit one derived from the BAAS id.

## v0.29.1 — 2026-09-25

- t17: `blockList` goes back to being a JSON **array**. v0.28.5 made it a string on the strength
  of the native `__ParseInitialBlockList`, but the native side never sees this JSON — C# rebuilds
  one for it. The C# field is declared `array[]` and the deserialiser is
  `JsonUtility.FromJsonOverwrite` (called from `WebRequest::UpdateWaitForResponse`, 0x4c0fefc),
  which **throws on a type mismatch** and takes the whole auth step down silently.
- Field types now come from the metadata field table rather than inference: exp/ttl `int32`,
  `killSwitchActive` bool, `blockList` array, the other eight strings. A test asserts each one.
- Corrects v0.29.0's reasoning too: JsonUtility ignores unknown keys and defaults missing ones,
  so the `apiVersion`/`killSwitchActive` changes were tidiness, not the fix.

## v0.29.0 — 2026-09-25

- t17: the get-token reply now matches the **C# response class** exactly — twelve fields:
  websocketUrl, token, exp, ttl, displayName, globalPlayerId, role, blockList, version, deviceId,
  platformId, **killSwitchActive**. Two corrections fall out of reading it: `killSwitchActive` was
  never sent, and `apiVersion` was sent but belongs to a *different* class
  (`SimpleCorePreInitData`), not to this reply.
- The C# is the real gate, not the native SDK. `BE_PreInitialise` is a P/Invoke stub that passes
  native a single string, and `GetT17AuthJson` **rebuilds** that string from the managed object —
  so the eleven fields `T17BE_Transport::PreInitialise` demands are produced by C#, and our reply
  only ever had to satisfy the C# model.
- Read without a working IL2CPP dump: both Il2CppDumper and Il2CppInspectorRedux fail on this
  build because the compiler folded `g_CodeRegistration->codeGenModules` into a constant.
  `scratch/il2cpp_methods.py` maps 117,803 method names to addresses from the code-gen module and
  metadata tokens instead; the class fields come from the metadata field table, where a class's
  fields are contiguous.

## v0.28.5 — 2026-09-25

- t17: `blockList` is a **string** holding JSON (`"[]"`), not a JSON array.
  `T17BE_FriendSystem::__ParseInitialBlockList` (0x669acc) passes the value to 0x670180 — the
  same parser `PreInitialise` runs on the whole reply — so an array is a JSON chunk it cannot
  parse. `exp` and `ttl` are confirmed numbers (read with `ldr w8,[member+0x18]`) and `version`
  a string (string-assign helper 0x1f4b9f0), so the rest of the reply matches the code.

## v0.28.4 — 2026-09-25

- t17: send `version`, the eleventh key. Recovered from the binary rather than guessed:
  `T17BE_Transport::PreInitialise` (0x68f2c0 in 1.3.315) looks its keys up in a fixed order,
  twice — a validation pass that names the ten it can complain about, then a fill pass ending at
  `version` (0x6901a4), which has no error string of its own. That is why a ten-field reply was
  accepted over HTTP and then dropped without a word and without the socket ever opening.
  Tooling for the recovery lives in `scratch/arm64xref.py`.

## v0.28.3 — 2026-09-25

- t17: back to a flat get-token reply, plus `apiVersion`. The envelope probe changed nothing, and
  the C# side settles the shape: `SimpleCorePreInitData` — the class built from this reply — has
  `_websocketFullConnectionString _websocketUrl _role _blockList _apiVersion ttl bAllOK
  bKillSwitchActive`, and every one of the ten native field names also appears in the C#
  metadata. So the names were right and the reply is flat; `apiVersion` is what was missing.

## v0.28.2 — 2026-09-25

- t17: probe the get-token envelope. Ten flat fields were accepted over HTTP and then silently
  discarded — the game neither opened the socket nor named a missing field, which is what
  `__ParseJSONObject --> No Header for Response - REQUIRED FOR RESPONSES!!` does. The reply now
  carries the same fields flat, under `body`, and beside a `headers` object at once, because
  every guess costs a console relaunch. Prune to the shape that opens the socket.

## v0.28.1 — 2026-09-25

- t17: get-token answers all **ten** fields PreInitialise demands, not six. The game
  authenticated against v0.28.0 and then went silent, never opening the socket, because
  `deviceId`, `globalPlayerId`, `role`, `exp` and `ttl` were absent — and the player id key is
  `globalPlayerId` here, not the `globalID` used elsewhere. The list is not guesswork: the
  binary carries one "Backend Missing required <field>!!!!" string per field.

## v0.28.0 — 2026-09-25

- t17: answer `POST <xplayurl>auth/get-token`. The console sends its own BAAS id_token (one we
  signed), so the backend verifies its own token rather than asking Nintendo — the
  `servers/demonware` pattern. The reply carries `token`, `websocketUrl`, `displayName`,
  `platformId`, `globalID` and `blockList`: every one of those names is a standalone string in
  the game's binary, where `authToken`, `globalId` and `blocklist` are not.
- t17: accept the T17BE websocket and log its frames (RFC 6455 by hand, stdlib only). Nothing is
  answered yet — this is how the message envelope gets read off a real client.

## v0.27.0 — 2026-09-25

- t17: answer `directory.t17service.com` ourselves when `T17_SELF_HOST` is set, handing the game
  `game.<host>` and `xplay.<host>` instead of Team17's addressing. The real service answers with
  an **empty** `game.url` (`http:///`) for this title and tier, which is why Moving Out 2 stops
  at "An error has occurred connecting to T17 services" before it ever reaches Photon. Because
  the directory is the only address the game is given, this points it at OpenPak without
  redirecting `*.execute-api.eu-west-1.amazonaws.com`. Unset keeps the passthrough capture.

## v0.26.0 — 2026-09-25

- t17: Team17's backend (`*.t17service.com`) is redirected here and read — every request is
  logged and passed to the real service, whose reply is logged too. Moving Out 2 asks
  `directory.t17service.com` for an auth token and a `websocketUrl` before it ever reaches
  Photon Fusion; this records that exchange. `T17_PASSTHROUGH=0` answers 404 instead.
  A capture spike: it moves to `servers/t17` once OpenPak answers for itself.

## v0.25.3 — 2026-09-24

- deps: grpc 1.83.2, x/net 0.59 (Dependabot)

## v0.25.2 — 2026-09-24

- netdiag: `/v1/ip` carries `global_ip` and nothing else [26c23ef]

## v0.25.1 — 2026-09-24

- netdiag: answer the global IP probe under `global_ip` [cee3880]
- ci: build scratch in the workspace/runner temp, not `/tmp` or the checkout

## v0.25.0 — 2026-09-23

- The eShop and OpenPak Online follow the website's 2026-09 design language (tokens from
  `website/web/src/input.css`): Inter, the indigo accent, pill navigation and buttons, the
  gradient primary button, hairline-bordered 20 px cards, chip badges and eyebrow labels.
  The eShop is light with the website's dark palette when the console asks for dark;
  OpenPak Online stays blue in the website's hero style (indigo depth, glow, dot grid,
  gradient wordmark, glass cards).

## v0.24.0 — 2026-09-23

- OpenPak Online uses illustrated icons for its six features (grid and page headings),
  served from the binary at `/_openpak/icon/<name>.png`.

## v0.23.0 — 2026-09-23

- OpenPak Online: the mark, Complete Guide and the wide button appear on the main page only;
  each topic page uses the full width with larger text, so no page needs scrolling.

## v0.22.0 — 2026-09-23

- OpenPak Online is sized from the screen it gets (the console's own button bar takes the
  bottom of the 720), so the wide button no longer hides under that bar; the logo shows in
  its own colours on a white badge instead of as a white disc. The console's bar was
  confirmed on hardware showing only Back and Confirm.

## v0.21.0 — 2026-09-23

- **OpenPak Online (Switch Online) is all blue** and laid out like Nintendo's: the OpenPak
  Online mark and a Complete Guide button on the left, the page on the right (the home page
  is a 3×2 grid of the features), dots between L and R, and one wide button at the bottom.
- **The console's button bar shows only Confirm and Back** on the eShop and Switch Online
  pages: both drive `window.nx.footer` (unsetAssign for X/End and the zoom buttons,
  setAssign for A, B and, on Switch Online, L/R), and pinch zoom is off. The footer API is
  unconfirmed on 22.5.0, so what it offers and each call's outcome are reported.
- L/R reached the page on hardware (v0.20.0); a press that arrives twice turns one page.

## v0.20.0 — 2026-09-23

- eShop and Switch Online pages lose the bottom bar: the console draws its own button hints.
- The eShop shows the signed-in user's own avatar in a circle, top right
  (`/ashigaru/api/v1/me/avatar`, the same picture the console profile uses).
- The eShop sidebar drops Nintendo Switch Online and Redeem Code; the scenes systemWeb opens
  for them still answer.

## v0.19.0 — 2026-09-23

- **eShop, laid out like the console eShop** in OpenPak purple and blue: a sidebar (Highlights,
  Search, Your Titles, Recent Releases, Recently Updated, Nintendo Switch Online, Redeem
  Code), a two-column card grid with NEW and OWNED badges, a detail view with one action
  button, and a footer with the B/A hints. B goes back, and from a section leaves the shop.
- **The eShop opens faster**: the catalog renders at once instead of waiting up to 4 s for
  the account; the view refreshes when sign-in arrives.
- **Sign-in in the shop**: on 22.5.0 `nx.shop.requestNaIdToken` exists and throws "Not
  enough arguments" with a callback alone (hardware, 2026-09-23). The likely signatures are
  tried in turn and the first that works, the declared arity and the result are reported.
- **Switch Online pages**: seven pages (Home, Online Play, Save Data Cloud, Smartphone App,
  Across Consoles, FAQ, Help & Guides) on a tab bar that L and R move through. The keys L
  and R send are not known yet, so the likely ones and gamepad buttons 4/5 are all taken,
  and every key the page sees is logged once through `/_openpak/diag`.

## v0.18.0 — 2026-09-23

- **Voice-chat lobby**: the znc `/lobby/` page is now OpenPak voice chat's console side. It
  tells the player to open the OpenPak app → Voice chat and shows their game room's code and
  how many players are in voice, from `/_openpak/voice` (the console's account, asked of the
  website's `/internal/voice/room` with `WEBSITE_INTERNAL_URL`/`WEBSITE_INTERNAL_KEY`).

## v0.17.0 — 2026-09-23

The four eShop P2 leftovers that v0.16.0 answered with stubs are now features (evidence
and what stays unverified: `docs/native-shop.md`, "After v0.16.0"):

- **Digital bundles**: a catalog title may declare a `bundle` of applications (with an
  `is_upgrade_edition` flag). beach `digital_bundle/contents` lists the bundle of every
  title the device's linked accounts own; `target/set` redeems it for the presenting
  account (real entitlements, so the titles install through edge tokens and atum) and
  records the redemption per device; `target/clear` undoes it, revoking only what the
  redemption granted. `redeemed_status.digital_bundle` is true once a bundle is fully
  redeemed. Editable through the store admin API (`bundle` on the title object);
  entitlements now carry `source`.
- **bvc firmware blocklist**: operator-managed through
  `/internal/store/firmware-blocklist`, persisted. A listed version gets 200 (NIM refuses
  it with 2137-8164); anything else gets 404. Both answers copy Nintendo's Akamai headers
  and bodies.
- **idbe**: icon files for 3DS and Wii U title ids (the only ones the console asks for —
  its consumer is cabinet, the amiibo settings applet) are Nintendo's own, fetched once
  from `idbe-ctr`/`idbe-wup.cdn.nintendo.net` over TLS pinned to Nintendo's CA, checked
  for size and header the way cabinet checks them, cached under `$NX_DATA/idbe/` and
  served with an ETag (304 on `If-None-Match`). Switch ids and upstream misses stay a
  logged 404. No key is held; nothing is re-encrypted.
- **pearljam** `/civil`, `/sugar`: any suffix and verb is answered `200 {}` when the
  endpoint's device and account tokens verify, `401` with `$.error.code` otherwise; every
  request is kept in full under `$NX_DATA/pearljam/`. NIM is a pass-through for its IPC
  caller, so the shape is unverified until a console sends one.

## v0.16.0 — 2026-09-23

The P2 leftovers from `../docs/switch/native-news-eshop-nso-gap-22.5.0-2026-09-23.md`
(evidence and addresses in `docs/native-shop.md`, "P2 leftovers"):

- **Voice-chat lobby**: `web-<env>.znc.srv.nintendo.net/lobby/*` serves a controller-first
  page ("Voice chat isn't available on OpenPak yet"); Close navigates to the Lobby shim's
  callback URL `https://localhost/lobby/`. It used to hit the catch-all 404.
- **beach `redeemed_status`** answers `{"digital_bundle":false,"pre_install":false}`. NIM
  requires both booleans; the old `{"redeemed":false}` failed the call.
- **beach `digital_bundle/contents`** answers `{"contents":[],"redeemed":false}` (element
  shape `application_id`/`is_upgrade_edition`/`redeemed` recovered). It was a recorded 404.
- **bvc** (`bvc-hac-<env>.cdn.nintendo.net/<major>-<minor>-<micro>`): always 404. NIM treats a
  200 as "this firmware is refused" (2137-8164), so the catch-all was the right status by
  accident; now it is deliberate and logged.
- **idbe** (`idbe-hac.cdn.nintendo.net/icondata/…idbe`): a logged 404. NIM passes the body to
  its caller unread and no 22.5.0 module names the format, so no icon data is invented.
- **pearljam** `/civil`, `/sugar`: still a recorded 404; what a second pass recovered (headers,
  retry policy, `$.error.code`) is in `eshop_unserved.go`.
- Docs: the `dispatchEvent` provenance now names systemWeb.

## v0.15.0 — 2026-09-23

- **Store admin API** on the game-API listener (`/internal/store/*`, contract in
  `docs/store-admin-api.md`): title CRUD, publish/unpublish, icon upload, NSP upload of a
  base version or an update (streamed to disk, `NX_SHOP_UPLOAD_MAX_BYTES`, PFS0 parsed,
  content id checked against each NCA's SHA-256, tickets refused, no decryption),
  withdrawing an update, read-only entitlements/tasks per account, download stats.
  Requires `NX_INTERNAL_KEY` (fail closed). Unpublished titles are hidden from every
  console surface. atum now honors a content's offset inside a package, sets its headers
  before the status line, answers HEAD, and counts downloads.
- **Console error reports**: eupld uploads (`receive.hac.<env>.er.srv.nintendo.net/`) are
  kept raw under `$NX_DATA/error-reports/raw/`, decoded (multipart/mixed, msgpack report
  fields, attachment) and forwarded to the website's
  `POST /api/v1/internal/crash-reports` (`X-Internal-Key`), spooled and retried; 4xx
  refusals park in `spool/rejected/`. `NX_ERROR_REPORT_MAX_BYTES`,
  `NX_ERROR_REPORT_KEEP_DAYS`. They used to be discarded.
- **Bans everywhere**: a core account that is banned, deleted or pending deletion is
  refused on BaaS login/federation and every user-scoped BaaS call (`403 banned_user`,
  2124-5110; `404 deleted_user`), the NA token/refresh/authorize/users-me flows
  (`invalid_grant`/`user_banned`; silent authorize redirects
  `interaction_required`/`user_banned`), the link pages, the store principal, Penne
  frontline, Five invitations, and the game API (`403 {"error":"account_banned"}` on
  `/internal/switch/identity`, photon, mint-token, emulator routes, `/api/invitations`).
  State from core `GetAccount`, cached `NX_BAN_CACHE_SECONDS` (30, max 60), dropped on the
  core's ban/unban/delete events, which also close live Penne connections. Fails open when
  the core is unreachable. `/internal/switch/identity` now returns `account_id`.

## v0.14.0 — 2026-09-23

eShop, Switch Online and News against firmware 22.5.0
(`../docs/switch/native-news-eshop-nso-gap-22.5.0-2026-09-23.md`):

- The storefront answers on `hac.<env>.savanna.srv.nintendo.net`, where 22.5.0's systemWeb
  opens the shop: `/top`, `/detail/…`, `/catalog_tickets/…`, `/search/result/conditions`,
  `/my`, `/membership`, `/redeem/input`, `/shelf`; unknown query parameters are ignored;
  `bugyo…/ashigaru/` stays an alias. Close navigates to `eshop://success`. Nintendo-only
  scenes say "not available on OpenPak".
- The bridge: identity through `requestNaIdToken` / `setNsaIdTokenAvailableCallback`
  (looked up across `nx.shop`, `nx.ec`, `nx.account`, `nx.lhub`, `nx`); download is
  task → `requestSyncRights` → `requestDownloadTaskListOnEnd`. The diag page probes the
  22.5.0 names and drops the nine that do not exist. The shop accepts our NSA id token.
- Updates: catalog titles can carry a `patch` (patch id = app id + `800`), picked up from
  `catalog.json` without a restart. tagaya `/tagaya/hac_versionlist` lists every title's
  newest version with an ETag; superfly `/v1/a/<id>/dv` answers the recovered
  `[{title_id,title_type,version}]` array; atum serves patch content under the
  application's edge token; veer `/v5/policy.json` picks atum.
- pushmo `/pushmo/d/<id>.json` lists open download tasks (ns download-task-list shape,
  unconfirmed) with ETag/304; `/p/` is empty; every request is dumped.
- Rights replies carry `accepted_rights_ids` / `skipped_rights_ids`; the edge token is
  issued on `dragons.` and `tigers.` too.
- Routing: `sun.`, `aqua.`, `superfly.`, `atumn*` d4c hosts reach the NIM path table
  instead of atum's 404; beach answers `redeemed_status`, `target/{set,clear}` and records
  `digital_bundle/contents`; vermillion `gw.` tries the NIM routes before its `{}`.
- Switch Online: an Lhub landing page on `*.nso.nintendo.net` (paywall launch included);
  capi answers the Expansion Pack (`ex`) active; `fw-api…/v1/events` answers an empty list.
- News: `NEWS_INTERNAL_URL` forwards `openpak_*` lists and title topics to the news service
  verbatim (`NEWS_INTERNAL_CA`, `NEWS_INTERNAL_SERVER_NAME` for its TLS);
  `POST /internal/news/push` delivers `{"type":"news",…}` to consoles subscribed to the
  topic. A console's topic subscriptions now accumulate instead of keeping only the last.

## v0.13.0 — 2026-09-23

Cross-network presence with client labels:

- `X-OpenPak-Client: <client>/<version>` (ryujinx, eden, citron) is recorded per device claim on
  login and on the presence PATCH; Penne DAPresence claims are `switch`; no header is `""`.
  The client rides into the core session (`RegisterSessionRequest.client`), from the
  reconciler and from the title-less login session alike; a client change re-registers.
- A friend live on another platform (Wii U, 3DS) renders ONLINE with no title id and an
  appField `{"sys_description":"Playing <title> on <label>"}` / `"Online on <label>"`. Title
  names come from the website (`GET /internal/titles/name`, cached, never blocking a
  render). Unverified on hardware whether the system friend list shows the description for a
  friend with no title; `NX_FOREIGN_PRESENCE_DESCRIPTION=0` turns it off.
- `/internal/switch/emulator` friends' presence gains `platform`, `client`, `label`.

## v0.12.58 — 2026-09-23

- Presence: an hourly console login keeps the game; core presence cached per account

## v0.12.57 — 2026-09-22

- ACNH user id is the NSA id; minted-pid records move back

## v0.12.56 — 2026-09-22

- ACNH best friends: friend requests, accept, friends list

## v0.12.55 — 2026-09-22

- ACNH `profile_status`: "ng" latches the Code-of-Conduct refusal; answer "ok" always (the
  remembered failed upload gated Orville, not `profile_status`)

## v0.12.54 — 2026-09-22

- ACNH `profile_status`: "ok" is the reported verdict, answer "ng"

## v0.12.53 — 2026-09-22

- Serve ACNH's island and passport API, resolving warm-client ids
- Emulator identity carries the account's country

## v0.12.52 — 2026-09-20

- Keep the game a console named, and stop counting the menu as a title
- Emulator identity: say which platform a friend is on, and since when

## v0.12.51 — 2026-09-20

- Read presence back from the core, so other platforms show through
- Tell the core which game a console is playing

## v0.12.50 — 2026-09-20

- Keep a presence claim alive while its console is connected

## v0.12.49 — 2026-09-20

- Answer a presence frame first, and mint hex device passwords
- Answer the console again, with the strings it actually waits for
- Invitations expire after 4 h (override read in seconds); a new invitation retires the
  sender's older one for that game
- Settle a delivery against the profile that owns it

## v0.12.48 — 2026-09-20

- Stop offering an invitation once its sender left the game

## v0.12.47 — 2026-09-20

- Stop answering the console's requests: it crashed npns

## v0.12.46 — 2026-09-20

- Answer the console, and build a message it can read

## v0.12.45 — 2026-09-20

- Serve INACTIVE as INACTIVE: a console at Home is not online

## v0.12.44 — 2026-09-20

- Push to each console profile, not to whoever signed in last
- A friend PATCH always answers the whole relationship

## v0.12.43 — 2026-09-19

Friends-contract gaps, from the 22.5.0 friends-module read
(`docs/switch/friends-contract-22.5.0.md`):

- Presence: read the console's DAPresence state byte for PLAYING, always send appField (`"{}"` minimum or the event parser drops it), notify on an appField-only change [c1c2354]
- Invitation event ids as JSON integers or the module drops the whole `friend_invitation_received` [a03f726]
- Read no longer accepts: marking a request read (`/extras/receiver/read`) without `/state` stopped auto-accepting it [5680af2]
- Cancel with the console's spelling, `CANCELED` (one L); only that was rejected [da6fcec]
- Request boxes carry the read flag and honour `offset`/`count`, so the badge clears and pages stop duplicating [280ab50]
- Keep the channel and route a friend request was sent with [879646a]
- Crossed requests become a friendship, answered `AUTHORIZED` so the sender syncs at once [536ff55]
- Blocks: read `targetUserId` on POST and list `items[*].targetUserId` + `targetUser`, the shape the console parses [535e6ba]
- Play log kept per `/extras/<group>/playLog` and shown to who may see it, instead of `""` everywhere and a re-sent `"[]"` each sync [fc8f79d]
- `replace /friendNote` (≤ 20 chars) persists; longer stays the tolerated `invalid_params` [6243cf8]
- Recommendations as JSON `{"items":[]}`; the empty gRPC body failed the 20300 parse [a920477]
- `catalog.json` carries `catalog_id` and `enable_icons: ["nx"]` when the title has art [dcb0083]
- `regenerableAt` is the enforced last-issue + 24 h, not +30 d [a148122]
- Presence/request switches enforced: presence normalizes to SELF/FAVORITE_FRIENDS/FRIENDS, reception-off refuses new sends (crossed sends still complete) [e6235a7]
- Thumbnail URLs versioned `?v=<picture time>` so a new picture invalidates the console's image cache [a55af16]
- `friend_request_received` pushes carry `value.channels` (the sent-with channel, FRIEND_CODE by default) or the console fails the whole event [99a612e]

## v0.12.42 — 2026-09-19

- Presence: read the console's state byte, always send appField [c1c2354]
- Send the invitation event's ids as JSON integers [a03f726]
- docs: catalogue the ZNC voice-chat calls a title makes [f0d6c96]
- internal: /switch/emulator/link-token mints the NA id_token an emulator federates with [181af3a]
- docs: record the Stardew session-port outage and its guards [f426c1c]

## v0.12.41 — 2026-09-16

- Bind the notification channel on the NA token refresh, not only at login [634e4ed]

## v0.12.40 — 2026-09-16

- Deliveries addressed to the BAAS account, not the certificate the console presents: the Penne bearer on `god.*` routes is the device token (subject = certificate), so `NoteAccount` keyed console account ids by a cert that `AccountsFor` could never match and every frame left unaddressed — the friends module drops a zero uid by design; `ResolveUser` at the record sites, `BindConsole` heals cert-keyed entries including on an already-bound login. Found live on prod: a natural presence write reached a connected console with no reconnect (the shape failure is gone) but unaddressed [6d8fe42]

## v0.12.39 — 2026-09-16

- docs: say plainly that prod is two commits behind the carrier fix [680f033]
- N5 answered from the friends module's own init: it registers its own program id (`0x010000000000000e`) as an npns listen key (u64 Listen, proxy slot 5) and starts its `nn.friends.EventWatcher` thread only if Listen succeeds [4009ab2]
- Penne notification carried as the kind-1 message it is: envelope slot 2 string `"NX"`, `PutRecord{[Entry], u8 1}` → `Entry{kind 1 → Message{name, u16, Meta{receivers, 32-hex account id}, body, deliverAt}}`; `BuildMessage`/`ParseMessage`, one frame per account from `AccountsFor`; the six-way `NX_PENNE_RECORD_PROBE` rotation, the refuted PutRecord shape and the record-name constants deleted [522fbe2]
- docs: recover the PutRecord message shape from 22.5.0; close N2, open N5 [4908cdb]
- docs: correct the friend-list branch's fate on origin [4b26bcc]
- docs: record the worktree prune and the retired friend-list branch [56319da]
- docs: move PRDs in-house; scaffold next-session, changelog and shared docs [1e873f3]

## v0.12.38 — 2026-09-12

- Answer the console's LeafHash (0x07): decode the leaf listing and reply in the console's shape behind `NX_PENNE_RECONCILE`; unanswered, the console abandons the sync after the measured ~70 s [481388d]

## v0.12.37 — 2026-09-12



## v0.12.36 — 2026-09-12



## v0.12.35 — 2026-09-12



## v0.12.34 — 2026-09-12



## v0.12.33 — 2026-09-12



## v0.12.32 — 2026-09-12



## v0.12.31 — 2026-09-12



## v0.12.30 — 2026-09-12



## v0.12.29 — 2026-09-12



## v0.12.28 — 2026-09-12



## v0.12.27 — 2026-09-12



## v0.12.26 — 2026-09-12



## v0.12.25 — 2026-09-12



## v0.12.24 — 2026-09-12



## v0.12.23 — 2026-09-12



## v0.12.22 — 2026-09-12



## v0.12.21 — 2026-09-12



## v0.12.20 — 2026-09-12



## v0.12.19 — 2026-09-12



## v0.12.18 — 2026-09-12



## v0.12.17 — 2026-09-12



## v0.12.16 — 2026-09-12



## v0.12.15 — 2026-09-12



## v0.12.14 — 2026-09-12



## v0.12.13 — 2026-09-12



## v0.12.12 — 2026-09-12



## v0.12.11 — 2026-09-12



## v0.12.10 — 2026-09-12



## v0.12.9 — 2026-09-12



## v0.12.8 — 2026-09-12



## v0.12.7 — 2026-09-12



## v0.12.6 — 2026-09-12



## v0.12.5 — 2026-09-12



## v0.12.4 — 2026-09-12



## v0.12.3 — 2026-09-12



## v0.12.2 — 2026-09-11



## v0.12.1 — 2026-09-11



## v0.12.0 — 2026-09-11



## v0.11.0 — 2026-09-10



## v0.10.0 — 2026-09-10



## v0.9.0 — 2026-09-10



## v0.7.30 — 2026-09-09



## v0.8.0 — 2026-09-09



## v0.7.29 — 2026-09-09



## v0.7.28 — 2026-09-08



## v0.7.27 — 2026-09-08



## v0.7.26 — 2026-09-08



## v0.7.25 — 2026-09-08



## v0.7.24 — 2026-09-08



## v0.7.23 — 2026-09-08



## v0.7.22 — 2026-09-08



## v0.7.21 — 2026-09-08



## v0.7.20 — 2026-09-08



## v0.7.19 — 2026-09-08



## v0.7.18 — 2026-09-08



## v0.7.17 — 2026-09-08



## v0.7.16 — 2026-09-08



## v0.7.15 — 2026-09-08



## v0.7.14 — 2026-09-08



## v0.7.13 — 2026-09-08



## v0.7.12 — 2026-09-08



## v0.7.11 — 2026-09-08



## v0.7.10 — 2026-09-08



## v0.7.9 — 2026-09-08



## v0.7.8 — 2026-09-08



## v0.7.7 — 2026-09-08



## v0.7.6 — 2026-09-08



## v0.7.5 — 2026-09-08



## v0.7.4 — 2026-09-08



## v0.7.3 — 2026-09-08



## v0.7.2 — 2026-09-08



## v0.7.1 — 2026-09-08



## v0.7.0 — 2026-09-08



## v0.6.2 — 2026-09-08



## v0.6.1 — 2026-09-08



## v0.6.0 — 2026-09-08



## v0.5.5 — 2026-09-08



## v0.5.4 — 2026-09-08



## v0.5.3 — 2026-09-08



## v0.5.2 — 2026-09-08



## v0.5.1 — 2026-09-08



## v0.5.0 — 2026-09-07



## v0.4.0 — 2026-09-07



## v0.3.0 — 2026-09-07



## v0.2.9 — 2026-09-07



## v0.2.8 — 2026-09-07



## v0.2.7 — 2026-09-07



## v0.2.6 — 2026-09-07



## v0.2.5 — 2026-09-07



## v0.2.4 — 2026-09-07



## v0.2.3 — 2026-09-07



## v0.2.2 — 2026-09-07



## v0.2.1 — 2026-09-07



## v0.2.0 — 2026-09-07



## v0.1.2 — 2026-09-07



## v0.1.1 — 2026-09-07



## v0.1.0 — 2026-09-07



## frozen-20260907 — 2026-09-07



## frozen-20260907 — 2026-09-07

- License: AGPL-3.0 [9cb6f7c]
- debug: log every TLS ClientHello by SNI (spot non-HTTP frontline connections) [c87fe51]
- NSO memberships (capi.lp1.op2) and NA qrcode_param, VPS parity; capi in the fixed cert [0808537]
- VPS parity: full push_channels object, application block in id_token, default thumbnails for unlinked users [bf9168c]
- userObj: etag mirrors bs:did for linked users (VPS parity) [a39a7ea]
- TLS: random cert serials (same-second mints shared a serial) [e391076]
- TLS: fixed multi-SAN cert for every name it covers; on-demand certs only for unrouted SNI (console 2123-0013) [1e7066f]
- Serve nxAccount only from the user's own uploaded blob; drop the global probe constant [329a754]
- Login: a pre-seeded device with an empty password adopts the one it presents (console mirror) [8ed31bc]
- Serve the fixed multi-SAN cert in capture mode; per-SNI certs elsewhere; verbatim nxAccount probe blob [cdbf276]
- Penne/Beach/Vermillion registration answered; profile blob gets a fresh uid [5b67e64]
- Probe: NX_TEST_NXACCOUNT serves a console profile blob in extras.self for linked users [5aa3472]
- Match the captured VPS login: token headers/claims, user object, device snapshot, silent authorize for system applets [51c4546]
- Federation = Restore User: return the account's canonical BAAS user with this console's device account [f9746c8]
- Bisect switch NX_MINIMAL for the federation user object; access token claims per documentation [ec24fc4]
- playLog passed through as the string it already is; NX_DEBUG logs BAAS/NA request and response bodies [66957fc]
- Federation keeps the console's BAAS user id; stale users for the same PID are unlinked [6dd6c54]
- BAAS user object: avatars as https URLs on the cdn-image host, bare friend-code ids [7bc6e9c]
- access token issuer on m-lp1 as well [600b48d]
- BAAS token issuer on m-lp1 too: the console derives its key-set URL from the token and had the VPS keys cached for the old host [3316b19]
- Distinct kid for Nintendo-Account tokens: the console binds kid to issuer and rejects a kid shared with BAAS [bc46aff]
- BAAS token jku on m-lp1: the console caches key sets per URL and had the VPS's for the old URL [31d7964]
- NA tokens and users/me shaped exactly like the captured VPS responses [f9ce2c5]
- capture: mask form passwords in the log [43e8a4a]
- Capture mode (NX_UPSTREAM): pass-through to a real deployment with full request/response logging [e7b71d2]
- users/me: the exact minimal object a console accepts; no scope in the token response [9cadb77]
- users/me: minimal, null-free profile; id lowercase; nickname bounded [2b85c27]
- Adopt unknown device accounts on first use (consoles previously linked to the VPS) [1c94499]
- NA token: scope as string, signed refresh tokens (survive restarts); users/me: timestamp types [4bea7df]
- Server cert validity 2020-2036: a console clock behind ours must not see a not-yet-valid cert [690612a]
- nx-baas: BAAS + Nintendo Account servers for a real CFW Switch, backed by openpak-account [223c063]

