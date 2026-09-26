# Changelog — nx-baas

Generated from git history on 2026-09-15. `git log` stays the source
of truth; this file is the readable summary.

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

