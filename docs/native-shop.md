# Native OpenPak store — implementation notes and review handoff (workstream D)

Implements `../prds/native-switch-store-prd.md` (SHP-01–05, journey J8) against the shared
rules in `../prds/native-switch-social-eshop-prd.md` and the coordination plan
`../prds/native-switch-parallel-plan.md`.

- Branch: `agent-d-native-store`, based on `nx-baas` `main` at `e8b7afc` (clean).
- Verification: `go vet ./...` clean; `go test -race -count=1 .` passes (existing suite +
  new store suite). Reproduce: `cd nx-baas-store && go test -race -count=1 .`
- **No native acceptance gate is claimed.** Every hardware scenario below is *pending*:
  mocks, HTTP success and these tests cannot close SHP-04/05's native install gate.

## What ships in this branch

| File | Owns |
| --- | --- |
| `shop_data.go` | Durable store state: catalog, entitlements, download tasks, beach device links. Idempotent acquisition; stable elicense ids derived from (account, title) so even a lost state file cannot re-mint one. |
| `shop.go` | `hac.<env>.savanna.srv.nintendo.net` (the 22.5.0 shop host): the scene paths `/top`, `/detail/<id>`, `/detail/application_items/<id>/…`, `/catalog_tickets/<id>`, `/search/result/conditions`, `/my`, `/membership`, `/redeem/input`, `/shelf`; plus `bugyo.hac.lp1.eshop.nintendo.net` `/ashigaru/` as an alias. Both hosts share `/ashigaru/diag` (bridge diagnostics) and `/ashigaru/api/v1/*`, the OpenPak-owned JSON API (catalog, ownership, acquire, tasks). |
| `eshop_nim.go` | NIM's download and update hosts: pushmo (download lists), tagaya (version list), superfly `dv` (one title's versions), veer (vendor policy), and the d4c metadata hosts (sun, aqua, superfly, atumn) routed away from atum. |
| `beach.go` | `beach.` (extracted from penne.go's `{}` placeholder), `dragonst.`/`tigers.` and the store rights routes on `dragons.`: device links, elicense publication/availability/revocation, dragons edge tokens, the eticket trust boundary. |
| `atum.go` | `*.d4c.nintendo.net`: c1/c2 content routes, edge-token authorization, HTTP Range resumable download, `/d` hash manifests, missing-content failure propagation. |
| `shop_test.go`, `beach_test.go`, `atum_test.go` | The server-side contracts below. |

## Provenance of every protocol fact used

Labels per parent PRD §2: **source** = public research; **firmware** = 22.5.0 static scan
(strings/Ghidra, private tree `~/openpak-firmware-audit-22.5.0`); **ours** =
OpenPak-defined protocol (no Nintendo counterpart). Nothing here is runtime-confirmed.

| Fact | Label | Origin |
| --- | --- | --- |
| On 22.5.0 the shop is systemWeb (EcUsage) opening `https://hac.%.savanna.srv.nintendo.net/<scene path>`; `ashigaru` occurs nowhere in 22.5.0. Leaving the shop navigates to the `eshop://` callback (`eshop://success`) | firmware | systemWeb `0100000000001042` strings (`https://hac.%.savanna.srv`, the scene-to-path table, `eshop_hac_urls.txt`); qlaunch's LibAppletShop argument blob. The older `bugyo…/ashigaru/` start URL (kinnay wiki, accessed 2026-09-11) is pre-22 and kept only as an alias |
| Bridge function names: shop `prepareSpaceSizes`, `get{Total,Free}Size{Nand,Sd,Usb}`, `requestDownloadTaskListOnEnd`, `getApplicationContentMetaStatusArray`, `requestCleanup(All)PreInstalledApplication(s)`, `cleanupDigitalBundles`, `canJumpToLhubApplet`, `requestUpdateNsaIdTokenCache`, `get/setAdditionalQueryParameters`, `setLanguage`; rights `requestSyncRights`, `cancelSyncRights`, `requestLinkDevice`, `requestUnlinkDevice`; tokens `requestNaIdToken`, `requestEdgeToken`, `setNsaIdTokenAvailableCallback`, `requestNaTokenForProfile`, `getNintendoAccountIdsOnDevice`, `requestSignedDeviceIdentifierForNintendoAccount` | firmware | systemWeb strings. The object carrying each (`window.nx.shop`, `.ec`, `.account`, `.lhub` or `window.nx`) is **not** recovered, so the pages look each name up across all of them. `requestNaAuthToken` and eight more names on the old diag list are absent from 22.5.0 and were removed |
| Bridge events dispatch via `window.nx.dispatchEvent({type:'message',data:…})` with an injected EventTarget | firmware | systemWeb `0100000000001042` strings: the dispatch snippet (rodata `0x993233`) and the `window.nx.EventTarget_` polyfill. On 22.5.0 the shop runs in systemWeb, so that is the copy that matters; LibAppletOff (`010000000000100f`) and openWeb (`0100000000001043`) carry the same strings because they share the engine |
| Beach methods (`/v1/my/devices`, `/v1/my/devices/hac/link`, `/v1/my/devices/hac/unlink_all`, `/v1/devices/<id>/notification_token/register`, `/v1/rom_cards`, `/v1/my/membership/free_trial_availability`) and `{"error":{code,message}}` | source | kinnay wiki, Beach-Server; request shapes corroborated by 22.5.0 NIM strings |
| Dragons host split (dragons: rights/elicense; dragonst: edge tokens; tigers: `/v1/etickets/publish`), API v2 on 22.5.0, `DeviceAuthorization` bearer, elicense/rights-id field shapes, problem-doc errors | source | kinnay wiki, Dragons-Servers |
| Atum routes (`/c1|c2/a/d/<tid>[/<ver>]`, `/c1|c2/t/a/<tid>/<ver>`, `/c1|c2/<tid>/c/(a|c)/<cid>`, `/…/d`), `X-Nintendo-DenebEdgeToken`, c1=dauth token / c2=dragons token, host `{atum-subdomain}.hac.%.d4c.nintendo.net` | source + firmware | kinnay wiki, Atum-Server; NIM strings (`X-Nintendo-EdgeToken`, `X-Nintendo-DenebEdgeToken`, `/c/c/<hex>`, `403/edge_token_not_grantable`, atum-4ff/f03/eda/5a8) |
| `/d` manifest field names; `edge_token/issuable_titles` response shape; beach `/v1/my/devices` response shape; every bridge call's arguments and callback shape | **hypothesis** | Neither the wiki nor the strings document them. Each is implemented minimally, marked at its code site, and listed under "open protocol questions" below. A hardware capture settles them. |
| Rights-id ↔ title-id mapping (last nibble = title type 3) | hypothesis (convention) | Public captures show it; nothing in our flow requires it — we only need determinism |

**Never used as inputs:** earlier material (evidence of observable behavior only), any
Nintendo binary, key or decompiled output. The pages, API and state model are original.

## Requirements ledger

| Req | Code | Tests | Evidence | Status |
| --- | --- | --- | --- | --- |
| SHP-01 launch/routing | `shop.go` savanna scenes + bugyo alias, entry + diag pages; router cases in `main.go`; cert SANs for bugyo/atum/tigers (savanna is served on an on-demand CA-signed cert, and no client certificate is requested there) | `TestShopEntryAndDiagPagesServeThroughRouting`, `TestSavannaServesEverySceneAndTheSharedAPI`, `TestSavannaIsNotAskedForAClientCertificate`, `TestDiagPageProbesThe2250BridgeNames` | diag page probes every 22.5.0 bridge name across the candidate objects and posts results to the bounded in-memory ring; every bugyo/d4c/dragons/beach request is logged server-side so a hardware run records the real sequence | **implemented; hardware pending** (need: native shop launch on the declared Atmosphère setup, actual request sequence, `window.nx.shop` callback results) |
| SHP-02 catalog | `shop_data.go` catalog model (localized text, size, version, compatibility, distribution gate), `shop.go` API + pages | `TestShopCatalogLanguageFallback`, `TestShopCatalogDetailsAndPermissionGate` | fixture catalog with en-US/ja; entries without a recorded distribution permission are dropped at load, never listed | **implemented**; real redistributable title + permission still to be chosen/placed by the owner (runbook below); controller usability needs a console look |
| SHP-03 acquisition/rights | `shop_data.go` acquire (idempotent, durable, elicense ids stable across restart), `beach.go` device link + dragons publish/available/revoke | `TestAcquireIsIdempotentAndDurable`, `TestBeachLinkIsIdempotentAndSurvivesRestart`, `TestBeachLinkRequiresAPrincipal`, `TestDragonsPublishElicensesIsIdempotent`, `TestDragonsAvailableElicensesReflectsOwnership` | acquire twice → same elicense id; restart → same id; publish twice → same id; principal binding enforced (header-only refused) | **implemented server-side; native requestSyncRights behavior pending hardware** |
| SHP-04 download/install | `beach.go` dragons edge tokens (issued only for linked+owned titles), `atum.go` c1/c2 with token-title binding, Range resume, `/d` manifests; eticket publish records and refuses | `TestDragonsEdgeTokenOnlyForOwnedTitles`, `TestAtumC2GateRequiresATokenBoundToTheTitle`, `TestAtumC1AcceptsADtokenShape`, `TestAtumRangeResumption`, `TestAtumHashManifestMatchesTheCatalog`, `TestEticketsPublishIsRecordedNotFaked` | content is served only against a valid token naming the title; the one thing we cannot mint — an ES-trusted eticket — is explicitly refused (501) and logged as spike evidence | **implemented; native install blocked on packaging/trust** — see the proposal below. A web page or 200 does not close this gate. |
| SHP-05 ownership lifecycle | revoke propagation, task state machine (terminal states, missing-content failure), update versioning, per-account entitlements | `TestRevokedEntitlementGrantsNothing`, `TestTaskLifecycle`, `TestUpdateFlowMovesInstalledVersionOnCompletion`, `TestAccountSwitchAndRedownload`, `TestAtumMissingContentFailsOpenTasks` | revoked → nothing grants; cancel terminal; update completes only when the task completes; account B sees/cannot use A's title; missing file fails open tasks with `missing_content` | **implemented server-side; native removal/update/redownload scenarios pending hardware** |
| J8 journey | all of the above | — | — | **pending native reproduction end to end** |

## Wiring patches provided to A (shared-file changes, kept minimal)

All in `main.go` unless noted:

1. `server` struct: two fields added — `shop *shopState`, `shopUI *shopUI` — plus their
   initialization in `main()` (`shop: newShopState(getenv("NX_DATA","/data")+"/shop")`).
   Handlers are nil-safe, so a zero-value `&server{}` (existing tests) keeps working.
2. Router (`ServeHTTP`): five cases inserted **before** the dauth case (dauth's prefix list
   also claims `dragons*`, and switch order decides):
   - `bugyo.` → `s.shopHandler`
   - `*.d4c.nintendo.net` → `s.atum`
   - `dragonst.` / `tigers.` → `s.dragons`
   - `dragons.` **and** `shopRightsRoute(path)` → `s.dragons` (only `/rights/publish_elicenses`, `/rights/available_elicenses`, `/elicenses/revoke`, v1/v2)
   - `beach.` → `s.beach`
   All other `dragons*` traffic keeps flowing to `s.dauth` (its setup-critical answers —
   elicense archives, exercise, migration state, penne id, contents authorization token —
   are untouched and keep the working console link alive).
3. Cert SANs added to the fixed multi-SAN certificate: `bugyo.hac.lp1.eshop.nintendo.net`,
   `atum.hac.lp1.d4c.nintendo.net`, `tigers.hac.lp1.dragons.nintendo.net`
   (`dragons.`/`dragonst.`/`beach.` were already present).
4. `penne.go`: the `beach.` case removed (it answered `200 {}`); nothing else in the file
   changed. Beach hosts are routed to `s.beach` (2. above). B's penne cases are untouched.

Host/path summary for A's Traefik/DNS wiring (hosts must resolve to this service, TLS SNI):
`bugyo.hac.lp1.eshop.nintendo.net`, `beach.hac.lp1.eshop.nintendo.net`,
`atum.hac.lp1.d4c.nintendo.net` (+ any `atum-*` subdomain NIM is configured to try —
on-demand certs cover those), `dragons.hac.lp1.dragons.nintendo.net`,
`dragonst.hac.lp1.dragons.nintendo.net`, `tigers.hac.lp1.dragons.nintendo.net`.

## Console-change proposal (reviewable; NOT authorized by this branch)

Native installation consumes, at minimum, content the console's own trust stores validate:
NCAs signed under Nintendo's chain, an eticket the ES accepts, and (for launching a
digital title) the aauth contents-authorization token flow. OpenPak can serve bytes and
mint *our own* tokens (dcert serves our JWKS, and the dragons aauth CAT is implemented on
that basis), but it cannot mint Nintendo-trusted tickets. Therefore a native install of a
homebrew package requires build-specific console changes, e.g. Atmosphère-level signature
verification overrides for the titles/ES modules — exactly the class of change the PRD
requires to be a reviewable proposal before any console is touched.

Proposed experiment (owner-authorized hardware only, one console, with rollback):

1. Record firmware/Atmosphère build IDs and the active hosts file before anything else.
2. Point the store hosts at the adapter (wiring above); load `/ashigaru/diag` first and
   capture the bridge surface + full request sequence (SHP-01 evidence).
3. Place one redistributable package per the runbook; run acquisition and observe how far
   NIM drives the download against `atum` (edge-token route proves itself here).
4. Only then evaluate the minimum signature/trust override needed for NIM's
   install step, its exact build-ID targets and effects, and roll it back afterwards.

Until that experiment concludes, `tigers /v1/etickets/publish` records the request and
answers 501 with a pointer here. **No NRO-only workflow is substituted for the native
one** — the native path is instrumented end to end and its blocker is named.

## Operator runbook

Catalog: `$NX_DATA/shop/catalog.json` — an array of `ShopTitle` objects (see
`shop_data.go`); an entry **without `distribution.permission` is dropped and logged**.
Content: place package files under `$NX_DATA/shop/content/…`, declare them in the entry's
`content` array (`content_id`, `file`, `size`, `sha256`, optional `offset`) plus
`control_path`/`cnmt_path`. Verify pins after placing:

```
go run . -shop-verify   # (proposed helper; until it exists use: shasum -a 256 file)
```

The catalog's `sha256` must equal the file's; the `/d` manifest serves that pin, and
`serveContentRange` refuses ranges past a file that shrank (missing content fails the
tasks loudly rather than serving short bytes silently).

State: `$NX_DATA/shop/state.json` (entitlements, tasks, beach links; one document,
temp+rename saves). Back it up before upgrades; deleting it loses only entitlement
records — elicense ids are derived deterministically from (account, title), so re-acquire
restores the same identity. Rollback of this branch = redeploy the previous image and
remove the six new hosts from DNS; the state file is inert to the old build.

Diagnostics: `[shop]`-prefixed log lines carry the full request trail; the diag page's
ring holds the last 32 bridge reports in memory only. `NX_DEBUG=1` adds full body dumps
(existing behavior) — mind tokens when sharing logs.

## Open protocol questions (each blocks one native gate; next experiment noted)

1. **Bridge call shapes** — `requestNaIdToken`, `setNsaIdTokenAvailableCallback`,
   `requestSyncRights`, `requestDownloadTaskListOnEnd`, `requestEdgeToken`,
   `prepareSpaceSizes`: which object carries each, argument shapes, callback payloads,
   error reporting. Next: open the shop on the declared console and load
   `/ashigaru/diag` on the savanna host; the page records where each name was found, what
   the safe calls returned and any `message` events, and the server logs the sequence. Blocks SHP-01 completion and the storefront's native flows.
2. **Atum `/d` manifest field names** and `edge_token/issuable_titles` response shape.
   Next: the same hardware capture (NIM's request lands in the log; serve-and-observe).
3. **Eticket/ticket trust** — whether NIM's install step proceeds without an ES-valid
   ticket under a scoped Atmosphère override. Blocks SHP-04's install half; the proposal
   above bounds the experiment.
4. **Beach response shapes** for `/v1/my/devices` and friends (implemented as minimal
   hypothesis shapes). Next: capture on hardware; shapes are isolated in `linkObj`/`beach`
   for one-commit replacement.

Hardware results template: record branch/commit, firmware + Atmosphère build IDs, active
hosts file hash, sanitized request sequence, screen state per step, and restoration steps —
per the coordination plan's test-slot rules.

## Managing the catalog (store admin API)

After v0.14.0 the catalog need not be hand-edited: the website's admin pages call
`/internal/store/*` on the game-API port ([`store-admin-api.md`](store-admin-api.md)).
An upload is an NSP plus the metadata its uploader supplies; the package is kept whole
under `content/<title id>/` and atum serves each NCA from its offset inside it. The API
writes `catalog.json` itself, so hand edits and API edits share one file (an entry with no
`unpublished` key is published). Titles created through the API start unpublished;
unpublished titles are invisible to the storefront, tagaya, superfly, pushmo and atum.

## 22.5.0 surface (2026-09-23)

From `../docs/switch/native-news-eshop-nso-gap-22.5.0-2026-09-23.md` and a further read of
NIM and ns for the update path. Nothing here is hardware-confirmed.

**Scope.** The store carries homebrew and the updates for it. Store titles have no rights
ID, so installs do not go through elicenses or etickets; the dragons/tigers answers stay
defensive (tigers eticket publish is still a recorded 501) and no ticket is ever issued.
Nintendo-only scenes (add-on content, tickets, subscriptions, memberships, codes) render
"not available on OpenPak". **Install trust stays an open decision:** a no-rights-ID
title still needs the console's NCA/ACID signature checks relaxed, which is a console-side
change this adapter neither makes nor assumes.

**The page's native chain.** Acquire (OpenPak API) → create the download task (OpenPak
API; this is what pushmo lists) → `requestSyncRights` → `requestDownloadTaskListOnEnd`,
which makes NIM fetch pushmo, then an edge token, then atum c2. Identity comes from
`requestNaIdToken` or `setNsaIdTokenAvailableCallback`; `shopPrincipal` accepts both our
NA id token and our BAAS-issued NSA id token.

| Host / path | Answer | Evidence |
| --- | --- | --- |
| `superfly.hac.%.d4c` `/v1/a/<app id>/dv` | JSON array `[{title_id, title_type, version}]`: the application (`Application`, base version) and, when published, its patch (`Patch`, patch id = app id with `800`) | **verified**: NIM's reply handler (vtable `0x3280e0`, element callback `0x20f090`) reads `title_id` base-16, `title_type` ∈ `Application`/`Patch`/`AddOnContent`/`DataPatch`, `version` u32. The gap report took `0x20f090` for pushmo's parser; it is this one |
| `tagaya.hac.%.eshop` `/tagaya/hac_versionlist` | `{format_version:1, last_modified, titles:[{id, version, required_version:0}]}`, newest version of every catalog title, ETag + 304 | ns parses `$.last_modified`, `$.titles[].{id,version,required_version}` (ns `0x1f66d0`, `0x1f6950`; id base-16); NIM sends `If-None-Match`. **Unconfirmed:** whether `id` is the application or the patch id (application served) |
| `pushmo.hac.%.eshop` `/pushmo/d/<id>.json` | `{tasks:[{id (UUID), owner_application, titles:[{id, version, type}]}]}` from the open download tasks of the accounts linked to `<id>` (device id, else account id, else the requesting device); ETag + 304 | **unconfirmed**: NIM does not parse the body itself. The shape is ns's download-task-list parser (ns `0x22a090`, `0x22a674`: task id must be 36 characters; type ∈ `Application`/`Patch`/`AddOnContent`/`Delta`/`DataPatch`). Every request is dumped in full |
| `pushmo…/pushmo/p/<id>.json` | `{tasks:[]}` + ETag | meaning of `p` unrecovered; logged |
| `veer.hac.%.d4c` `/v5/policy.json` | `{ttl:86400, weights:[{vendor:"atum", weight:100}]}` | **verified**: NIM `0x2277e0`/`0x228230` read `$.ttl` and `$.weights[].{vendor,weight}` |
| `sun.`, `aqua.`, `superfly.`, `atumn*` `.d4c` | routed to the NIM path table before atum | they used to be 404'd by atum |
| beach `redeemed_status`, `target/{set,clear}`, `digital_bundle/contents` | the device's digital bundle (catalog `bundle`), redeemed by `target/set` into real entitlements | see "Digital bundles" below. The first pass paired `$.digital_bundle` with the contents route; it belongs to `redeemed_status` |
| dragons/tigers `edge_token/issue`, `issuable_titles` | on all three rights hosts; an update id is authorized by its application's entitlement | |
| rights publish/available | `accepted_rights_ids` / `skipped_rights_ids` added | NIM `$.accepted_rights_ids[*]`, `$.skipped_rights_ids[*]` |

**Publishing an update** (operator): place the patch's NCA files, then in the title's
`catalog.json` entry set `base_version` (normally 0) and a `patch` block
(`version`, `version_label`, `content[]`, `cnmt_path`, `control_path`), and raise
`updated_at`. The server re-reads `catalog.json` when its modification time changes, so
the next version-list poll carries the new version with a new ETag; atum serves the
patch's content under the patch id, authorized by the application's edge token.

## P2 leftovers (2026-09-23, after v0.15.0)

From the gap report's P2 list. New Ghidra work is in `ghidra-p2/` in the audit workspace
(`nim.gpr` opened read-only); systemWeb was read with the workspace's disassembly scripts.
Addresses are Ghidra addresses for NIM and ELF vaddrs for systemWeb. Nothing here is
hardware-confirmed.

| Surface | Answer | Evidence |
| --- | --- | --- |
| `web-<env>.znc.srv.nintendo.net/lobby/*` (voice-chat lobby) | **served**: a controller-first page, "Voice chat isn't available on OpenPak yet", Close navigates to `https://localhost/lobby/` (then `endApplet`, then `window.close` if nothing intercepts it). Other paths on the host: recorded 404. On-demand cert, no client-certificate request | systemWeb `ShimUsageLobby::overwriteInternalArgs` (`0x85c65c`): session `LobbyApplet`, start URL `https://web-%.znc.srv.nintendo.net/lobby/` plus `app_id` and, when the caller passed one, `param`; the callback URL `https://localhost/lobby/` and the allowed prefix `https://web-%.znc.srv.nintendo.net/` go through the same two setters the shop shim uses for its `eshop://` callback |
| `idbe-hac.cdn.nintendo.net/icondata/%02x/%016llX[-%hu].idbe` | **refused**: logged 404 (`no icon data`), naming whether the title is in the store | NIM builders `0x1ecc50` (with version, `%hu`) and `0x1eccc0`; `%02x` is bits 8–15 of the id, the id is upper-case hex. The task (`0x28c5e0`, vtable `0x324830`) sends a device-token header, `Accept: application/json` and `If-None-Match`, and has no reply parser: the body goes back to the IPC caller (`0x1b9e60`, `0x1ba0b0`) unread. No other 22.5.0 module names `.idbe`, so the format is not recoverable from this firmware and none is invented |
| `bvc-hac-<env>.cdn.nintendo.net/<major>-<minor>-<micro>` | **served from the operator blocklist** (after v0.16.0): a listed version gets Akamai's 200 (empty `text/plain`, ETag, Last-Modified), anything else Akamai's 10-byte 404 `Not found\n` with no Content-Type | NIM builder `0x1ed990` formats the first three bytes of `set:sys` GetFirmwareVersion; the check `0x238460` turns any success into NIM's own error `0x3fc89` (2137-8164) and an HTTP 404 (`0x39d889`, per the status map at `0x1a56f0`) into success. Headers and bodies copied from `bvc-hac-lp1.cdn.nintendo.net` on 2026-09-23 (see "Firmware blocklist" below) |
| beach `/v1/devices/redeemed_status` | **served** (after v0.16.0 from the device's bundle): `{digital_bundle, pre_install:false}` | NIM `0x234540`: both keys required (else `0x15489`); the reply handler (`0x234a50`) stores each bool as sent, and `0x234540` sets caller flag bit 0 when `digital_bundle` is false and bit 1 when `pre_install` is false. The booleans read "redeemed"; false is the "not yet redeemed" signal |
| beach `/v1/devices/digital_bundle/contents?shop_id=4` | **served** (after v0.16.0 from the catalog): the device's bundled applications | NIM `0x234bd0`, handler vtable `0x328ed8`: `$.contents[]` (max 64) of `{application_id (hex string, base-16), is_upgrade_edition (bool), redeemed (bool)}`, top-level `$.redeemed` (bool). `shop_id` is the constant 4. The IPC result copies the count, the 64 ids (+8), the 64 upgrade flags (+0x208) and the 64 redeemed flags (+0x248) |
| pearljam `/civil`, `/sugar` | **still refused** (recorded 404) | Tried: both URLs are the bases of two endpoint objects (`0x22e430` sugar: 60 s, 10 attempts; `0x22eb70` civil: 60 s, 30 attempts) run by a templated request runner (`0x22d410`) that appends a caller-supplied `{name}` template path and POSTs `application/json`. sugar adds `X-DeviceAuthorization`, `X-NINTENDO-NSA-ID-TOKEN` and `X-Nintendo-Application-Id`; civil adds `X-DeviceAuthorization`, `Authorization: Bearer` and `X-Nintendo-Application-Id`. On error statuses the reply's `$.error.code` is read (`0x22e620`). The success body goes to a request-specific sink (`0x2314b0`) with no selector strings, and none of NIM's `/{version}/…` templates is bound to either endpoint (they belong to dragons' endpoint table at `0x327358`). The direct path `0x22b280` hands base + suffix + body to a persisted request store (`0x1a64e0`). No path or reply shape is recoverable from NIM alone |


## After v0.16.0: the P2 leftovers made real

### Digital bundles

A catalog title may declare a bundle (`catalog.json` or the store admin API):

```json
"bundle": [{"application_id": "0100aaaa00000000"},
           {"application_id": "0100bbbb00000000", "is_upgrade_edition": true}]
```

Buying or owning that title gives every console the owning account is linked to (beach
link) a digital bundle: the bundled applications this store publishes (a bundled id
that is not in the catalog, or is unpublished, is left out because it could never
install). The console sees it through NIM's three beach calls (`eshop_bundle.go`):

| Call | NIM | OpenPak |
| --- | --- | --- |
| `GET /v1/devices/redeemed_status` (device token only) | `0x234540`; handler `0x234a50` stores each bool, `0x234540` flags "not redeemed" for each false | `digital_bundle` is true once the device has a bundle and all of it is redeemed; false when something is waiting or there is no bundle (the v0.16.0 answer). `pre_install` stays false: OpenPak never pre-installs software |
| `GET /v1/devices/digital_bundle/contents?shop_id=4` (device token only) | `0x234bd0`, vtable `0x328ed8` | one element per bundled application, `redeemed` per device; top-level `redeemed` = non-empty and all redeemed |
| `POST /v1/devices/target/set` | task `0x237f30` (flag at `+0x90` = set, URL builder `0x1ed4c0`), device token + `Authorization: Bearer <id token>` of the user at `+0x80`, no body, success body unread | the redemption: the presenting account gets an entitlement for every unredeemed bundled application (the same row a purchase makes, marked `source: bundle:<title>`), the device is linked to it, and the redemption is recorded per device. Idempotent. Without an account: 401 |
| `POST /v1/devices/target/clear` | same task, flag clear (`0x1ed570`) | removes that account's redemptions on the device and revokes only the entitlements they created; a purchased title is never revoked |

Why `target/set` is the redemption: it is the only account-bearing call in the family,
and the console's other strings describe the same act (qlaunch `StReceiveDigitalBundle`,
`StCheckForRedeemable`; the account picker's `ActSelect_DigitalBundleDetail_DlgBodyOwner` /
`…Other`; Nintendo's public bundle FAQ: "the game will be claimed by the Nintendo Account
you selected"). The redeemed titles then install through the ordinary path: edge tokens
(`deviceOwnsTitle`), atum, pushmo.

**Unverified on hardware:** that bit 0 of `redeemed_status` is what makes qlaunch look at
the contents (the consumer is qlaunch/ns, not NIM; its reading of the flag was not traced),
what `target/clear` means to Nintendo, and the reply bodies of `target/{set,clear}` (200
with no body; NIM does not read them).

### Firmware blocklist (bvc)

The operator keeps a list of refused firmware versions (store admin API,
`/internal/store/firmware-blocklist`, persisted in the shop state). A listed version gets
200 and NIM refuses it (2137-8164); anything else gets 404. Both answers are copies of
Nintendo's CDN as observed on 2026-09-23:

- listed: `200`, `Content-Type: text/plain`, `Content-Length: 0`,
  `ETag: "d41d8cd98f00b204e9800998ecf8427e:<unix time>.000000"` (the MD5 of the empty
  body), `Last-Modified`, `Accept-Ranges: bytes`, `Server: AkamaiNetStorage`;
- not listed: `404`, body `Not found\n` (10 bytes), no `Content-Type`, `Accept-Ranges:
  bytes`, `Server: AkamaiNetStorage`.

For reference, Nintendo's own lp1 list on that day answered 200 for 12.1.0 and every
x.0.0 from 13.0.0 to 22.0.0 plus several point releases probed (13.1.0, 13.2.1, 16.0.3,
17.0.1, 18.1.0, 19.0.1, 20.5.0, 21.2.0, 22.1.0), and 404 for 22.5.0 (current), 11.0.1,
12.0.x and everything below. OpenPak's list starts empty: nothing is refused until the
operator lists it.
