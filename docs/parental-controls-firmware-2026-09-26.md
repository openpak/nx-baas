# Parental controls on 22.5.0: what the console asks for, and what OpenPak must build

Source: `~/openpak-firmware-audit-22.5.0/all/pctl` (title `010000000000002E`,
name `pctl` per `all/names.tsv`; `main.elf` + `strings.txt`, the same tree as
`firmware-22.5.0-followup-2026-09-12.md`). Offsets below are file offsets into
`all/pctl/main.elf`. Nothing here is runtime-confirmed: every item says what
would confirm it.

Short version: the on-console half of parental controls needs nothing from us —
it is local (PIN, restriction level, play timer, all in pctl's system savedata).
The half that is dead without a server is the **smartphone-app pairing and
settings sync**, and that talks to exactly one API we have never answered:
`api-<env>.pctl.srv.nintendo.net/moon/v1/…`. DNS, TLS and the CA store already
carry it to us; `nx-baas` answers every path under it with
`{"status":"available","type":"NORMAL"}` (`main.go:2500` → `services.go:83`),
which is a lie the sync layer cannot use. Ten endpoints, one bearer we already
mint, and an ETag contract is the whole server-side job.

## 1. Transport, identity and the client's neighbours

| Fact | Evidence |
| --- | --- |
| Base URL `https://api-%.pctl.srv.nintendo.net`, 15 call sites | 1030216 and 14 copies; the `%` is filled with the environment (`lp1` on retail) |
| `User-Agent: HAC-pctl/2.0/P00 (SDK 22.2.0.0; Add-on 22.2.0.0)` | 1030528 |
| `X-Nintendo-SDK-Version: 22.2.0.0` | 1030589 |
| `Accept: application/json`, `Content-Type: application/json` | 988649, 991902 |
| `Authorization: Bearer %s` | 997400, 999515 |
| The bearer is a **device** token: pctl is a `dauth:0` client | 1088973; no `nas`/`baas` token plumbing appears on the HTTP path |
| libcurl inside pctl (its own copy, not nnssl-only); HTTP/1.1 and HTTP/2 | curl strings throughout 985–1005k; `HTTP/2` 1000034 |
| Methods used: `GET`, `PUT`, `POST`, `DELETE`. **No `PATCH`** | method constants at 1004946 / 989708 / 999540 / 1005692; no `PATCH\0` anywhere |
| Conditional sync: `If-None-Match: %s`, 304 handling, `etag` / `synchronizedEtag` / `vrRestrictionEtag` | 986122, 998311, 989691, 987608 |
| Push, not just polling: pctl is an npns client (`npns:u/s/a`, `npns_create_token`, `notificationToken`) and holds `nn::npns::IDigitalTwinUpdateNotifier` | 992499, 993396, 999580, 997193, 1004260, 1049916 |
| Periodic work is scheduled through `bgtc:t` (background task) as `IntermittentContext<…Executor>` | 1003284, 1028625–1029102 |
| The bedtime alarm banner goes out over `ovln:snd` (overlay notification) | 988026 |
| Also a client of `acc:e:u1`, `nn::account::baas::IManagerBase`, `nn::account::nas::IAuthorizationRequest`, `nifm`, `bsd`, `sfdnsres`, `arp:r` | 1053168, 1055773, 1057084, 1038896, 1034274, 1037568, 1032151 |
| Local state (system savedata): `pt.conf`, `pt.dat`, `pstate.dat`, `sub.dat`, `netDevice.dat`, `mks.dat`, `eventlog.dat` | 1030152–1032037; `CreateSystemSaveData` 987017, `MountSystemSaveData` 1000888 |

The console already resolves this host to us: `*.pctl.srv` is in the dns_mitm
split list the nro writes (`console/openpak-nro/source/hosts.c:228`), and the
`switch` ceiling carries `.nintendo.net` (`website/netprofile-ceiling.v2.json`,
v2). So there is nothing to change on the console to *reach* the API.

## 2. The ten endpoints

Path templates, verbatim, with `%s` = base URL and `%016llx` = a 64-bit id the
server assigns:

| # | Path | Offset | What it is |
| --- | --- | --- | --- |
| 1 | `/moon/v1/devices?filter.links.pairingCode.code.$eq=%s` | 1031259 | the console looks a **pairing code** up — the code is created on the parent side, typed on the console |
| 2 | `/moon/v1/devices/%016llx/activate` | 1030180 | claim/activate the device record found by (1) |
| 3 | `/moon/v1/devices/%016llx` | 1031232, 1031732, 1031795, 1031858, 1031921 | five separate call sites: read device, update device, unlink, online check |
| 4 | `/moon/v1/devices/%016llx/owners` | 1031496 | the parent accounts on this device |
| 5 | `/moon/v1/devices/%016llx/owners/%016llx` | 1031654 | one owner; the second id is a Nintendo-Account-shaped 16-hex id (`nintendoAccountId`, 985417) |
| 6 | `/moon/v1/devices/%016llx/parental_control_setting` | 1031566 | the setting document — the thing that actually restricts the console |
| 7 | `…/parental_control_setting/whitelisted_applications` | 1031383 | per-title exemptions |
| 8 | `/moon/v1/devices/%016llx/players/` | 1031090 | the device's players (and their icons) |
| 9 | `/moon/v1/devices/%016llx/events` | 1031020 | play-time / state events uploaded to the parent app |
| 10 | `/moon/v1/devices/%016llx/copy` | 1031351 | copy settings from another already-paired device |

One call site takes a **bare base URL with no path** (1031196): the icon
downloader, which follows a URL the server put in the players response
(`imageData` 1003604, `IconDownloaderExecutor` 1029345).

Which verb goes with which path is not in the strings. It does not need to be
guessed: the first pairing attempt against a logging handler prints it.

## 3. The client state machine

pctl's vtable type names name every operation (1028625–1030152) — this is the
work list, in the client's own words:

`RequestPairing`, `RequestCopyPairing`, `AuthorizePairing`,
`RetrieveDeviceOwnersExecutor`, `RetrieveSettingsExecutor`,
`UnlinkDeviceExecutor`, `OnlineCheckExecutor`, `UpdateDeviceExecutor`,
`UpdateDeviceAlarmSettingExecutorV1` / `V2`,
`UpdateDeviceExtraPlayingTimeExecutor`, `IconDownloaderExecutor`, plus
`WatcherEventStorage` (the `eventlog.dat` queue behind endpoint 9) and
`IntermittentContext<…>` wrappers that re-run `OnlineCheck`,
`RetrieveSettings`, `UpdateDeviceAlarmSetting` and
`UpdateDeviceExtraPlayingTime` on a `bgtc` schedule.

`AuthorizePairing` + `pairingActive` (986660) + `unlockCode` /
`synchronizedUnlockCode` (1001844, 989712) are the pairing handshake: a code
looked up, a device activated, an unlock code agreed so the parent can release
a restriction remotely.

## 4. JSON vocabulary

Field names, straight out of rodata (985285–1004260). Grouped by the document
they plausibly belong to; the grouping is inference, the names are not.

- **Device**: `deviceId`, `serialNumber`, `firmwareVersion`, `internalVersion`,
  `displayedVersion`, `nickname`, `environment`, `language`, `device`,
  `pairingActive`, `notificationToken`, `lastOnlineCheckedAt`, `lastCheck`,
  `synchronizedAt`, `synchronizedEtag`, `synchronizedUnlockCode`,
  `synchronizedParentalControlSetting`, `updatedAt`, `expiresAt`, `etag`,
  `unlinkReasonFlags`, `statusFlags`, `timeZoneUtcOffsetSeconds`.
- **parentalControlSetting**: `parentalControlSetting`,
  `functionalRestrictionLevel`, `safetyLevel`, `customSettings`,
  `ratingOrganization`, `ratingAge`, `ageRestriction`,
  `isDefaultRatingOrganizationSet`, `isFreeCommunicationRestrictedByDefault`,
  `isSnsPostRestricted`, `isStereoVisionRestricted`, `snsPostRestriction`,
  `ugcRestriction`, `vrRestriction`, `vrRestrictionEtag`, `stereoVision`,
  `safeLaunch`, `whitelistedApplications`, `applications`, `restriction`,
  `restrictionMode`, `visibility`, `shared`.
- **Play timer**: `playTimerRegulations`, `dailyRegulations`,
  `eachDayOfTheWeekRegulations`, `timerMode` (`daily`/`weekly`/`custom`),
  `timerRunning`, `limitTime`, `limitTimeEnabled`, `timeToPlayInOneDay`,
  `startingTime`, `endingTime`, `startTime`, `stopTime`, `disabledTime`,
  `elapsedTime`, `weekUsed`, `duration`, `miscTime`, and `monday`…`sunday`.
- **Bedtime alarm**: `bedtime`, `bedtimeEnabled`, `bedtimeStartingTime`,
  `bedtimeEndHour`, `bedtimeEndMinute`, `bedtimeAlarmTimeMinute`,
  `bedtimeAlarmResetTimeHour`, `bedtimeAlarmResetTimeMinute`,
  `extraBedtimeAlarmTimeHour` / `Minute` / `Second`, `alarmSetting`,
  `alarmSettingFlags`, `alarmSettingState`, `alarmExpire`.
- **Extra playing time** (the "just 15 more minutes" grant): `extraPlayingTime`,
  `extraPlayingTimeExpire`, `extraPlayingTimeFlags`, `totalExtraPlayingTime`,
  `additionalTime`.
- **Events / players**: `eventId`, `eventType`, `eventTimestamp`,
  `applicationId`, `applicationTimes`, `anonymousPlayTime`, `devicePlayers`,
  `acdIndex`, `pdmOffset`, `imageData`, `sourceId`, `changedTypeFlags`,
  `notifyNecessaryFlags`, `payload`, plus the event type names
  `StreamPlayEvent`, `AppEvent`, `AccountEvent`.
- **Envelope**: `items`, `count`, `result`, `status`, `code`, `detail`, `type`,
  `value`, `targets`, `settings`, `current`, `location`, `version`.

`pdmOffset` is the tell that play time is read out of pdm's play-event log and
uploaded as a rolling offset, not recomputed by the server.

## 5. The error contract

pctl carries sixteen error type URIs (988088–1004865). These are the identities
it recognises, so our error bodies must use them rather than a bare status:

`400/firmware_update_required`, `400/invalid_params`, `401/invalid_token`,
`403/forbidden`, `403/insufficient_scope`, `404/resource_is_not_found`,
`404/resource_not_available`, `405/method_not_allowed`,
`406/not_acceptable_language`, `409/over_the_time_limit`,
`409/resource_already_exists`, `400/devices_maxed`, `410/service_terminated`,
`424/failed_dependency`, `500/internal_server_error`, `503/under_maintenance`
— all prefixed `https://moon.nintendo.com/errors/v1/`.

`400/devices_maxed`, `409/over_the_time_limit` and `410/service_terminated` are
the three that carry product meaning: device limit per parent, extra-time grant
refused, service retired.

## 6. What we have to build

**Console: nothing.** DNS, the CA store and the bearer are already in place.
The one unserved side-host is the explainer video
`parentalcontrols-movie-<env>.cdn.nintendo.net/default/switchpc_en.mp4`
(already catalogued in the 22.5.0 follow-up §22c) — if the setup screen blocks
on it, it is a static file, not an API.

**Server (`nx-baas`, one new `moon.go`):**

1. Split `api-*.pctl.srv.nintendo.net` off the `serviceStatus` case in
   `main.go:2500` into a real handler. Keep the `app.lp1.srv` half where it is.
2. A device record keyed by the dauth device id (`cert-<8 bytes>`,
   `dauth.go:206`) with a server-assigned u64 moon id, owners = existing
   `User.NaID` (`store.go:113`), plus a pairing code with a TTL.
3. The ten endpoints, the `items`/`count` envelope, ETag on the setting document
   and `304` for `If-None-Match`.
4. The moon error bodies from §5 for every refusal, including the 404 on an
   unknown pairing code — that path runs before anything else exists and is how
   we learn the verbs and the request bodies.
5. Events: accept and store; nothing needs interpreting until the parent UI
   shows play time.
6. Push: when a setting changes, fire the npns digital-twin notification so the
   console re-syncs instead of waiting for the `bgtc` poll. Reuse the Penne path
   that already delivers to a console.

**Parent surface (ours, not Nintendo's):** the smartphone app is a *client of
the same moon API* in Nintendo's world; for us it can be anything, because only
the console-facing contract is fixed. The cheapest home is the existing Flutter
app (`app/lib/`, beside `friends_page.dart`): show a pairing code, edit the
setting document, view play time, grant extra time, unlink. No imitation of
Nintendo's app-facing API is needed — that is the biggest thing on this list we
get to *not* build.

**Enforcement is local, so also enforce server-side.** The console applies the
setting itself; a modded console or an emulator can ignore it. If parental
controls are to mean anything for OpenPak's own features (chat, voice,
invitations, UGC), the restriction has to be checked where those are served, not
only on the client.

**Emulators (Ryujinx first, then Citron and Eden):** `pctl` is a stub in all
three — Ryujinx hardcodes `_restrictionEnabled = false`
(`Services/Pctl/ParentalControlServiceFactory/IParentalControlService.cs:18`)
and has no savedata; Citron/Eden have the fuller command table but gate
everything on an always-empty `pin_code`
(`src/core/hle/service/pctl/parental_control_service.cpp:294`). The minimum that
makes the feature real on an emulator:

1. Fetch the setting document in `OpenPakSession` (it already holds the dauth
   device token — `OpenPakSession.cs:354`) and cache it.
2. Feed `IsRestrictionEnabled`, `CheckFreeCommunicationPermission`,
   `IsFreeCommunicationAvailable` and the stereo-vision trio from it instead of
   from constants.
3. An OpenPak PIN dialog for temporary unlock, identical in the three
   emulators per the UX-consistency rule.

The play timer, bedtime alarm and event upload are phase 2 there: no game reads
them, and without a System Settings UI they have no surface on an emulator.

## 7. Open questions, and the cheap experiment for each

| # | Question | How it gets answered |
| --- | --- | --- |
| P1 | Verb per endpoint, and every request body | serve §2 paths with a logging handler that returns `404 resource_is_not_found`, then walk the console through *Parental Controls → use smartphone app* and read the log |
| P2 | Shape of the device id on the wire (u64 as number, or hex string) — the URL says `%016llx`, the JSON key is `deviceId` | same session: the console echoes back whatever (1) gave it |
| P3 | Pairing-code alphabet and length | the `$eq=` query prints it verbatim on the first attempt; base36 and base64 tables both sit in pctl's rodata, so do not guess |
| P4 | Whether `activate` precedes or follows `AuthorizePairing` | order of requests in the same log |
| P5 | Whether the setup screen blocks on the explainer video | watch for the `cdn.nintendo.net` movie request; serve a short mp4 if it does |
| P6 | Whether pctl pins a specific built-in CA id | if the request never arrives at all while other nnssl clients work, check the CertStore category the nro writes |

## 8. Reproducing the dig

```sh
cd ~/openpak-firmware-audit-22.5.0/all/pctl
grep -n "moon/v1" strings.txt              # the endpoints
grep -n "moon.nintendo.com/errors" strings.txt   # the error identities
grep -n "Executor\|RequestPairing" strings.txt   # the state machine
```

`scripts/dump-all.sh` rebuilds the tree; it is idempotent.
