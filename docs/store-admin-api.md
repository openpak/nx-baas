# Store admin internal API (contract v1)

The OpenPak store's management surface, served by nx-baas on the **game-API listener**
(`NX_API_ADDR`, default `:20070`, plain HTTP, internal network only). The website's admin
pages are the caller. Everything here is OpenPak-defined; nothing is a Nintendo wire shape.

The store serves **only homebrew titles and their updates, packaged without a rights ID**.
A package carrying a ticket (`.tik`) or a certificate (`.cert`) is refused.

## Authentication

Same scheme as every other `/internal/*` route on this port: header
`X-Internal-Key: <NX_INTERNAL_KEY>` (falls back to `OPENPAK_INTERNAL_KEY`).

One difference: the other internal routes accept any caller when no key is configured
(development convenience). **The store admin routes refuse everything with 503
`internal_key_not_configured` when no key is set**, because they write to disk and accept
multi-gigabyte uploads. A wrong or missing key is 401.

## Errors

Every error is JSON:

```json
{"error": "<machine code>", "message": "<human text>"}
```

| status | `error` | when |
| --- | --- | --- |
| 400 | `invalid_json`, `invalid_title_id`, `invalid_field`, `invalid_metadata`, `invalid_multipart` | malformed input; `message` names the field |
| 401 | `unauthorized` | wrong/missing `X-Internal-Key` |
| 404 | `not_found` | no such title / version / account |
| 405 | `method_not_allowed` | |
| 409 | `already_exists`, `version_not_newer`, `no_base_version` | create of an existing id; update version not above the published one; publish before a base version exists |
| 413 | `too_large` | upload above `NX_SHOP_UPLOAD_MAX_BYTES` |
| 422 | `not_pfs0`, `rights_id_not_allowed`, `no_cnmt`, `content_id_mismatch`, `content_mismatch`, `size_mismatch` | the package failed verification (see "Upload verification") |
| 503 | `internal_key_not_configured` | |
| 500 | `internal` | disk errors |

## Title object

Returned by list/get/create/update. Field names match the catalog file
(`$NX_DATA/shop/catalog.json`), which this API keeps in sync.

```json
{
  "title_id": "0100abcd12340000",
  "published": false,
  "publisher": "Someone",
  "category": "tool",
  "localized": {"en-US": {"name": "My App", "description": "…"}},
  "default_lang": "en-US",
  "languages": ["en-US"],
  "compatibility": ["handheld", "docked"],
  "screenshots": [],
  "distribution": {"source": "https://github.com/…", "permission": "GPL-3.0, author's release"},
  "icon_path": "icons/0100abcd12340000.jpg",
  "size_bytes": 123456,
  "version": 65536,
  "version_label": "1.0.1",
  "base_version": 0,
  "updated_at": 1790000000,
  "application": {"version": 0, "version_label": "1.0.0", "content": [ContentObject…]} ,
  "update": {"title_id": "0100abcd12340800", "version": 65536, "version_label": "1.0.1", "content": [ContentObject…]},
  "bundle": [{"application_id": "0100aaaa00000000", "is_upgrade_edition": false}]
}
```

- `title_id`: 16 lowercase hex digits ending in `000` (an application id). The update is
  always published under the patch id (`title_id` with `800` as the last three digits).
- `published`: only published titles appear in the console storefront, the version list
  (tagaya), superfly, pushmo and atum. New titles start **unpublished**.
- `version`: the newest version a download reaches (the update's when there is one).
- `application` / `update`: `null` when that version was never uploaded. Hand-written
  `catalog.json` entries (no `unpublished` key) read as published.
- `bundle`: the applications that come with this title (a digital bundle, see
  `docs/native-shop.md` "Digital bundles"). A console whose linked account owns this title
  offers them for redemption; redeeming grants the account an entitlement for each. Only
  bundled titles that are in the catalog and published reach the console. `[]` when none.
- ContentObject: `{"content_id": "32 hex", "content_type": "meta|program|control|legalinformation|htmldocument|data|deltafragment", "size": n, "sha256": "64 hex"}`.

## Endpoints

### `GET /internal/store/titles`

`200 {"count": n, "titles": [Title…]}`, every title including unpublished ones, sorted by
`title_id`. The `application`/`update` content arrays are omitted here (fetch one title for
them).

### `POST /internal/store/titles`

Body: a Title object without `published`, `version*`, `application`, `update`,
`size_bytes`, `updated_at`, `icon_path` (ignored if sent). Required: `title_id`,
`publisher`, `localized` with at least one language having a non-empty `name`,
`distribution.permission` and `distribution.source`.

`201 Title` (unpublished, no versions). `409 already_exists` if the id is in the catalog.

### `GET /internal/store/titles/{title_id}`

`200 Title` with content arrays. `404` if unknown.

### `PATCH /internal/store/titles/{title_id}`

Partial update of the metadata fields: `publisher`, `category`, `localized` (replaces the
whole map), `default_lang`, `languages`, `compatibility`, `screenshots`, `distribution`
(both fields required if sent), `bundle` (replaces the whole list; `[]` removes it; each
`application_id` must be 16 hex digits ending in `000`, not the title itself, no
repeats, at most 64; the bundled titles need not exist yet). `bundle` is also accepted on
create. Unknown fields → `400 invalid_field`. Versions and
publication have their own endpoints. `200 Title`.

### `DELETE /internal/store/titles/{title_id}`

Removes the title from the catalog and deletes its uploaded package files
(`$NX_DATA/shop/content/<title_id>/`) and icon. Entitlements and tasks are kept as history.
`204`.

### `PUT /internal/store/titles/{title_id}/icon`

Raw body, `Content-Type: image/jpeg` or `image/png`, at most 1 MiB. The console storefront
shows it. `200 Title`.

### `POST /internal/store/titles/{title_id}/versions`

Upload a base version or an update as an NSP. `Content-Type: multipart/form-data` with two
parts, **`metadata` first, then `nsp`** (the metadata is needed before the package is
accepted; a request with the file first is refused `400 invalid_multipart`):

1. `metadata` — JSON:

   ```json
   {
     "kind": "base",
     "version": 0,
     "version_label": "1.0.0",
     "contents": [
       {"content_id": "…32 hex…", "content_type": "meta", "size": 3584, "sha256": "…64 hex…"},
       {"content_id": "…", "content_type": "program", "size": 4096000, "sha256": "…"},
       {"content_id": "…", "content_type": "control", "size": 180224, "sha256": "…"}
     ]
   }
   ```

   - `kind`: `"base"` (the application content meta, under `title_id`) or `"update"` (the
     patch, under the patch id). An update needs a base first (`409 no_base_version`).
   - `title_id` (optional): when sent, must be the title's application id or its patch id.
   - `version`: the content meta version (u32, `major<<26|minor<<20|micro<<16|…`; base is
     normally 0). For an update it must be greater than the currently published update's.
   - `contents`: every NCA in the package with the type the CNMT records for it. `size`
     and `sha256` are optional per entry (verified when present); `content_id` and
     `content_type` are required. Exactly one `meta`.
2. `nsp` — the package file (any filename). Streamed to disk, never held in memory; the
   request is capped at `NX_SHOP_UPLOAD_MAX_BYTES` (default 8 GiB).

`201` with the Title (content arrays included). Uploading a new base or update replaces the
previous one of that kind; its package file is deleted. Publication state is unchanged: a
published title serves the new version on the next version-list poll.

#### Upload verification

The server does **not** decrypt NCAs (see "Why metadata is supplied" below). What it checks:

1. The file is a PFS0 (`not_pfs0` otherwise) whose entries lie inside the file.
2. No `.tik` or `.cert` entry (`rights_id_not_allowed`): the store serves only titles
   packaged without a rights ID.
3. Every `*.nca` entry is named `<32 hex>.nca` or `<32 hex>.cnmt.nca`, and exactly one is
   `.cnmt.nca` (`no_cnmt`). Other entries (`.cnmt.xml`, `.jpg`, …) are ignored.
4. For each NCA, the SHA-256 of its bytes is computed and **the content id must equal the
   first 16 bytes of that hash** (`content_id_mismatch`) — the Switch's own content id rule,
   checkable without keys.
5. The NCA set equals the `contents` set by content id (`content_mismatch`), the `.cnmt.nca`
   is the one declared `meta`, and any declared `size`/`sha256` equals the measured one
   (`size_mismatch` / `content_id_mismatch`).

The registered content (what atum, pushmo, tagaya and superfly serve) is the measured
size, the measured SHA-256 and the declared type; the bytes are served straight out of the
stored NSP at each entry's offset.

### `DELETE /internal/store/titles/{title_id}/versions/update`

Withdraws the update (the console then sees only the base version). Deletes its package
file. `200 Title`. `404` when there is no update.

### `POST /internal/store/titles/{title_id}/publish` · `POST …/unpublish`

`200 Title`. Publishing a title with no base version is `409 no_base_version`. Unpublishing
hides the title from every console surface, including content delivery to people who
already acquired it.

### `GET /internal/store/accounts/{account_id}/entitlements`

Read-only. `{account_id}` is the **core account id**; the store keys its rows by the
Nintendo Account id the console presents, which this server maps from the account
(`?na_id=<16 hex>` addresses a row set directly, `{account_id}` then being `-`).

```json
{"account_id": "…", "na_id": "…", "entitlements": [
  {"title_id": "…", "status": "active|revoked", "version": 65536, "elicense_id": "…",
   "device_id": "…", "source": "purchase|bundle:<title_id>",
   "created_at": 1790000000, "updated_at": 1790000000}
]}
```

`404 not_found` when the account has no Switch identity here.

### `GET /internal/store/accounts/{account_id}/tasks`

Same addressing. `{"account_id", "na_id", "tasks": [{"id", "title_id", "version", "state",
"fail_reason", "created_at", "updated_at"}]}`, newest first. `state` ∈
`queued|downloading|paused|completed|failed|canceled`.

### Firmware blocklist: `/internal/store/firmware-blocklist`

The firmware versions the eShop refuses (bvc, see `docs/native-shop.md` "Firmware
blocklist"). A listed version makes NIM fail with 2137-8164 before the shop opens, so
list only versions that must not use the store. Versions are `major-minor-micro`, each
0–255; `22.5.0` is accepted and stored as `22-5-0`. Persisted in the shop state file.

- `GET /internal/store/firmware-blocklist` → `200 {"versions": [{"version": "13-0-0",
  "note": "…", "added_at": 1790000000}…]}`, in version order.
- `PUT /internal/store/firmware-blocklist` with `{"versions": [{"version": "13-0-0",
  "note": "optional"}…]}` replaces the list (duplicates collapse; an existing entry keeps
  its `added_at`). `200` with the list.
- `PUT /internal/store/firmware-blocklist/{version}` adds one (optional body
  `{"note": "…"}`; re-adding updates the note). `200` with the list.
- `DELETE /internal/store/firmware-blocklist/{version}` removes one. `200` with the list;
  `404 not_found` when it was not listed.
- A malformed version is `400 invalid_field`.

`added_at` is also what bvc sends as the entry's `Last-Modified` and inside its ETag.

### `GET /internal/store/stats` · `GET /internal/store/titles/{title_id}/stats`

```json
{"titles": [{"title_id": "…", "downloads": 12, "content_requests": 80, "bytes_served": 123456789,
  "last_download_at": 1790000000, "entitlements": 5, "tasks": {"completed": 4, "failed": 1}}]}
```

(the per-title route returns one element, not wrapped; `tasks` only lists states that
occur). Byte counters are saved with the state file; a crash can lose the bytes counted
since the last download was recorded.

- `downloads`: install starts — times the title's (or its update's) meta NCA was served
  from byte 0 by atum.
- `content_requests`: every successful atum content response for the title (ranges
  included); `bytes_served` the bytes written.
- `entitlements`: active entitlements; `tasks`: task count by state.

## Why metadata is supplied instead of read from the CNMT

The CNMT (title id, type, version, content list with types and hashes) lives inside the
meta NCA, whose header and sections are encrypted: the header with the console's NCA
header key, the section with a key-area key derived from the console's master keys. Reading
it would need Nintendo's keys (`header_key`, `key_area_key_application_*`) on this server.
OpenPak does not hold or ship Nintendo keys (clean-room policy), so the server does not
decrypt anything. Instead the uploader, who built the package and knows its metadata,
supplies it; the server verifies everything verifiable without keys (content id = hash
prefix, sizes, the set of NCAs, the absence of tickets). The console itself checks the CNMT
against the content when it installs, so a mis-declared type or version fails on the
console, not silently.

## Environment

| var | default | meaning |
| --- | --- | --- |
| `NX_INTERNAL_KEY` / `OPENPAK_INTERNAL_KEY` | — | the internal key; **required** for these routes |
| `NX_SHOP_UPLOAD_MAX_BYTES` | `8589934592` (8 GiB) | largest accepted upload request |
| `NX_DATA` | `/data` | packages under `$NX_DATA/shop/content/<title_id>/`, icons under `$NX_DATA/shop/icons/` |
