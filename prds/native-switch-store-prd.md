# D — Native OpenPak store

Status: ready for agent assignment. Date: 2026-09-11.

## Objective and owned scope

Deliver OpenPak's homebrew catalog through the native shop applet and prove acquisition,
rights, download, installation, launch, update and redownload. Own SHP-01–05 and J8.
Official Nintendo purchases/payments are outside this release. A working catalog alone
does not complete the store.

## Shared requirements and evidence

Read the [coordination plan](native-switch-parallel-plan.md) before editing. The
[parent PRD](native-switch-social-eshop-prd.md) remains normative for shared scope,
architecture, provenance, security, performance targets, acceptance and review artifacts
(sections 1–3, 6, 8–10). This workstream owns only the requirements listed below;
it does not need to implement the other workstreams to submit its own review package.

Target Horizon 22.5.0; record the actual Atmosphère setup. Use the
[firmware findings](../../docs/switch/firmware-22.5.0-social-eshop-findings.md),
[backend audit](../../docs/switch/native-social-eshop-audit-2026-09-11.md), and public
references linked in the parent. The firmware findings supersede the audit's unknown
friend-list shape. Firmware and Ghidra work remain in the private paths recorded there.
Recheck current source and account contracts before treating historical gaps as current.

Use Go 1.26/project licensing, independent implementation and versioned core APIs;
no direct core database access, copied third-party implementation, secrets or firmware in
commits. Missing core capabilities become concrete contract requests, not adapter-owned
canonical substitutes. Deliver code for review with deployment/rollback instructions;
active deployment and console changes follow the owner's existing authorization.

## Ownership and integration boundaries

Own new store handlers/assets, catalog, rights/entitlement and download state, store
fixtures and tests. Confirm placement within the existing adapter architecture before
creating another service or repository. A owns shared route/TLS/configuration wiring;
provide exact required host/path and dependency patches. Existing Beach placeholders
in `penne.go` must be extracted in coordination with B/A, never overwritten wholesale.

Specify authenticated principal/device needs and a narrow catalog/rights/download
boundary. Reuse B's verified notification transport if the traced store lifecycle needs
it; do not build an independent Penne implementation. Preserve News/saves routes and
current account-link flows. Shared core changes go through the agreed contract process.

## Functional requirements

### SHP: native OpenPak store

- **SHP-01 — Launch and routing.** Prove native shop launch, selected-account handoff,
  required host routing, TLS acceptance and `window.nx.shop` callbacks on the declared
  setup. Start with a diagnostic page and record the actual request sequence. The
  firmware dump does not contain the live storefront or active Atmosphère settings.
- **SHP-02 — Catalog.** Provide controller-usable listing, details, images, language
  fallback, compatibility, size/version and ownership state. Start with one original or
  redistributable homebrew title and record its distribution permission. Provide useful
  empty, loading and failure states; keep protocol diagnostics out of normal store UI.
- **SHP-03 — Acquisition and rights.** Implement idempotent acquisition, durable
  entitlement and required account/device/rights synchronization. Replace relevant
  Beach/license placeholders with actual behavior. Trace which 22.5.0 ticket/device/
  virtual-card operations the chosen journey invokes; implement required operations,
  documenting why unused ones are not release dependencies.
- **SHP-04 — Download and install.** Prove packaging/trust feasibility, metadata/hash
  consistency, authorized content delivery, resumable download and download-task
  lifecycle through install and launch. A web page or available-license flag does not
  prove this gate. Record any required build-specific console changes and their exact
  effects as a reviewable proposal before active installation.
- **SHP-05 — Ownership lifecycle.** Complete update, removal and redownload; handle
  account changes, invalid entitlement, insufficient storage, cancellation, corrupt or
  missing content, interrupted network and backend restart without false ownership or
  success states. Do not claim store completion if native installation is still blocked.

## Milestones and acceptance

1. Run bounded applet/bridge and packaging/trust feasibility investigations on the
   declared configuration. Identify one original or redistributable test title.
2. Build controller-usable catalog/details and selected-account integration; give A
   required route wiring. Record the actual native workflow, not just static strings.
3. Implement only the required rights/device/ticket/content paths with durable,
   idempotent state and verified metadata; establish install and launch on hardware.
4. Complete update, removal/redownload and failure recovery; document rollback.

Acceptance: account selection, language fallback, ownership and acquisition retries,
rights sync, installed title launch and version update, redownload after removal,
insufficient space, network interruption/resume, canceled tasks, corrupt/missing content,
invalid entitlement, account switch and backend restart. Report packaging/trust blockers
precisely. Any required console modification is a reviewable proposal subject to existing
authorization. Never silently replace native installation with an NRO-only workflow.

## Review handoff

Return branch/base/commit references, requirement-to-code/test/evidence ledger, contract
changes, migrations/rollback, operator notes and exact reproduction commands. Run
`go vet ./...`, `go test -race ./...` and required affected-repository CI. Retain sanitized
hardware results with firmware/build IDs and timings. Mark missing hardware or dependent
integration as pending; mocks, HTTP success and locally passing tests cannot close native
acceptance gates. Include known blockers and the next reproducible experiment.

## Copyable assignment

> Implement `prds/native-switch-store-prd.md`. Read the linked coordination plan and shared
> parent requirements first. Use your own branch/worktree, agree shared interfaces at
> kickoff, and deliver only your owned feature changes plus narrow integration patches
> for A. Return the review handoff with explicit native acceptance and dependency status.
