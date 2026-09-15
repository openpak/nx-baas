# Native Switch implementation: two- or four-agent assignment

Status: ready for assignment. Date: 2026-09-11.

The [parent PRD](native-switch-social-eshop-prd.md) remains the complete product and
acceptance specification. The four smaller PRDs below are the executable assignments.
This plan supersedes the parent's single-agent assignment and ownership wording only;
it does not reduce scope or waive shared acceptance requirements.

## Assignments

| Workstream | PRD | Exclusive requirements | Four agents | Two agents |
| --- | --- | --- | --- | --- |
| A: friends, profiles and presence | [A PRD](native-switch-friends-presence-prd.md) | SOC-01–05, PRE-01–04; shared integration | Agent 1 | Agent 1 |
| B: Penne and notifications | [B PRD](native-switch-penne-notifications-prd.md) | NTF-01–06 | Agent 2 | Agent 2 |
| C: native invitations | [C PRD](native-switch-invitations-prd.md) | INV-01–04 | Agent 3 | Agent 1 after initial A contracts/fixes |
| D: native store | [D PRD](native-switch-store-prd.md) | SHP-01–05 | Agent 4 | Agent 2 after the initial B protocol milestone |

With two agents, Agent 1 owns social state and invitation semantics; Agent 2 owns
transport and store workflows. Advance the other assigned workstream when a research
or hardware dependency blocks progress. This grouping preserves ownership boundaries;
four agents provide more independent capacity, especially for store feasibility.

Give each agent its PRD plus this plan. Each PRD links the shared parent rules and
evidence. Do not also assign the parent's old all-features prompt to another agent.

## Kickoff and edit ownership

All four roles operate within the Switch adapter workstream previously reserved for
S1 T4/T5. Unrelated workstream agents still do not own `nx-baas`. The generic
one-repo-per-PRD rule has this scoped exception: four feature PRDs share one repository
through separate branches/worktrees and a designated integration owner, A.

1. Record the current `nx-baas` base commit, local modifications and repository rules.
   Create one branch/worktree per active agent without discarding existing work.
2. A records an ownership map of existing files and reserves common wiring: router,
   authentication, shared models/core clients, migration registration and core-event
   polling/cursor handling. B/C/D own their new feature files and feature-specific tests.
3. Existing files mix concerns. In particular, `penne.go` contains both Penne and Beach
   logic; `main.go` and `gameapi.go` mix multiple handlers. Agree any extraction first.
   A lands a small preparatory extraction if needed; agents then rebase onto that commit.
   Until then B/C/D develop modules and supply narrow integration patches to A.
4. Each feature owner owns its persistence implementation/migrations; A coordinates
   shared registration and migration order. Do not independently change shared schemas
   or exported interfaces without notifying dependent owners.
5. A integrates each reviewed branch sequentially and resolves shared-file conflicts
   with the feature owner. Feature ownership does not transfer to A merely because A
   applies the final wiring. No agent deploys another agent's incomplete branch.

## Contracts to agree before dependent implementation

These are internal semantic requirements, not invented Nintendo wire schemas. A records
the agreed types/error semantics in a small versioned contract document and shared code
where appropriate. Reuse existing interfaces where they already provide the behavior.

| Contract | Owner | Required semantics | Consumers |
| --- | --- | --- | --- |
| Authenticated principal and policy | A | Account/device identity derived from validated credentials; interaction and presence visibility checks; revocation behavior | B/C/D |
| Social/presence snapshot | A | Stable IDs/revisions, current viewer-authorized state, freshness and per-friend alert preference | B/C |
| Semantic notification submission | B, reviewed by A/C | Stable event/dedup identity, recipient, event kind, entity/revision reference, expiry, acceptance/persistence outcome and retry semantics | A/C; D only if traced workflow requires |
| Core-event dispatch | A, reviewed by B/C | One durable core cursor, replay-safe routing to feature consumers, defined crash behavior between processing and persistence | B/C |
| Native invitation lifecycle | C | Durable invitation/group identity, recipients, title payload, read/expiry state, policy/session outcomes and notification trigger | A/B |
| Store handler integration | D | Required hosts/paths, principal/device dependency, rights/content/task boundary and migration/configuration needs | A; B if notifications are required |

B owns final wire encoding and delivery, including policy revalidation before sending.
A/C own semantic state changes. Agree how committed changes become durable delivery
work: an outbox, replayable core event or another justified reconciliation mechanism.
Do not mark an event consumed before its required durable effect is recoverable. Do not
add a second core poller or competing canonical state to avoid coordinating this boundary.

Missing account-core functionality becomes a concrete contract request through the
existing core review workflow. A consolidates requests to avoid incompatible proposals;
the feature owner supplies the required semantics and integration test. No direct core
database access or mock-only completion.

## Dependency and integration order

All agents can immediately inspect evidence and build bounded independent components.

1. Agree shared contracts and ownership; land A's common scaffolding and verified social
   correctness/authentication fixes. B supplies the debug-stream fix for A to integrate.
2. B proves the native Penne connection/subscription lifecycle. In parallel C builds
   invitation REST/core integration and D runs store launch/install feasibility work.
3. Integrate A's social/presence events with B; verify recipient policy, notification
   behavior, restart and reconnect using real core state.
4. Integrate C with B; verify native inbox/alert/read and then per-title joining.
5. Integrate D's catalog/rights/content routes and complete the native install lifecycle.
   D only depends on B where an observed store operation actually needs notifications.
6. A assembles the combined branch and runs shared regressions. Each feature owner
   remains responsible for its acceptance evidence and defects.

Protocol research may block native notification acceptance without blocking friend-list
fixes, invitation REST or store diagnostics. Packaging/trust research may block store
installation without blocking social acceptance. Mark these gates separately.

## Test sessions and review package

Serialize use of the owner's shared hardware and endpoint configuration. Maintain a
test-slot record with branch/commit, firmware/configuration, scenario and restoration
steps so results are attributable to one build. No implicit production or console-change
authorization is created by parallel assignment.

Each agent returns its PRD's review package and status ledger. A assembles a coverage
index for all 24 requirements and J1–J8, shared CI results and integrated hardware matrix.
The requesting reviewer reviews feature changes and the combined behavior; passing an
isolated feature branch does not close dependent acceptance gates. Unknowns and failed
targets remain visible rather than disappearing during integration.

## Copyable kickoff message

> You own workstream [A/B/C/D] in `prds/native-switch-parallel-plan.md`. Read your
> linked PRD and the shared parent rules/evidence. Record your base commit, use an
> isolated branch/worktree, and agree the ownership/interface contract with A before
> touching shared code. Implement your workstream and return its required review package.
> Coordinate dependent contracts directly; do not overwrite another workstream's files
> or claim native completion from mocks. Hardware-dependent gates remain pending until
> reproduced on the declared setup.
