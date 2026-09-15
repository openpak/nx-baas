# The OpenPak look

> Trimmed copy for this repository; the canonical document lives at
> `Openpak/docs/design.md` and governs. Last synchronised 2026-09-15.

One design across three surfaces: the website, the console link pages, and the phone app. They
are built with completely different tools and must still read as one product, so what follows
is the part that has to stay in step — not a style guide anybody has to admire.

## What we deliberately do not serve (2026-09-08)

A console asks a lot of servers. Answering one badly is worse than not
redirecting it at all, so each is a decision rather than an omission.

| Service | Decision |
| --- | --- |
| Telemetry (`*.dragons`/`ndas` play reports, `receive-lp1`) | **Never.** Nothing about how somebody plays needs to leave their house. |
| System updates (`sun`, `atumn`, `aqua`, `superfly`) | **Never.** Firmware is Nintendo's to sign; a console pointed at us for updates is a console we could brick. |
| eShop / Atum (title content: NCA files, icons, updates) | **Later, for homebrew.** Atum is the file server behind the shop, edge-token gated. Hosting homebrew through it is wanted; today it is out of scope. |
| ZNC (`api-lp1.znc`) | **Not yet.** It is the Nintendo Switch Online phone app's API — and the console's **voice chat** path. Our companion app speaks our own API instead; voice chat would need this. |
| Eagle relay | **Not yet.** A handful of titles relay instead of peer-to-peer: Tetris 99, Super Mario Bros. 35. Matchmaking stays NEX; the session hands out an eagle URL and token. |
| NAT check, connection test | Not served; a console that cannot check its NAT falls back sensibly. |

Served today: device auth (dauth/aauth/dcert/acert), dragons eLicenses, BAAS
users and friends, Nintendo Accounts, Penne push, Vermillion, Beach, capi
memberships, NPLN game servers, BCAT news (empty), OLSC saves (served by `saves` through the adapter; console acceptance of the key seed package is M0, untested).


## Tokens, and the one rule about them

The palette is plain custom properties that flip with the reader's system setting. **Nothing
hardcodes a colour.**

| Token | Light | Dark | For |
| --- | --- | --- | --- |
| `paper` / `paper-2` / `raised` | `#ffffff` / `#f7f7f8` / `#ffffff` | `#101114` / `#191a1f` / `#1c1e24` | page, inset, card |
| `ink` / `ink-2` / `muted` | `#16161a` / `#3d3f47` / `#6b6e79` | `#e9eaee` / `#b7bac2` / `#8a8e99` | text, secondary, quiet |
| `line` / `line-2` | `#e4e4e8` / `#c9cad1` | `#26282e` / `#3b3e47` | borders, control borders |
| `accent` (+ `-weak`, `-line`) | `#4f46e5` | `#818cf8` | the logo's indigo |
| `ok` / `warn` / `bad` (+ `-weak`, `-line`) | `#1a7f4b` / `#8a5a00` / `#b3261e` | `#4ec98a` / `#e5b169` / `#ff8079` | state |

Where they live:

| Surface | File |
| --- | --- |
| Website | `website/web/src/input.css` (built by Tailwind; run `./scripts/css.sh`) |
| Console link pages | `nx-baas/link.go`, `pageCSS` — inline, because a console may not reach the site |
| App | `app/lib/theme.dart`, `Tokens.light` / `Tokens.dark` |

Three copies is a deliberate cost: each surface must work when the others are unreachable.
**When one moves, move all three** — a mismatch is visible the moment someone opens the app
beside the site.

## The tinted row

The one shape worth learning. Every list of things-with-a-state uses it: name on the left, pill
on the right, and **the tint carries the state so the pill carries the fact**.

```
┌──────────────────────────────────────────────┐
│  Stardew Valley                  ● 2 players │   green  = working
└──────────────────────────────────────────────┘
┌──────────────────────────────────────────────┐
│  Wii U                          ● Being built│   amber  = on its way
└──────────────────────────────────────────────┘
┌──────────────────────────────────────────────┐
│  PSP                              ● Planned  │   grey   = nothing claimed
└──────────────────────────────────────────────┘
```

- **green** — working, online, live.
- **amber** — being built, waiting on you. Most of a roadmap lives here; without it, unfinished
  work has to borrow a colour that means something else.
- **red** — not answering. Keep it for that, or it stops meaning anything.
- **grey** — *nothing is being claimed*: planned work, an offline friend, an expired invitation,
  a server this deployment does not check. Grey is not "slightly wrong".

Because the tint says how a thing is, the pill is free to say **what** it is — a player count,
a title, a time — instead of repeating the colour in words. The pill also carries a dot, so the
state survives for anyone who cannot rely on the tint.

Implementations: `.state-row` (website `input.css`), `.row` (`nx-baas/link.go`), `StateRow`
(`app/lib/widgets.dart`).

## Rules that keep costing us when broken

1. **Mobile first.** The narrow layout is the design; wider screens add to it. The site was
   desktop-first with patches, which is why fixing one page never fixed the next.
2. **No font under 16px on an input.** Below that iOS zooms on focus and leaves the page
   scrolled sideways — a layout bug the reader cannot undo.
3. **44px touch targets**, 60px on a console where a stick is doing the aiming.
4. **Long strings wrap** — friend codes, title ids, tokens. Horizontal scroll is the one thing a
   phone user cannot work around.
5. **No JavaScript for any journey.** The site's menu is a `<details>` element for this reason.
6. **The logo is one file.** `website/web/static/icon.svg`, copied into the app and rasterised
   for launcher icons; a redrawn copy diverges the moment the real one changes, silently.

## Looking before shipping

Neither the site nor the link pages can be judged from source. Both render to files:

```sh
cd website && PREVIEW_DIR=/tmp/preview go test -count=1 ./internal/pages/ -run WritePreview
cd nx-baas && PREVIEW_DIR=/tmp/link    go test -count=1 -run DumpLinkPages .
chromium --headless --window-size=390,900 --screenshot=/tmp/s.png file:///tmp/preview/status.html
```

390px and 1280px for everything, plus 1280×720 for the console page. Checking desktop is not
optional: the row-note bug that put every badge at a different x was invisible on a phone.
