# Security Awareness Center

Fifteen generated breaches for **CompTIA Security+ (SY0-701)**. Each one is a
single incident seen through seven domain lenses — the human layer, the threat,
the controls, the architecture, identity and crypto, the response, and the risk
— then an eighth tile where the student **builds the fix**, plus a capstone that
makes them account for the whole thing.

Live site: https://rafikiscyent888.github.io/Security-Awareness-Center/

Part of the **Cyber Warrior Program**. Same shape as the
[CySA CVSS Center](https://rafikiscyent888.github.io/CySA-CVSS-Center/), pitched
at Security+ rather than CySA+: domains instead of tools, and awareness treated
as a first-class control rather than a footnote.

## How it works

One seeded object per scenario is the single source of truth. Every tile renders
a different lens onto that object, and **every graded answer is computed from
the object rather than written beside the rows**. That is the whole design
constraint: hand-matched answers drift the moment anything regenerates, so
there are none. Press **Shuffle** and all fifteen incidents rebuild — the
answers follow, because they were never separate from the evidence.

There is no question bank to memorise and no answer key to leak. A student who
counts the rows gets exactly what the grader wants.

## The eight tiles

| Tile | Domain | What the student does |
|---|---|---|
| 0 · The human layer | 1.2, 2.2 | Reads a mail, badge or service-desk log; finds who reported it, who saw it and said nothing, and which tells actually hold up |
| 1 · The threat | 2.1, 2.4 | Attributes the actor, names the vector, and separates real indicators from a well-run IT department doing its job |
| 2 · Controls | 1.1, 2.5 | Finds the control that would have prevented it, and classifies both it and the one that was present but the wrong kind |
| 3 · Architecture | 3.1–3.4 | Names the design decision that turned a foothold into a breach |
| 4 · Identity & crypto | 4.6, 1.4 | **Builds it.** Sets an access matrix to least privilege — strip too much and the business stops, leave too much and the breach spreads |
| 5 · Response | 4.8, 4.9 | Finds the one action in six that cost something unrecoverable, and names its IR phase |
| 6 · Risk & compliance | 5.1–5.3 | Picks the risk treatment, the notification clock for that regime, and who owns residual risk |
| 7 · Remediation | 2.5, 3.2, 4.5 | **Builds the fix.** Repairs the firewall rule set by hand, then funds the changes that address this breach and only this breach |
| Capstone | all | States the causal chain, the one change worth funding first, and the lesson that is not a technology change |

## The remediation tile

This is the one that is not a quiz. It stays **locked until the threat tile is
answered** — the vector and the actor — because the point is to fix what you
have diagnosed rather than reach for controls you happen to like. Instructor
mode opens it regardless.

**The firewall.** A rule set of the kind that was actually running that
morning: a blanket allow off the user VLAN, added for a real reason years ago
and never revisited. Rules evaluate top to bottom, first match wins, and
anything that matches nothing is denied. The student adds, edits, reorders and
deletes rules, then runs a traffic test that replays eight flows through their
configuration — two of them the breach, six of them the business doing its job.

The grading is the lesson. Denying the user VLAN outright stops the breach and
fails, because staff can no longer browse, reach the portal, or do the work the
compromised role legitimately does. The feedback says which flows still get
through and which ones the student has just broken, so it reads as "your rules
still let it out" rather than "wrong answer". Verified across 600 generated
breaches: the starting rules always leak, a correct rule set always exists, and
a blanket deny always fails.

**The rest of the fix.** Eight changes, four of which address this breach — the
control that would have prevented entry, the architectural fix, the
cryptographic fix, and closing the gap in the MFA posture. The other four are
real, fundable controls drawn from the scenarios this one is not. Ticking a
good control that has nothing to do with the incident you just had is how a
security budget gets spent without the risk moving, and it is marked wrong.

Two tiles carry a **hold-to-read key** — the control types/categories, and the
IR phases plus order of volatility. It shows only while the button is held, so
it is a memory aid during the drill rather than a permanent crib sheet.

## Instructor mode

PIN **3693**, same as the rest of the toolkit. Reveals every answer, highlights
the significant rows in each table, marks the over-granted cell in the access
matrix, and shows the true timeline under the capstone. Switching it back off
takes the revealed answers away again; anything the student earned themselves
stays on screen.

## Design notes

- **Deadlines are real.** HIPAA 60 days, PCI DSS immediately, NERC CIP-008 one
  hour, state statute 30 days — and two organisations with **no** statutory
  clock, because FERPA sets recordkeeping rather than a notification deadline
  and professional conduct rules set a duty rather than a number. GDPR's 72
  hours is always on the option list and never the answer; it is the deadline
  students apply to everything once they have learned one.
- **Nothing is answerable by position.** Questions whose correct answer is the
  same string every time are shuffled per scenario, the significant rows in the
  control inventory and indicator list are interleaved rather than grouped at
  the top, and the mistake in the response log sits where its own IR phase puts
  it rather than always at row three.
- **The firewall is small on purpose.** Six zones, eight services, one service
  per resource. It is not a model of an enterprise; it is the smallest thing
  that makes first-match-wins and the implicit deny something a student has to
  actually get right.
- **Contrast.** Every piece of text on the page clears **WCAG AAA** (7:1 for
  body text, 4.5:1 for large) in both themes at 1300px, 820px and 390px.
- **Themes.** Follows the OS by default; the Dark/Light button in the header
  overrides it and the choice is remembered.

## What's here

```
index.html          the page shell, theme bootstrap, instructor dialog
assets/breach.js    the generator — one breach object per scenario
assets/evidence.js  renders that object into mail/badge/indicator/control/response views
assets/app.js       the eight tiles, the capstone, grading and page wiring
assets/style.css    tokens, tile palette, tables, access matrix
```

Plain static HTML/CSS and ES modules. No build step, no framework, no
dependencies. Because it uses ES modules it must be **served over HTTP** —
opening `index.html` from the filesystem will be blocked by CORS. GitHub Pages
serves it correctly; locally, any static server will do.

## Hosting

GitHub Pages, deployed from `main` / root — Settings → Pages → Source: Deploy
from a branch → `main` → `/ (root)`.

## Disclaimer

Addresses, domains, names and organisations are synthetic. For educational
purposes only. Not affiliated with, endorsed by, or sponsored by CompTIA®. All
trademarks belong to their respective owners.
