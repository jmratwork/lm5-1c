# PUC2 2c — Access matrix (Phase 0)

Which sandbox nodes give a **console** and which give a **graphical desktop with
a browser** that can reach the SOC dashboards on testnet, and where that leaves
the training's access instructions.

**Terminology, as the platform uses it.** The **GUI** is the CyberRangeCZ web
platform — the way in. From it (*Topology* → `Generate console URL`) you attach
to a node and get, depending on that node's image, either a **console** (a
command-line terminal in a new window) or a **graphical desktop**, where the
tooling needs one. Console and desktop are therefore two things the GUI gives
you, **not alternatives to the GUI**. `Get SSH Access` is also a platform
button — it hands you keys to connect from your own terminal — so it too is
something the GUI provides, not a way around it.

## Scope of this document — read first

This is **static analysis of the repository**, not an observation of a running
sandbox. From this workstation the deployed range is unreachable and Ansible
cannot run (Windows). Two kinds of facts follow, kept strictly apart:

- **VERIFIED (repo):** node→image mapping (`topology.yml`) and whether any role
  installs a desktop or browser (grep across `provisioning/roles`).
- **UNVERIFIABLE here:** whether a given CyberRangeCZ catalogue image *ships*
  a desktop and browser. That is a property of the image catalogue, not of this
  repo. Cells that need the live sandbox are marked **CONFIRM IN SANDBOX** and a
  read-only probe to fill them is proposed at the end.

## Nodes and images (VERIFIED from topology.yml)

| Node | Image | mgmt user | testnet IP | Role in scenario |
|------|-------|-----------|-----------|------------------|
| kali | `kali` | debian | 10.0.16.50 | **also the simulated C2** (see collision below) |
| docker-server | `ubuntu-noble-x86_64` | ubuntu | 10.0.16.60 | CTI-SS / CICMS / NG-SOAR host |
| ng-siem | `siemng` | ubuntu | 10.0.16.70 | NG-SIEM (Wazuh dashboard on :443) |
| victim | `ubuntu-noble-x86_64` | ubuntu | 10.0.16.100 | endpoint under attack |
| router | `debian-12-x86_64` | debian | 10.0.16.1 | gateway |

## Desktop / browser installed by any repo role (VERIFIED)

**None.** A grep for `xfce|gnome|kde|lxde|mate|desktop|firefox|chromium|chrome|
browser|xrdp|vnc|spice` across every role returns no install task. The only
hits are a Guacamole *hostname/cert* string in the ng-siem integration
(`guacamole.mini.ngsiem.sph.gr`, not a desktop this overlay installs) and an
unrelated comment. So **no node gets a browser from this repository.** Any
desktop/browser present comes from the base image alone.

## The access matrix

| Node | Console (via GUI) | Graphical desktop (via GUI) | Browser present | Reaches the 4 dashboards |
|------|--------------------|-------------------|-----------------|--------------------------|
| kali | Yes | **CONFIRM IN SANDBOX** (Kali images commonly ship XFCE) | **CONFIRM IN SANDBOX** (not from repo) | Yes — on testnet, all 4 IPs routable |
| docker-server | Yes | No (server image, none installed) | No | Yes — it *hosts* MISP/IRIS/NG-SOAR |
| ng-siem | Yes | Unlikely (server image; ships the Wazuh dashboard, not a client desktop) | No | Yes |
| victim | Yes | **No** (ubuntu-noble server image, no desktop, no browser) | **No** | N/A |
| router | Yes | No | No | Yes (routes, but nothing to browse from) |

## Two problems this confirms

1. **The L1 tip is wrong.** L1 advises keeping "the NG-SIEM dashboard open in a
   browser tab" while working on `victim`. `victim` runs `ubuntu-noble-x86_64`
   with no desktop and no browser — the repo installs neither. The tip cannot be
   followed. (Phase 3 fixes the text; the isolation warning on the same level is
   correct and stays.)

2. **The desktop candidate collides with the C2 narrative.** The only strong
   desktop candidate is **kali (10.0.16.50)** — Kali images usually ship a
   desktop and a browser, and kali sits on testnet with all four dashboards
   routable. But `topology.yml` puts kali at **10.0.16.50**, which the training
   L1 table labels *"Simulated C2 infrastructure (address only — no host to log
   into)"*, and `puc2_c2_ip` is in fact derived from kali's IP. So the node we
   would tell students to open a desktop on is the same box the scenario calls
   "C2, no host to log into." This must be resolved deliberately in the L1
   rewrite, not papered over.

## Recommendation

Because the desktop question is genuinely unverifiable from here **and** the one
candidate collides with the C2 narrative, do not hinge the training on the
desktop at all. Two independent tracks:

- **Guarantee the console path (Phases 1-2).** Every hands-on level must be
  completable from a console, with no desktop required. This is the real fix
  and the one fully under the repo's control. The three dashboard-only levels
  (L9, L14, L15) get console helpers on `docker-server`, following the existing
  `share_intel.sh` pattern.
- **Make the desktop path honest (Phase 3 + a probe).** Name the desktop node
  only once it is confirmed. To confirm it without guessing, add a **read-only
  access probe** (opt-in, `never`-tagged, like `puc2_diag`) that the operator
  runs in the sandbox; it records per node `which firefox/chromium`, presence of
  an X/Wayland session, and dashboard reachability, and rewrites the CONFIRM
  cells above with live data. If the probe finds no browser on any node, install
  one on kali via an **overlay** role (never touching the integrations
  substrate) — and, given the C2 collision, decide whether the desktop node
  should be kali at all or whether the console path alone is the sanctioned
  route.

## Decision taken (2026-07-23): kali doubles as the analyst workstation

The kali / C2 collision is resolved as **option (a)**: kali (10.0.16.50) is used
as the graphical workstation for the dashboards, and L1 will state explicitly
that 10.0.16.50 plays two roles — the simulated C2 in the scenario narrative, and
the analyst's desktop from which the SOC dashboards are opened. The "no host to
log into" wording becomes "the payload beacons to this address; you also use its
desktop to reach the dashboards."

**This decision is contingent on the F0 probe confirming kali actually ships a
desktop and a browser** — which is not verifiable from the repo. If the probe
finds no browser on kali, the fallback is to install one on kali via an overlay
role (never the integrations substrate). Until the probe result is in, the L1
text names kali but the console path (Phases 1-2) remains the guaranteed route
for every level, so the training never depends on the desktop being present.

### The F0 probe (read-only, opt-in, `never`-tagged)

Delivers "check, don't assume" for the cells marked CONFIRM IN SANDBOX above.
Run by the operator against the live range; per node it records `which firefox
/chromium`, whether an X/Wayland session exists, and whether each dashboard IP
answers, then rewrites this file's matrix with live data. It installs nothing
and cannot fail a build.
