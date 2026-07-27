#!/usr/bin/env python3
"""
Apply the PUC2 2c access-path text edits to the training definition — TEXT ONLY.

The training definition JSON is deliberately kept OUT of this repository
(git-ignored, uploaded to CyberRangeCZ by hand). So this tool edits *your* copy
in place rather than shipping a fork of it, and proves it changed nothing it must
not. It makes exactly two kinds of change:

  * rewrites the `content` field of levels L1, L9, L14 and L15 (the access-path
    text and the console helpers), and
  * corrects one wrong answer KEY in the L6 checkpoint: the EMI "Spearphishing
    link" statement pointed at T1566.002 (attachment) instead of T1566.001
    (link), contradicting L9. This is a `correct_option_order`, never an
    `answer` field. Idempotent — a no-op once corrected.
  * appends a node-access note to every training level that runs something on a
    node, so the login credentials are visible IN that level and a trainee is
    never blocked on a credential that only appears in the level-1 primer.
    Idempotent, and it changes only `content`.

It asserts every `answer` in the file is byte-identical before and after, and
that no field other than those changed (only L6's `questions`, and only when the
key fix actually fires). It also refuses to write if any level's `content` still
contains the word "placeholder" or any non-ASCII character — two ways a broken
file has reached the platform before.

    python3 training/apply_access_edits.py \
        puc2-cynet-2c-malware-detection-response_linear-training-definition.json

Writes <file>.edited.json next to the input and prints the answers diff (which
must be empty). Pass --in-place to overwrite after you have read the diff.
"""
import argparse
import copy
import json
import sys

# New `content` for each edited level, keyed by its `order`. Nothing else in the
# file is touched. No `answer` field is referenced here at all.
NEW_CONTENT = {
    # L1 — Accessing the environment
    1: (
        "Before you start, make sure you can reach the machines and the SOC "
        "dashboards.\n\n"
        "## How to access the range\n"
        "From the CyberRangeCZ **Topology** view, open a node with the top-right "
        "button, **`Expand All`**, pick the machine and **`Generate console URL`** "
        "-> **`Open link`**. Depending on the node's image you get one of two "
        "things, and both are valid throughout this training:\n"
        "- a **console** (a command-line terminal), or\n"
        "- a **graphical desktop**, when the image ships one.\n\n"
        "The **console** is what you get after acting on the GUI: a new terminal "
        "attached to the node for its command line. The **desktop** is the other "
        "thing the GUI can attach, when a node's image ships one. Both are reached "
        "through the GUI - neither is an alternative to it.\n\n"
        "**Your own terminal (optional).** The platform's **`Get SSH Access`** "
        "button also hands you keys to connect from your own machine, if you "
        "prefer that to the in-GUI console:\n"
        "```bash\n"
        "unzip ssh-access.zip -d ~/.ssh/\n"
        "chmod 600 ~/.ssh/pool-id-*-sandbox-id-*-user-key\n"
        "ssh -F ~/.ssh/pool-id-*-sandbox-id-*-user-config victim\n"
        "```\n\n"
        "## Logging into a node\n"
        "Each node's login user is **`ubuntu`** (on victim, ng-siem and "
        "docker-server) or **`debian`** (on kali). `Get SSH Access` logs you in "
        "with a key, so SSH needs no password. The graphical console asks for that "
        "user's password, which for this range is **`PUC2-2c-training`**. And "
        "**`sudo` needs no password on any node**, so every `sudo ...` command in "
        "the levels just runs.\n\n"
        "## The SOC dashboards\n"
        "The dashboards live on **internal testnet addresses**, so a browser must "
        "run *inside* the sandbox - open the **graphical desktop on `kali` "
        "(10.0.16.50)** and use its browser. In this scenario 10.0.16.50 plays two "
        "roles: it is the simulated **C2** the payload beacons to, and it is also "
        "the node whose desktop you use as the analyst workstation. You never need "
        "to \"log into the C2\" as an attacker - you are just using that node's "
        "desktop to reach the dashboards:\n"
        "- NG-SIEM (Wazuh) dashboard: `https://10.0.16.70`\n"
        "- CTI-SS (MISP): `https://10.0.16.60:8443`\n"
        "- CICMS (DFIR-IRIS): `https://10.0.16.60:8083`\n"
        "- NG-SOAR: `http://10.0.16.60:8080`\n\n"
        "**Dashboard credentials** are published inside the sandbox, not handed "
        "out separately. Read them on **docker-server**:\n"
        "```bash\n"
        "sudo cat /opt/puc2/CREDENTIALS.txt\n"
        "```\n\n"
        "> **You can complete every hands-on level from a terminal alone.** Each "
        "dashboard step also has a console command, so you are never blocked if a "
        "desktop is unavailable.\n\n"
        "> **Important - keep a console open on `victim`.** Later in the exercise "
        "the endpoint is placed under network isolation. A console opened from the "
        "GUI is out-of-band and keeps working, and an SSH session opened "
        "beforehand survives; a *new* SSH connection to `victim` may be refused "
        "while containment is in force."
    ),
    # L9 — Enrich the hash with CTI
    9: None,  # filled below by appending a console block to the existing content
    14: None,
    15: None,
}

# For L9/L14/L15 we APPEND a console block to whatever the level already says,
# rather than replace it, so the dashboard instructions and the answer-bearing
# prose stay exactly as they are. Keyed by order.
CONSOLE_APPEND = {
    9: (
        "\n\n**Console (on `docker-server`):**\n"
        "```bash\n"
        "sudo /opt/cti-ss-seed/cti_lookup.sh\n"
        "```\n"
        "Read the **MITRE ATT&CK techniques** block: the technique marked "
        "*initial access* is this level's answer."
    ),
    14: (
        "\n\n**Console (on `docker-server`):**\n"
        "```bash\n"
        "sudo /opt/cicms-assets/case_lookup.sh\n"
        "```\n"
        "It lists the IRIS cases and marks the **scenario case** by its SOC id, "
        "separating it from the auto-created `WAZUH-...` alert cases."
    ),
    15: (
        "\n\n**Console (on `docker-server`):**\n"
        "```bash\n"
        "sudo /opt/cti-ss-seed/cti_lookup.sh\n"
        "```\n"
        "Read the **IOCs** block: the C2 domain is this level's answer."
    ),
}

# Every hands-on level that tells the trainee to run something on a node must
# show, IN THAT LEVEL, how to get onto the node — otherwise a trainee who lands
# straight on it (levels are not always read in order) is blocked on a
# credential that only appears in the level-1 primer. This note is appended to
# each training level that carries a shell step. It repeats the published range
# credentials on purpose: seeing them beats a cross-reference. The sentinel in
# the first line keeps the append idempotent.
NODE_ACCESS_SENTINEL = "Node access for this step:"
NODE_ACCESS_NOTE = (
    "\n\n> **" + NODE_ACCESS_SENTINEL + "** open the node from the GUI (console "
    "or desktop) or over SSH, and log in as `ubuntu` (or `debian` on kali) with "
    "the range password `PUC2-2c-training`. `sudo` needs no password. (Same "
    "credentials as the level-1 access primer and `/opt/puc2/CREDENTIALS.txt`.)"
)


def touches_a_node(content):
    """A level has a node step if it shows a shell block or a sudo command."""
    return "```bash" in content or "sudo " in content


def levels_by_order(doc):
    return {lvl.get("order"): lvl for lvl in doc.get("levels", [])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("json_path")
    ap.add_argument("--in-place", action="store_true",
                    help="overwrite the input after you have read the diff")
    args = ap.parse_args()

    with open(args.json_path, encoding="utf-8") as fh:
        doc = json.load(fh)

    before = copy.deepcopy(doc)
    by_order = levels_by_order(doc)

    edited_orders = []
    for order in (1, 9, 14, 15):
        if order not in by_order:
            sys.exit(f"ERROR: no level with order {order} in {args.json_path}")
        lvl = by_order[order]
        if order == 1:
            lvl["content"] = NEW_CONTENT[1]
        else:
            # Append the console block only if it is not already there, so
            # re-running the tool on its own output does not double it.
            block = CONSOLE_APPEND[order]
            if block not in lvl.get("content", ""):
                lvl["content"] = lvl.get("content", "") + block
        edited_orders.append(order)

    # ── Show the node credentials on every level that runs something on a node ─
    # Done AFTER the console blocks above, so L9/L14/L15 get the note too. Skips
    # level 1 (which IS the access primer) and any level already carrying it.
    noted_orders = []
    for lvl in doc.get("levels", []):
        if lvl.get("level_type") != "TRAINING_LEVEL":
            continue
        content = lvl.get("content", "")
        if lvl.get("order") == 1 or not touches_a_node(content):
            continue
        if NODE_ACCESS_SENTINEL in content:
            continue
        lvl["content"] = content + NODE_ACCESS_NOTE
        noted_orders.append(lvl.get("order"))

    # ── Correct the L6 checkpoint answer key (idempotent) ─────────────────────
    # The EMI statement "Spearphishing link" pointed at T1566.002 (spearphishing
    # ATTACHMENT); a link is T1566.001 — which is also L9's graded answer, so the
    # original contradicted it and marked a correct trainee wrong. This is a
    # `correct_option_order`, not an `answer` field, so it is fixed here. No-op
    # when already correct (e.g. a file that has already been through this tool).
    l6_fixed = False
    lvl6 = by_order.get(6)
    if lvl6:
        for q in lvl6.get("questions", []):
            if q.get("question_type") != "EMI":
                continue
            opts = {o.get("order"): o.get("text")
                    for o in q.get("extended_matching_options", [])}
            for s in q.get("extended_matching_statements", []):
                if s.get("text") != "Spearphishing link":
                    continue
                if opts.get(s.get("correct_option_order")) == "T1566.001":
                    continue  # already correct
                target = [o for o, t in opts.items() if t == "T1566.001"]
                if not target:
                    sys.exit("ERROR: L6 EMI has no T1566.001 option to map "
                             "'Spearphishing link' onto")
                s["correct_option_order"] = target[0]
                l6_fixed = True

    # ── Prove no answer changed, anywhere ────────────────────────────────────
    before_answers = {o: l.get("answer") for o, l in levels_by_order(before).items()}
    after_answers = {o: l.get("answer") for o, l in levels_by_order(doc).items()}
    changed_answers = {o: (before_answers[o], after_answers[o])
                       for o in before_answers
                       if before_answers[o] != after_answers.get(o)}

    # ── Prove ONLY the four `content` fields changed, nothing else ────────────
    changed_fields = []
    for o, lvl_after in levels_by_order(doc).items():
        lvl_before = levels_by_order(before)[o]
        for k in set(lvl_before) | set(lvl_after):
            if lvl_before.get(k) != lvl_after.get(k):
                changed_fields.append((o, k))

    print("Levels edited (content only):", edited_orders)
    print("Node-access note added to    :", noted_orders or "none (already present)")
    print("L6 key fix     :", "Spearphishing link -> T1566.001" if l6_fixed
          else "already correct (no change)")
    print("Answers changed:", changed_answers if changed_answers else "NONE")
    print("Fields changed :", changed_fields)

    # Allowed content changes: L1/L9/L14/L15 (the rewrites) and every level the
    # node-access note was appended to. Allowed non-content change: L6 questions,
    # only when the key fix fired. Anything else is a bug and blocks the write.
    content_ok = set((1, 9, 14, 15)) | set(noted_orders)
    unexpected = [(o, k) for (o, k) in changed_fields
                  if not ((k == "content" and o in content_ok)
                          or (o == 6 and k == "questions" and l6_fixed))]
    if changed_answers or unexpected:
        sys.exit("REFUSING TO WRITE: an answer or an unexpected field changed.")

    # A build-scaffold string must never survive to a shippable file. The last
    # round shipped a level whose content was literally "placeholder-0" because
    # the input carried it and nothing here objected. Now it does — for EVERY
    # level's content, not just the four this tool rewrites, because the failure
    # was a placeholder in a level the tool does not touch (L0).
    placeholders = [lvl.get("order") for lvl in doc.get("levels", [])
                    if "placeholder" in (lvl.get("content") or "").lower()]
    if placeholders:
        sys.exit(f"REFUSING TO WRITE: 'placeholder' text left in level(s) "
                 f"{placeholders}. Supply the real content for those levels.")

    # The training UI mangles non-ASCII (an em-dash rendered as mojibake once).
    # Keep the output plain ASCII so nothing depends on the platform's encoding.
    non_ascii = sorted({c for lvl in doc.get("levels", [])
                        for c in (lvl.get("content") or "") if ord(c) > 127})
    if non_ascii:
        sys.exit(f"REFUSING TO WRITE: non-ASCII character(s) in content: "
                 f"{non_ascii}. Replace them (e.g. an em-dash with ' - ').")

    out = args.json_path if args.in_place else args.json_path + ".edited.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"\nOK - wrote {out}. Changed only `content` (the L1/L9/L14/L15 "
          f"rewrites and the node-access note) plus the L6 key; every answer is "
          f"identical.")


if __name__ == "__main__":
    main()
