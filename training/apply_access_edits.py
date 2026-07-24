#!/usr/bin/env python3
"""
Apply the PUC2 2c access-path text edits to the training definition — TEXT ONLY.

The training definition JSON is deliberately kept OUT of this repository
(git-ignored, uploaded to CyberRangeCZ by hand). So this tool edits *your* copy
in place rather than shipping a fork of it, and proves it changed nothing it must
not: it rewrites only the `content` field of levels L1, L9, L14 and L15, and
asserts every `answer` in the file — and every other field of every level — is
byte-identical before and after.

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
        "Both the console and the desktop are opened *through* the GUI — they are "
        "the two ways it can attach you to a node, not alternatives to it.\n\n"
        "**Direct SSH (without the GUI).** If you would rather use your own "
        "terminal, **`Get SSH Access`** downloads `ssh-access.zip`:\n"
        "```bash\n"
        "unzip ssh-access.zip -d ~/.ssh/\n"
        "chmod 600 ~/.ssh/pool-id-*-sandbox-id-*-user-key\n"
        "ssh -F ~/.ssh/pool-id-*-sandbox-id-*-user-config victim\n"
        "```\n\n"
        "## The SOC dashboards\n"
        "The dashboards live on **internal testnet addresses**, so a browser must "
        "run *inside* the sandbox — open the **graphical desktop on `kali` "
        "(10.0.16.50)** and use its browser. In this scenario 10.0.16.50 plays two "
        "roles: it is the simulated **C2** the payload beacons to, and it is also "
        "the node whose desktop you use as the analyst workstation. You never need "
        "to \"log into the C2\" as an attacker — you are just using that node's "
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
            lvl["content"] = lvl.get("content", "") + CONSOLE_APPEND[order]
        edited_orders.append(order)

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
    print("Answers changed:", changed_answers if changed_answers else "NONE")
    print("Fields changed :", changed_fields)

    unexpected = [(o, k) for (o, k) in changed_fields
                  if not (k == "content" and o in (1, 9, 14, 15))]
    if changed_answers or unexpected:
        sys.exit("REFUSING TO WRITE: an answer or an unexpected field changed.")

    out = args.json_path if args.in_place else args.json_path + ".edited.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"\nOK — wrote {out}. Only L1/L9/L14/L15 `content` changed; every "
          f"answer is identical.")


if __name__ == "__main__":
    main()
