"""
GRC-Shield | ASI04 through ASI10 — Master Simulation Runner

Runs all seven simulations in sequence and produces a clean
summary showing which detection controls blocked which attacks.

ASI04, ASI06, ASI07, ASI08, ASI10 — local, no API key required
ASI05, ASI09 — require ANTHROPIC_API_KEY

Run from your grc-shield folder:
    PYTHONPATH=detection-engine python demo/asi04_to_asi10_demo/run_all_simulations.py

Author: Naga Sai Srinivas Matta
Repository: github.com/NSSMatta/grc-shield
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

# ── Import all simulations ────────────────────────────────────────────────────

from asi04_simulation import run as run_asi04
from asi05_simulation import run as run_asi05
from asi06_simulation import run as run_asi06
from asi07_simulation import run as run_asi07
from asi08_simulation import run as run_asi08
from asi09_simulation import run as run_asi09
from asi10_simulation import run as run_asi10

# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    has_api_key = bool(os.environ.get("ANTHROPIC_API_KEY"))

    print("\n" + "=" * 70)
    print("GRC-Shield | ASI04 through ASI10 — Full Simulation Suite")
    print("github.com/NSSMatta/grc-shield")
    print("=" * 70)

    if not has_api_key:
        print("\n⚠️  No ANTHROPIC_API_KEY set.")
        print("   ASI05 and ASI09 require an API key and will be skipped.")
        print("   All other simulations will run locally.\n")

    results = {}

    print("\n\n" + "━" * 70)
    print("Running ASI04 — Supply Chain Integrity (local)")
    print("━" * 70)
    try:
        results["ASI04"] = run_asi04()
    except Exception as e:
        print(f"ERROR: {e}")
        results["ASI04"] = False

    print("\n\n" + "━" * 70)
    print("Running ASI05 — Code Execution Monitor (API)")
    print("━" * 70)
    if has_api_key:
        try:
            results["ASI05"] = run_asi05()
        except Exception as e:
            print(f"ERROR: {e}")
            results["ASI05"] = False
    else:
        print("SKIPPED — set ANTHROPIC_API_KEY to run this simulation")
        results["ASI05"] = None

    print("\n\n" + "━" * 70)
    print("Running ASI06 — Memory and Context Poisoning (local)")
    print("━" * 70)
    try:
        results["ASI06"] = run_asi06()
    except Exception as e:
        print(f"ERROR: {e}")
        results["ASI06"] = False

    print("\n\n" + "━" * 70)
    print("Running ASI07 — Inter-Agent Message Authentication (local)")
    print("━" * 70)
    try:
        results["ASI07"] = run_asi07()
    except Exception as e:
        print(f"ERROR: {e}")
        results["ASI07"] = False

    print("\n\n" + "━" * 70)
    print("Running ASI08 — Cascading Failures (local)")
    print("━" * 70)
    try:
        results["ASI08"] = run_asi08()
    except Exception as e:
        print(f"ERROR: {e}")
        results["ASI08"] = False

    print("\n\n" + "━" * 70)
    print("Running ASI09 — Human-Agent Trust Exploitation (API)")
    print("━" * 70)
    if has_api_key:
        try:
            results["ASI09"] = run_asi09()
        except Exception as e:
            print(f"ERROR: {e}")
            results["ASI09"] = False
    else:
        print("SKIPPED — set ANTHROPIC_API_KEY to run this simulation")
        results["ASI09"] = None

    print("\n\n" + "━" * 70)
    print("Running ASI10 — Rogue Agent Behavioral Monitor (local)")
    print("━" * 70)
    try:
        results["ASI10"] = run_asi10()
    except Exception as e:
        print(f"ERROR: {e}")
        results["ASI10"] = False

    # ── Final Summary ─────────────────────────────────────────────────────────

    CONTROL_MAP = {
        "ASI04": "GS-06 Supply Chain Integrity Verifier",
        "ASI05": "GS-07 Code Execution Sandbox Monitor",
        "ASI06": "GS-08 RAG Integrity Monitor",
        "ASI07": "GS-09 Inter-Agent Message Authentication",
        "ASI08": "GS-10 Cascade Circuit Breaker",
        "ASI09": "GS-11 Output Integrity Verifier",
        "ASI10": "GS-12 Rogue Agent Behavioral Monitor",
    }

    print("\n\n" + "=" * 70)
    print("FINAL SUMMARY — GRC-Shield ASI04 through ASI10")
    print("=" * 70)

    all_passed = True
    for asi, control in CONTROL_MAP.items():
        result = results.get(asi)
        if result is True:
            status = "✅ BLOCKED"
        elif result is False:
            status = "❌ NOT BLOCKED"
            all_passed = False
        else:
            status = "⏭  SKIPPED"

        print(f"  {asi} — {control:<45} {status}")

    print()
    if all_passed:
        print("All detection controls verified.")
    else:
        print("Some controls require review before publishing.")

    print()
    print("This is a proof-of-concept simulation framework.")
    print("Not a live GRC platform test — a starting point for the community.")
    print("github.com/NSSMatta/grc-shield")
    print("=" * 70)
