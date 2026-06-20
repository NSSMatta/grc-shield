"""
GRC-Shield — Detection Engine Test Runner
Runs the built-in demonstration for every control GS-04 through GS-12.
Verifies all controls execute without errors before GitHub push.

Run from the detection-engine directory:
    python run_all_tests.py

Author: Naga Sai Srinivas Matta
Repository: github.com/NSSMatta/grc-shield
"""

import subprocess
import sys
import os

CONTROLS = [
    ("GS-04 Tool Sequencer Monitor (ASI02)",        "grc_shield/gs04_tool_sequencer.py"),
    ("GS-05 Privilege Scope Monitor (ASI03)",       "grc_shield/gs05_privilege_scope.py"),
    ("GS-06 Supply Chain Integrity (ASI04)",        "grc_shield/gs06_supply_chain_integrity.py"),
    ("GS-07 Code Execution Monitor (ASI05)",        "grc_shield/gs07_code_execution_monitor.py"),
    ("GS-08 RAG Integrity Monitor (ASI06)",         "grc_shield/gs08_rag_integrity.py"),
    ("GS-09 Inter-Agent Message Auth (ASI07)",      "grc_shield/gs09_message_auth.py"),
    ("GS-10 Cascade Circuit Breaker (ASI08)",       "grc_shield/gs10_cascade_breaker.py"),
    ("GS-11 Output Integrity Verifier (ASI09)",     "grc_shield/gs11_output_integrity.py"),
    ("GS-12 Rogue Agent Monitor (ASI10)",           "grc_shield/gs12_rogue_agent_monitor.py"),
]


def run_all():
    print("=" * 70)
    print("GRC-Shield Detection Engine — Full Test Run")
    print("github.com/NSSMatta/grc-shield")
    print("=" * 70)

    results = []
    for name, path in CONTROLS:
        print(f"\n{'─'*70}")
        print(f"Running: {name}")
        print(f"{'─'*70}")

        full_path = os.path.join(os.path.dirname(__file__), path)
        result = subprocess.run(
            [sys.executable, full_path],
            capture_output=False,
            text=True,
        )
        passed = result.returncode == 0
        results.append((name, passed))

    print(f"\n{'='*70}")
    print("TEST SUMMARY")
    print(f"{'='*70}")
    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}  {name}")
        if not passed:
            all_passed = False

    print()
    if all_passed:
        print("All controls passed. Ready for GitHub push.")
    else:
        print("Some controls failed. Review output above before pushing.")

    return all_passed


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
