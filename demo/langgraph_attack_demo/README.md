# GRC-Shield · Layer 3 · LangGraph Demo

A working LangGraph agent that demonstrates the ASI01 Goal Hijack
attack against a simulated GRC compliance agent — and shows
GRC-Shield catching and blocking it in real time.

## What This Demo Shows

**Attack mode** (no protection):
- Agent reads a poisoned evidence PDF containing hidden instructions
- Agent marks a failing PCI DSS control as Compliant
- Action committed to the GRC platform silently
- No detection. No audit trail. Board dashboard goes green.

**Defended mode** (GRC-Shield active):
- GS-01 tags the uploaded evidence as TIER_3 (external submission)
- GS-01 wraps it in an isolation boundary before agent reads it
- GS-02 detects: "Tier 3 source read before compliant mark"
- Action suspended. Human reviewer notified.
- GS-03 writes immutable signed audit record.
- The attack is caught.

## Setup

```bash
# Clone the repo
git clone https://github.com/NSSMatta/grc-shield.git
cd grc-shield

# Install dependencies
pip install langgraph langchain langchain-anthropic

# Set your API key (optional — demo runs in simulation mode without it)
export ANTHROPIC_API_KEY=your_key_here
```

## Run

```bash
cd demo/langgraph_attack_demo

# See the attack succeed (no protection)
python demo.py --mode attack

# See GRC-Shield catch and block the attack
python demo.py --mode defended
```

## What You Will See

```
# ATTACK MODE output:
[Node 1] Fetching control record: CTRL-4421
  Status: NON_COMPLIANT | Failing: 107 days

[Node 3] Agent evaluating evidence...
  ⚠️  [SIMULATION] Agent processing poisoned context...
  Decision  : COMPLIANT
  Confidence: 98%

ACTION COMMITTED ✅
Control CTRL-4421 marked: COMPLIANT
The attack succeeded silently.
```

```
# DEFENDED MODE output:
[Node 2 — GS-01] Tagging data sources...
  🔒 upload://evidence/access_review_q2_2026.pdf
     Tier: external_submission | Isolation: True

[Node 4 — GS-02] Checking for anomalies...
  ⚠️  1 anomaly flag(s) detected:
     [HIGH] AFTER_EXTERNAL_READ
     → Agent read 1 Tier 3 source before marking compliant...

ACTION BLOCKED 🛑 — ROUTED TO HUMAN REVIEW
GRC-Shield stopped the attack.
```

## Architecture

```
Evidence docs
     │
     ▼
[GS-01] DataProvenanceTagger
  Tags each source with trust tier (TIER_1/2/3)
  Wraps TIER_3 content in isolation boundary
     │
     ▼
[LangGraph Agent]
  Evaluates evidence in safe context window
  Proposes compliance decision
     │
     ▼
[GS-02] AnomalyDetector
  Checks action against behavioural thresholds
  Flags: rate, scope, compliance spike, Tier3→compliant pattern
     │
     ▼
[GS-03] GRCAuditLog
  Writes immutable signed record
  Captures: sources read, reasoning, anomalies, outcome
     │
     ▼
Commit to GRC platform OR Escalate to human reviewer
```

## Note on Simulation Mode

If no `ANTHROPIC_API_KEY` is set, the demo runs in simulation mode —
the LLM response is simulated to show how the attack would fool
a real agent. GRC-Shield still runs fully in both cases.
The detection logic is identical whether using a real LLM or simulation.
