# LLM-Driven GTP-U Traffic & Attack Generation

Generate realistic 5G user-plane (GTP-U) traffic and adversarial QoS-marking
attacks, then measure how faithful the traffic is and whether the attack opens a
detection gap. An LLM authors the flow-level semantics (payload sizes, inter-arrival
gaps, QoS markings); a deterministic packetizer renders each flow into 3GPP-compliant
wire packets and writes a PCAP.

The generated dataset is grounded two ways:

- **Protocol semantics** come from 3GPP specs — TS 29.281 / TS 38.415 (GTP-U wire
  format, PDU Session Container) and TS 23.501 (5QI → QoS characteristics).
- **Traffic realism** is scored against **5G-NIDD**, a real 5G RF-network flow
  dataset. Per-flow byte volumes and per-device inter-arrival gaps are the reference
  distributions; goodness-of-fit is a KS test against them, never a parametric model.

## What it produces

- **Benign baseline** — a Web Browsing stream (5QI 6, Non-GBR) over one or more UEs,
  each flow schema-valid and QoS-consistent with its PDU session.
- **Attack stream** — the benign baseline with an injected `qfi_qer_mismatch`
  campaign: each attack packet is *individually schema-valid* but carries a
  QFI/RQI/DSCP combination that violates the session's QER/FAR policy. The attack is a
  pure QoS-marking anomaly — it rides the same arrival/volume distribution as benign
  traffic, so it cannot be caught by rate or volume alone.
- **Live UPF study** — separate tooling that injects an unauthorized-QFI uplink
  G-PDU at a live free5GC UPF and measures whether the UPF polices it (empirically, it
  does not — free5GC v4.2.3 forwards unauthorized-QFI uplink G-PDUs).

## Repository layout

| File | Role |
| --- | --- |
| [gtpu.py](gtpu.py) | GTP-U mutation model + Scapy wire builder. `FIELD_BOUNDS` is the single source of 3GPP field ranges (schema, prompt, builder all read it). |
| [session_context.py](session_context.py) | `SessionContext` — PDU-session QoS state (QFI→5QI, QFI→QER, authorized QFIs, DSCP). Mutations are meaningful only relative to this. |
| [llm_client.py](llm_client.py) | `LLMClient` — builds prompts (3GPP + 5G-NIDD grounding), calls any backend via LiteLLM, parses/schema-validates output **read-only** (never clamps or repairs the model). |
| [reference_models.py](reference_models.py) | Loads the 5G-NIDD reference distributions (flow bytes, request bytes, arrival gaps); supplies few-shot examples, prompt targets, and the KS scoring reference. |
| [generate_llm_pcap.py](generate_llm_pcap.py) | Benign baseline generator (LLM authors flow scalars; packetizer splits each flow into MTU-sized wire packets). |
| [generate_attack_pcap.py](generate_attack_pcap.py) | Benign baseline + injected LLM-driven `qfi_qer_mismatch` attack campaign. |
| [extract_5gnidd_reference.py](extract_5gnidd_reference.py) | Builds the 5G-NIDD reference `.npz` from the raw Argus flow CSV. Run this first. |
| [plot_gof.py](plot_gof.py) | Goodness-of-fit: KS test + plots of generated vs. real 5G-NIDD distributions. |
| [detection_gap_report.py](detection_gap_report.py) | Tier-1 semantic-vs-structural check on an attack PCAP: shows the attack is structurally normal but semantically policy-violating. |
| [inject_qfi_attack.py](inject_qfi_attack.py) | Inject an unauthorized-QFI uplink G-PDU at a live free5GC UPF and sniff the verdict. |
| [measure_upf_cost.py](measure_upf_cost.py) | Measure a live UPF's forwarding cost under an unauthorized-QFI flood. |
| [test_phase1_starter.py](test_phase1_starter.py) | Unit tests for the GTP-U wire builder. |
| [DATASET_VALIDATION.md](DATASET_VALIDATION.md) | Per-claim validation log for the generated dataset (intended for publication). |

Outputs land in `pcap_files/` (PCAP + `_telemetry.json` ground truth per run) and
`gof_plots/` (figures). Both are git-ignored.

## Setup

Requires Python 3.11+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Copy the environment template and set your backend:

```bash
cp .env.example .env
```

```ini
# Self-hosted Ollama server (backend=ollama, the default)
SELF_HOSTED_MODELS_URL=http://127.0.0.1:11434
MODEL_VARIANT=mistral:7b
# Required only for --backend openai
OPENAI_API_KEY=
```

- **ollama** (default): a local model served at `SELF_HOSTED_MODELS_URL` (must be
  pulled — see `ollama list`).
- **openai**: pass `--backend openai` with `OPENAI_API_KEY` set and `--model` an
  OpenAI model id.

## Usage

### 1. Build the 5G-NIDD reference (once)

```bash
python extract_5gnidd_reference.py path/to/5gnidd_argus_flows.csv --out reference_data/5gnidd_benign_tcp_flows.npz
```

The generators and GoF scoring have **no parametric fallback** — a missing reference
is an error, by design.

### 2. Generate a benign baseline

```bash
python generate_llm_pcap.py --duration 15 --backend openai --model gpt-5.6-luna
```

Key options: `--duration` (minutes), `--num-ues` (concurrent UEs interleaved into one
UPF-facing stream), `--llm-batch-size` (arrivals per LLM call, default 200),
`--max-packets` (bound the run), `--generation-mode {llm,sampled}` (`sampled` = no-LLM
baseline that draws scalars straight from 5G-NIDD — the SOTA lower bound).

### 3. Generate an attack stream

```bash
python generate_attack_pcap.py --background-duration 5 --direction UL --backend openai --model gpt-5.6-luna
```

Key options: `--direction {DL,UL}` (`UL` is the direction a UPF's QFI verification is
meant to reject; `DL` models a compromised-UPF egress), `--burst-size` /
`--attack-duration` (campaign length; mutually exclusive — omit both to let the model
decide), `--injection-fraction` (where to strike), `--background-num-ues` (hide the
compromised UE in a crowd), `--generation-mode {llm,script}`.

### 4. Score realism (goodness-of-fit)

```bash
python plot_gof.py pcap_files/web_browsing_benign_*_telemetry.json \
  --attack pcap_files/injected_attack_stream_*_telemetry.json --outdir gof_plots
```

### 5. Detection-gap report on an attack PCAP

```bash
python detection_gap_report.py pcap_files/injected_attack_stream_<ts>.pcap --plot
```

### Live free5GC UPF study (optional, requires a testbed)

```bash
# Inject an unauthorized-QFI uplink G-PDU and read the verdict
python inject_qfi_attack.py --teid 0x2 --qfi 7 --upf-ip 10.100.200.2

# Measure UPF forwarding cost under an unauthorized-QFI flood
python measure_upf_cost.py --qfi 7 --pps 0,1000,10000,50000,150000
```

## Design principles

- **LLM authors, code renders.** The LLM owns flow-level scalars and QoS markings; the
  packetizer owns the deterministic wire realization (MTU split, headers, timing).
- **Read-only evaluation.** `llm_client.py` never clamps, repairs, or gates model
  output — it parses and schema-validates only, so schema-invalid output is a *finding*
  about the model, not something silently fixed.
- **Grounded, not fabricated.** QoS semantics come from 3GPP TS 23.501; traffic shape
  is scored against real 5G-NIDD flows. Every dataset claim is logged and independently
  checkable in [DATASET_VALIDATION.md](DATASET_VALIDATION.md).

## Tests

```bash
pytest test_phase1_starter.py
```
