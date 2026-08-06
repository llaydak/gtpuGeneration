# Dataset Validation Log

This log tracks every claim this project makes about its generated GTP-U
benign+attack traffic dataset, how each claim was verified, and its current
status. It exists because this dataset is intended for publication and
reuse in other work, so every claim needs to be independently checkable
rather than taken on faith.

Methodology loosely follows the "Datasheets for Datasets" framework
(Gebru et al., 2018, arXiv:1803.09010) — cite this in the paper's
methodology section if referencing this log's process.

Status values: **Verified** (checked, holds), **Fixed** (was wrong, now
corrected and reverified), **Open** (known gap, not yet resolved), **Risk**
(not wrong, but not deterministically guaranteed — needs monitoring).

---

## 1. GTP-U wire format is 3GPP-compliant (TS 29.281 / TS 38.415)

**Claim:** Extension header encoding (type, QFI, RQI, PPI, PDU type) matches
the 3GPP-defined bit layout.
**Verification:** Unit tests in `test_phase1_starter.py`
(`test_gtpu_mutation_adapter_builds_scapy_packet`,
`test_gtpu_dict_adapter_builds_scapy_packet`,
`test_gtpu_mutation_rqi_regression_and_ppp_auto_set`,
`test_build_gtpu_packet_raises_value_error_on_ul_rqi_ppi`).
**Status:** Verified.

## 2. Attack packets have a structurally realistic inner packet (T-PDU)

**Claim:** An attack packet's inner payload is a valid, dissectable IP
packet — not raw filler bytes that a packet analyzer would flag as
malformed.
**Finding (2026-08-04):** `_build_attack_packet` used
`Raw(load=b"X" * payload_size)` with no inner IP header at all. Discovered
by manually inspecting the pcap in Wireshark — attack packets rendered in a
different color than benign ones, and the "X" filler bytes were being
mis-parsed as a bogus inner IP header.
**Fix:** Wrapped the payload in `IP(src="10.45.0.2", dst="8.8.8.8") /
ICMP(type=8, code=0)` plus filler, matching the benign path's pattern
exactly (`generate_attack_pcap.py::_build_attack_packet`).
**Reverification:** Confirmed programmatically post-fix — all attack
packets in a real run have `inner_is_icmp=True` (see conversation log,
run `injected_attack_stream_20260804_154602`).
**Status:** Fixed.

## 3. Attack packets' outer DSCP marking reflects the claimed violation on the wire

**Claim:** For a DSCP-violation-type attack mutation, the actual outer IP
ToS byte in the pcap carries the violating DSCP value — not the session's
correct one.
**Finding (2026-08-04):** `_build_attack_packet`'s wire packet hardcoded
`tos=ctx.dscp_marking << 2` (the session's *correct* DSCP) instead of the
mutation's own `outer_dscp` — so DSCP-violation attacks never actually
carried the wrong DSCP on the wire, only in telemetry metadata.
**Fix:** Changed to `tos=gtp_mutation.outer_dscp << 2`.
**Reverification:** Confirmed programmatically — a DSCP-violation mutation
with `outer_dscp=46` now shows `dscp=46` when the wire packet is
re-dissected from the written pcap (run `injected_attack_stream_20260804_154602`).
**Status:** Fixed.

## 4. Benign LLM batch calls complete without truncation

**Claim:** A `generate_benign_batch` call finishes with valid, parseable
JSON within its token ceiling.
**Finding (2026-08-04):** At `llm_batch_size=200` with the
auto-computed ceiling (`max(2000, batch_size*300)=60000`), one run hit
exactly 60000 completion tokens and got cut off mid-JSON — a total loss of
that call (0 usable packets) after burning the full token budget.
**Fix (2026-08-05):** `generate()` now captures `finish_reason` from the API
response and exposes it as `self.last_finish_reason`, so truncation is
detected explicitly rather than inferred from a parse failure.
`generate_benign_batch`'s retry loop checks this: on a truncated response
it halves the requested `batch_size` (and recomputes the token ceiling)
before retrying, instead of blindly repeating the same request that just
failed. Verified with a mocked truncate-then-succeed scenario: batch_size
100 (30000 tokens) → truncated → retried at 50 (15000 tokens) → succeeded.
(Correction: an earlier version of this entry claimed the CLI/function
default `llm_batch_size` was lowered to 100 — that was never actually
applied to the code; the default remains 200. The `--llm-batch-size 100`
used in manual test runs was a per-invocation override, not a code change.)
**Status:** Fixed — the retry path is now deterministic given a truncation
signal, but the initial `llm_batch_size` choice is still a guess; recommend
monitoring `[WARN] Response was truncated` frequency across production runs
to see how often the first attempt needs shrinking.

## 5. `--max-packets` bounds wire segments, not traffic arrivals

**Claim:** N/A — this is a parameter semantics gotcha, not a dataset
correctness claim, but it could silently reduce effective diversity in a
capped pcap (a few large bursts could exhaust the packet budget after only
a handful of real arrivals, discarding the rest of that batch call's
generated diversity for free — no extra API cost either way).
**Finding (2026-08-05):** Confirmed — the loop in
`create_web_browsing_stream` gated on `seq`, which counts post-MTU-split
wire packets, not LLM arrivals. A run with large bursts could hit
`--max-packets` after very few real arrivals.
**Fix:** Loop now gates on `llm_arrivals_used` (arrivals actually consumed
into wire packets), not `seq` (wire packet/segment count) —
`generate_llm_pcap.py::create_web_browsing_stream`. `--max-packets`'s help
text and print output were updated to describe it as an arrival cap, not a
wire-packet cap. Also added `llm_arrivals_used`/`llm_arrivals_unused` to
telemetry (`llm_usage`), and an `[INFO]` print when a batch call's leftover
arrivals go unused because the cap or duration limit was hit mid-batch —
directly surfacing the "N of M generated arrivals were unused" signal this
entry called for.
**Reverification:** Not yet re-run end-to-end against a live LLM backend;
logic reviewed by inspection and the arrival-vs-segment distinction is now
structurally enforced by which counter gates the loop.
**Status:** Fixed. Recommend one real run with a small `--max-packets` to
confirm `llm_arrivals_used == max_packets` while `packet_count` (wire
segments) is allowed to exceed it, before citing this as reverified.

## 6. Attack campaign violation-type diversity (QFI vs RQI vs DSCP)

**Claim:** Across a campaign, the model doesn't default to one violation
dimension — it exercises all three (QFI outside active set, RQI outside
allow-list, DSCP mismatch) roughly evenly.
**Finding (2026-08-03):** An early run (before prompt fixes) was skewed
6/10 toward RQI violations.
**Fix:** Added explicit dimension-rotation instructions and 3 real
few-shot examples (one per dimension, taken verbatim from an actual
generation run) to `generate_mutation`'s prompt.
**Reverification:** Two independent post-fix runs: 4/4/4 and 3/3/2 splits
across QFI/RQI/DSCP (`injected_attack_stream_20260804_151646`,
`injected_attack_stream_20260804_154602`).
**Status:** Fixed, but only reverified on 2 runs — recommend a larger
sample (10+ runs) before citing "balanced" as a dataset-wide property.

## 7. Attack campaign size and injection point are not fixed/hardcoded

**Claim:** Each generated attack campaign has a model-chosen size and
model-chosen point in the traffic timeline, not a constant (e.g. always
the midpoint, always the same packet count) — reflecting that a real
attack could occur anywhere with any duration.
**Implementation (2026-08-04):** `generate_burst`/`generate_mutation` ask
the model to decide `campaign_size`/`injection_fraction` as part of its
first packet's response (see `LLMClient.generate_mutation`'s
`request_campaign_plan`).
**Reverification:** `injection_fraction` differed across two runs (0.400,
0.620); `campaign_size` differed (12, 8).
**Status:** Implemented and verified on 2 runs — same caveat as #6, small
sample so far.

## 8. Benign 5QI-6 traffic's inner payload matches its claimed application type (TCP-based)

**Claim:** 3GPP TS 23.501 Table 5.7.4-1 describes 5QI 6 as "Non-GBR,
TCP-based apps (www, email, chat, ftp, ...)". The generated inner T-PDU
should therefore be TCP-based traffic (e.g. an HTTP-like exchange), not a
different protocol.
**Finding (2026-08-05):** The inner payload was
`IP(src="10.45.0.2", dst="8.8.8.8") / ICMP(type=8, code=0)` — an ICMP echo,
used purely as a simple placeholder to get a valid, dissectable inner IP
packet (see #2). This did not match the claimed TCP-based application
type.
**Fix (2026-08-06):** `create_web_browsing_stream`'s `base_inner_payload`
(`generate_llm_pcap.py`) and the attack path's `base_inner_payload`
(`generate_attack_pcap.py`, kept consistent with the benign path per #2)
now build `IP(src="10.45.0.2", dst="8.8.8.8") / TCP(sport=51820, dport=80,
flags="PA", seq=1000, ack=1000)` — a TCP data segment to port 80 (HTTP),
still padded with `Raw` filler to the LLM-requested payload size.
**Status:** Fixed — the generated dataset's inner protocol now matches its
claimed 5QI-6 web-browsing traffic class.

## 9. Benign long-run achieved bitrate is plausible relative to prior published measurements

**Claim:** `achieved_bitrate_bps` (long-run total_bytes/duration) should be
in a realistic range for web-browsing traffic, without being explicitly
anchored to any single external figure (see project decision to ground in
TS 23.501 QoS characteristics instead of the Nikolaidis et al. Table II
figure of 5 Mbps for 5QI 6 — see `DATASET_VALIDATION.md` #10 below and
project memory `project_gtpu_3gpp_grounding`).
**Observation:** Across several unanchored runs, `achieved_bitrate_bps`
came out at 2.70–3.36 Mbps — in the same order of magnitude as, and
somewhat below, Table II's reference figure, despite no longer anchoring
to it. Note this is the long-run average; per-burst instantaneous bitrate
means are naturally much higher (12–17 Mbps observed) due to the bursty
on/off nature of the traffic — these are different statistics and
shouldn't be compared to Table II's R5QI directly.
**Status:** Verified as plausible on the runs observed so far; not a
formal statistical test. Recommend an aggregate statistical comparison
(e.g. distribution overlap or a formal goodness-of-fit test against a
published mobile-traffic dataset) before making a strong "realistic"
claim in a paper.

## 10. Traffic parameter grounding: 3GPP TS 23.501, not a third-party paper

**Claim:** Benign traffic timing/bitrate is derived from each QFI's own
3GPP TS 23.501 Table 5.7.4-1 QoS characteristics (Resource Type, Priority
Level, Packet Delay Budget, Packet Error Rate), not anchored to the
Nikolaidis et al. (NOMS 2023) paper's Table II empirical means.
**Status:** Implemented (2026-08-04). **Caveat:** the specific
PDB/Priority/PER numbers in `_5QI_3GPP_REFERENCE`
(`llm_client.py`) were reproduced from memory of the published table, not
read from a live copy of the spec — cross-check against an actual TS
23.501 copy before citing these exact numbers in the paper.

## 11. No hardcoded correction of LLM output

**Claim:** Nothing in the generation pipeline silently clamps, repairs, or
rejects-and-retries LLM-produced packet fields to make output look more
compliant than it actually is — evaluation metrics (schema validity,
semantic precision) are computed read-only, so reported compliance/success
rates reflect genuine model behavior.
**Status:** Implemented (2026-08-04) — removed `_clamp_extension_headers`
(attack path), `_ensure_diverse_structure`, `_evaluate_structured_claims`,
`_infer_anomaly_type`, `_build_reasoning`. See project memory
`feedback_no_hardcoded_llm_correction` for the full rationale.

## 12. Non-LLM ("stats") generation path removed

**Decision (2026-08-05):** `generate_llm_pcap.py` previously supported two
generation paths: a fast, non-LLM `mode="stats"` (sampling directly from
`TABLE_II_5QI_STATS`'s Table II distributions via `_sample_table_ii_burst`
and writing raw bytes via `_FastSessionPacketBuilder`) and `mode="llm"`.
The `stats` path and its supporting code
(`_sample_table_ii_burst`, `_checksum16`, `_FastSessionPacketBuilder`,
`_PAYLOAD_SIZE_CV`) were removed — `create_web_browsing_stream` is now
LLM-only, and the `--mode` CLI flag no longer exists.
**Why:** the project's contribution is LLM-driven generation; the stats
path existed only as a fast comparison baseline, and the relevant
stats-vs-LLM comparison data from earlier runs already exists (see #9).
If a rigorous benchmark against the paper's exact distributions is needed
for longer-duration runs later, this is recoverable from git history
(commit predating 2026-08-05) rather than kept live in the codebase.
`TABLE_II_5QI_STATS` itself and the `achieved_bitrate` vs. `table_ii_reference`
comparison in telemetry were kept — they're just a static reference number
now, not a sampling path.
**Status:** Implemented. Test suite (6/6) and both CLIs re-verified
post-removal.

## 13. No public dataset provides empirical ground truth for QFI/extension-header realism

**Claim under test:** Before this project's QFI marking (via GTP-U PDU
Session Container extension headers) can be claimed "realistic," it should
be checked against real-world 5G GTP-U traffic that actually populates
this field, if any such public dataset exists.

**Method:** Four externally-sourced candidate datasets were evaluated
against a shared framework (accessibility/license, native-ness of the
capture environment, and — critically — whether GTP-U extension
headers/QFI are structurally present and populated) rather than assumed
from documentation alone; each was inspected directly with `tshark`
(`gtp.flags.e`, `gtp.ext_hdr`, `gtp.ext_hdr.pdu_ses_con.qos_flow_id`) or,
where no packet-level data exists, by reading the dataset's own schema.

| Dataset | Capture environment | GTP-U present? | QFI/ext. header populated? |
|---|---|---|---|
| Mugna46/N3_dataset | Non-native (Kitsune IDS traffic re-tunneled through GTP-U) | Yes (structural) | Not checked at extension-header level — benign traffic itself isn't 5G-native, so moot for this claim |
| 5GAD-2022 (Idaho National Lab, `IdahoLabResearch/5GAD`) | Simulated (free5GC) | **No** — the "upfgtp" capture interface is the UPF's internal tun-style interface and yields already-decapsulated inner packets; `tshark -Y gtp` matched 0 frames in both a Normal-1UE sample (374 pkts) and a dedicated attack `upfgtpcap_*` file (4 pkts) | N/A |
| Wengappuli (Oulu, Dec 2024 thesis) "Comprehensive 5G Intrusion Detection Dataset" | Simulated (Open5GS/UERANSIM) | **No packet-level data of any kind** — dataset is aggregated Prometheus pod metrics + Loki log-count counters by design (traces deliberately not collected, per the thesis's own stated methodology) | N/A |
| **5G-NIDD** (Oulu, real RF test network) | **Real RF hardware** | Yes | **No** — `gtp.flags.e==1` matched 0 of 5,348 GTP-U frames in `SSH_BS2.pcapng` and 0 of 90,907 GTP-U frames in `UDPScan_BS2.pcapng`; `gtp.ext_hdr.pdu_ses_con.qos_flow_id` never appears |

**Finding:** Not one of the four datasets checked — including 5G-NIDD, the
only one captured on genuine RF hardware — populates the QFI/PDU Session
Container extension header on the wire. 5G-NIDD's GTP-U traffic carries a
valid TEID but the extension-header flag (`gtp.flags.e`) is unset on every
sampled packet across two independent files (background SSH traffic and
UDPScan attack traffic), meaning its testbed's gNB/UPF was not configured
to mark per-flow QoS at the GTP-U layer.

**Implication:** There is currently no available empirical baseline to
validate this project's QFI-marking realism against. The 3GPP-spec-grounded
approach already in place (`_5QI_3GPP_REFERENCE` in `llm_client.py`, TS
23.501 Table 5.7.4-1 / TS 29.281 / TS 38.415 — see #1 and #10) is therefore
not a fallback but the only rigorous validation path available for this
specific claim, and this absence of a real-world comparator is itself
worth stating explicitly if this dataset is published.

**Status:** Verified (absence of ground truth confirmed by direct
inspection, not assumed). Re-open this check if a future public 5G dataset
is found that does populate GTP-U extension headers.
