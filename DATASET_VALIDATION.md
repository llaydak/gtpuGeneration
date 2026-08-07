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
**Update:** The inner T-PDU was subsequently upgraded from IP/ICMP to a real
IP/TCP web-browsing segment matching the benign path (see sections 15–16);
`_build_attack_packet` now builds TCP, direction-aware (UL: UE→server;
DL: server→UE). The "dissectable inner IP, not raw filler" property still
holds.
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

## 14. Reported inter-arrival time is comparable to Table II's T5QI

**Claim:** A published `avg_inter_arrival_ms` figure should be directly
comparable to Table II's T5QI (100ms for 5QI 6), so a reader can sanity-check
achieved timing against the reference.
**Finding (2026-08-06):** The field was computed as a flat average over every
telemetry record, but each LLM-generated arrival ("burst") is split into
MTU-sized wire segments (see #2/#12, `_MAX_SEGMENT_BYTES`), and every segment
after the first gets a fixed synthetic `_INTRA_BURST_GAP_MS` (1ms) rather than
a real sampled gap. Since a ~62.5KB average burst splits into ~40-50 segments,
these 1ms artifacts vastly outnumbered real arrival gaps in the average — an
observed run showed `avg_inter_arrival_ms` of 3.22ms despite the underlying
burst-arrival process actually averaging ~101ms, right on T5QI.
**Fix:** `generate_llm_pcap.py` now tags each telemetry record with
`is_burst_start` (true only for a burst's first wire segment). The reported
`avg_burst_inter_arrival_ms` is computed only over `is_burst_start` records,
making it directly comparable to T5QI. `achieved_bitrate_bps` was also
switched from an average-of-ratios (`avg_payload*8/avg_iat`) to a direct
`total_bytes*8/simulated_duration_seconds` measure, which isn't sensitive to
segmentation granularity.
**Status:** Fixed — re-verified against a prior run's raw records
(reconstructing burst-start via `inter_arrival_ms != 1.0` as a proxy, since
that run predates the `is_burst_start` field): 413 burst-start records,
avg ≈101.2ms vs. T5QI=100ms.

## 15. Inner TCP header is not a static, repeated artifact across packets

**Claim:** Since the inner T-PDU is now a real TCP segment (#8), a packet
analyzer following an individual flow (5-tuple + sequence numbers) should
see plausible, internally-consistent TCP behavior — not the exact same
header repeated on every packet, which would be an obvious synthetic-data
signature.
**Finding (2026-08-06):** Direct inspection of a generated PCAP (parsing
the inner IP/TCP header out of 20 sampled wire packets) showed
`sport=51820, seq=1000, ack=1000` identical on every single one of 18,647
packets. The benign path's `base_inner_payload` (`generate_llm_pcap.py`)
and the attack path's (`generate_attack_pcap.py`) both built one fixed
`TCP(sport=51820, seq=1000, ack=1000)` object and reused it everywhere —
real TCP sequence numbers advance with bytes sent, and a real web-browsing
session opens many distinct short-lived connections rather than reusing
one static 5-tuple.
**Fix:** `generate_llm_pcap.py`'s `create_web_browsing_stream` now assigns
each LLM-generated arrival ("burst") its own random ephemeral source port
and initial sequence number (ISN); the sequence number advances across
that burst's own MTU segments by each segment's actual TCP data length
(segment size minus the fixed 40-byte IP/TCP header), and only the burst's
last segment carries the `PSH` flag (interior segments carry plain `ACK`).
`generate_attack_pcap.py`'s `_build_attack_packet` similarly randomizes
sport/seq/ack per attack packet instead of reusing a fixed header.
**Status:** Fixed — re-verified: within one simulated burst, sequence
numbers advance correctly per segment's data length (e.g.
`3589583794 → 3589585154 → 3589586514` for three MTU segments), and
consecutive bursts land on different ephemeral ports/ISNs.

## 16. PDU Session Container direction matches the packet's actual direction (TS 38.415)

**Claim:** The PDU Session Container's PDU Type must agree with the
direction the packet actually travels. Per TS 38.415, DL PDU Session
Information (type 0) is sent UPF → NG-RAN, and UL PDU Session Information
(type 1) is sent NG-RAN → UPF.
**Finding (2026-08-06):** Direct inspection of a generated PCAP showed a
three-way contradiction on every packet: the outer tunnel ran
`192.168.100.10 → 192.168.100.20` (gNB → UPF = **uplink**), the inner
T-PDU ran `10.45.0.2 → 8.8.8.8` (UE → internet = **uplink**), but the
container carried `pdu_type=0` = **DL** PDU Session Information. The
DL default in `build_gtpu_packet` ([gtpu_scapy.py](gtpu_scapy.py)) is
itself correct — RQI/PPI are DL-only fields, so DL is required for them to
be serializable at all — but nothing flipped the packet's actual direction
to match, so the marking contradicted the wire at both layers.
**Secondary issue:** web browsing is downlink-dominant (small uplink
requests, large downlink responses), so modeling ~62KB bursts on the
*uplink* also put the byte volume on the wrong side.
**Fix:** `generate_llm_pcap.py` and `generate_attack_pcap.py` now emit true
downlink G-PDUs — outer `upf_ip → gnodeb_ip`, inner
`_WEB_SERVER_IP → _UE_IP` — so `pdu_type=0` is correct, RQI is meaningful,
and the burst volume sits on the direction that actually carries it.
**Status:** Fixed — re-verified on regenerated packets: outer
`192.168.100.20 → 192.168.100.10`, `pdu_type=0`, inner
`93.184.216.34 → 10.45.0.2`.

## 17. Payload bytes are not a zero-entropy artifact

**Claim:** Inner payload bytes should not carry a signature that a detector
could separate benign from attack traffic on, independently of the QoS
policy violation under study.
**Finding (2026-08-06):** Padding was `b"X" * pad_len` — a single repeated
byte, entropy ≈ 0. Entropy and compression-ratio are common IDS feature-set
members, so a model trained on this dataset could learn the padding
artifact rather than the anomaly, silently invalidating detection results.
Cleartext port 80 was also modeled, which is dated for modern browsing.
**Fix:** Padding is now `os.urandom(pad_len)`, modeling TLS-encrypted
application data (incompressible/high-entropy), with the inner TCP server
port moved to 443 so the high entropy is self-consistent — encrypted bytes
are high-entropy, cleartext HTTP would not be.
**Status:** Fixed — measured payload entropy on regenerated packets:
7.81–7.89 bits/byte (8.0 = ideal uniform random).

## 18. Inter-packet timing is not a fixed constant

**Claim:** Wire-level packet spacing should be physically achievable and
not deterministic.
**Finding (2026-08-06):** 98% of all inter-packet gaps in a generated PCAP
were exactly 1.000ms (16,920 of 18,646, plus 1,314 at 0.999ms) — the fixed
`_INTRA_BURST_GAP_MS`. Back-to-back MTU frames on a real link are separated
by serialization time (~0.012ms for 1444 bytes at 1 Gbps), never a constant
1.000ms; the constancy alone is a synthetic signature.
**Fix:** Intra-burst spacing is now each segment's own serialization delay
at an N3 line rate (`_N3_LINK_BPS`, 1 Gbps) times a random jitter factor
(`_INTRA_BURST_JITTER_RANGE`) standing in for queueing/scheduling
variation, with a small floor. Burst-arrival gaps (the LLM-generated,
T5QI-comparable ones — see #14) are untouched.
**Status:** Fixed — re-verified: intra-burst gaps now span 0.005–0.018ms
with 33 distinct values across 127 gaps (granularity limited by libpcap's
microsecond timestamp resolution), versus one constant value before.
**Update (2026-08-07):** the jitter band was widened
(`_INTRA_BURST_JITTER_RANGE` 1.0→4.0) and a rare larger gap
(`_INTRA_BURST_PAUSE_PROB`/`_INTRA_BURST_PAUSE_RANGE_MS`, modelling an
ACK-clock / RAN-scheduler pause) was added, so intra-burst spacing is no
longer a near-constant ~11µs band. Kept small enough that accumulated
intra-burst time stays a low-single-digit % of the run and the achieved
bitrate remains tied to the burst-arrival gaps (see #23).
**Cost side effect:** simulated time now advances almost entirely via
burst-arrival gaps rather than accumulated 1ms segment gaps, so covering a
given `--duration` needs roughly 45% more LLM-generated arrivals (and
therefore ~45% more tokens) than before this fix. This is the correct
behavior — the old figure was inflated by the timing artifact — but it must
be accounted for when estimating run cost.

## 19. IP identification and TTL fields are not static

**Claim:** IP header fields that vary in real stacks should vary here too.
**Finding (2026-08-06):** All 18,647 packets in a generated PCAP carried
`IP id = 1` and `TTL = 64` on both the outer and inner header — Scapy's
constant defaults. Real stacks vary IP ID per packet (RFC 6864), and a
downlink response from an internet server arrives with TTL already
decremented by the path's hop count.
**Fix:** IP ID is now drawn per packet on both outer and inner headers;
inner TTL is drawn per TCP connection from a plausible post-path range
(52–62), varying by simulated server/path.
**Status:** Fixed — re-verified: 130/130 distinct outer IP IDs and 129/130
distinct inner IP IDs across a 130-packet sample, with inner TTLs varying
per connection.

## 20. Known remaining realism gaps (open)

Recorded so they are not mistaken for verified properties. None are
spec violations; all are traffic-modeling simplifications.

- **No TCP connection lifecycle.** No SYN/SYN-ACK/ACK handshake, no
  FIN/RST teardown, no pure-ACK packets, no retransmissions. Flows appear
  mid-stream, so "Follow TCP Stream" shows a one-sided, truncated
  conversation.
- **Single destination server, single UE, no DNS.** Real browsing resolves
  names first and fans out across many servers and parallel connections;
  this models one server IP and one UE.
- **Benign background is downlink-only.** The 5QI 6 benign baseline is
  generated in the downlink direction only; a real capture point would also
  see the uplink request/ACK stream. (Attack packets can now be uplink — see
  section 21 — but the benign background they are injected into is still DL.)
- **Single fixed TEID (`0xDEADBEEF`).** Real N3 allocates a separate TEID
  per direction, assigned by the receiving node; a magic constant is both
  directionally simplified and an obvious synthetic marker.
- **GTP-U S flag set on every G-PDU.** Sequence numbers are optional per
  TS 29.281 and mainly serve handover reordering; typical production /
  Open5GS / free5GC N3 G-PDU traffic runs `S=0`. Not a violation, but
  atypical, and it adds 4 bytes per packet.
- **QFI numerically equals 5QI (both 6).** Permitted, but QFI is an
  arbitrary 0–63 identifier that need not align numerically with the 5QI in
  a real deployment.

**Status:** Open — disclose in any publication describing this dataset.

---

## 21. Uplink attack packets target the field the UPF actually verifies (TS 29.244 / TS 23.501 §5.7)

**Claim:** An uplink (`--direction UL`, pdu_type=1) `qfi_qer_mismatch`
attack carries a QFI outside the session's authorized set — the exact
condition the UPF's uplink QoS-flow-ID verification is required to detect
and reject — and does so with a spec-correct UL PDU Session Container
(QFI only; no RQI/PPI, which are downlink-only fields).
**Rationale:** For downlink the UPF is the *producer* of QFI/RQI/DSCP and
the gNB/UE are the consumers, so a DL mutation models a compromised-UPF
egress rather than a packet the UPF verifies. On the uplink the UPF is the
*verifier* (TS 29.244 PDR/QER matching), so UL QFI mismatch is the
load-bearing "semantic attack against the UPF" case.
**Verification:** `_evaluate_semantic_precision(..., direction="UL")` marks
only `violates_active_qfis` as the UPF-enforced anomaly and records
`enforcement_point = "UPF (UL QoS-flow-ID verification)"`; the builder emits
`pdu_type=1` with RQI/PPI absent (rejected by `build_gtpu_packet` if set),
and tshark dissects the container as `UL PDU SESSION INFORMATION (1)` with
the marked QFI and no malformed/expert error. Confirmed on a mixed
DL-benign + UL-attack pcap.
**Status:** Verified.

## 22. Attack packets are semantic, not structural (Tier-1 detection-gap proof)

**Claim:** The injected attack packets are schema-valid — accepted as
well-formed by a standard, session-unaware parser — yet detectable only by a
session-aware policy check. This is the offline evidence for the study's
core "semantics over syntax" claim, independent of any live UPF.
**Verification:** `detection_gap_report.py` runs two detectors over a
generated pcap: a STRUCTURAL IDS (Wireshark/tshark expert-info at Error
severity) and a SEMANTIC IDS (session-policy check re-derived directly from
the wire, not from the generator's labels). On a mixed pcap the structural
IDS flags 0% of attacks (100% schema-valid), while the semantic IDS flags
them at 100% with 0% benign false-positive rate; the reported detection gap
is the fraction of attacks that are structurally valid but semantically
anomalous. The semantic detector's logic mirrors
`LLMClient._evaluate_semantic_precision`, so generator labels and the proof
agree by construction while remaining independently computed.
**Reverification:** Re-run
`./upfvenv/bin/python detection_gap_report.py <pcap>` on any generated
attack stream; the report is written to `<pcap>_detection_gap.json`.
On a real UL run (`injected_attack_stream_20260807_131847`, 29,010 packets,
4 UL attack packets, QFI 7/8/9/10 vs authorized {6}): structural IDS 0%
detection / 0% benign-FPR, semantic IDS 100% / 0% FPR, detection gap 4/4.
Independent tshark dissection of all 29,010 frames confirmed the GTP-U PDU
Session Container parses on 100% of frames, and the attack frames carry
`UL PDU SESSION INFORMATION (1)` with the unauthorized QFI.
**Refinement (2026-08-07):** the structural check is scoped to the GTP-U
layer (container dissects + fields in 3GPP range via tshark), NOT to
Wireshark whole-frame expert-info. Reason: tshark's heuristic upper-layer
dissectors (LISP/TLS) misfire on the random inner T-PDU payload and raise a
"malformed" expert error on ~1 in 29k *benign* frames (observed:
`Invalid message end marker`, a LISP artifact on frame 12149) that has
nothing to do with GTP-U well-formedness. The inner T-PDU is opaque user
data a UPF forwards without inspection, so those artifacts are out of scope;
counting them would spuriously inflate the structural IDS's benign-FPR.
Field extraction for both detectors now comes from tshark (an independent
parser), not the Scapy library that built the packets, removing any
circularity in the "schema-valid" claim.
**Status:** Verified.

## 23. Wire packet sizes are not a single MTU spike

**Claim:** The benign baseline's packet-size distribution resembles real
downlink web browsing (a bimodal mix of large data segments and smaller
packets), not a degenerate spike at MTU.
**Finding (2026-08-07):** in a real calibration run, 1,825 of 1,865 wire
packets were exactly 1,444 bytes — every burst's byte budget was sliced into
a uniform train of MTU frames, so the size histogram was a single spike with
no small-packet mode. Real downlink web browsing is bimodal (small-object
responses, TLS/HTTP-2 control records, response tails vs. bulk MSS
segments); a lone MTU spike is trivially separable by any size-feature IDS,
undermining the benign baseline's use for measuring such detectors'
false-positive rates.
**Fix:** `_segment_burst_sizes` re-slices each burst's byte budget into a
bimodal mix (`_SMALL_SEGMENT_FRACTION` of segments drawn from
`_SMALL_SEGMENT_RANGE` 40–400 B, the rest from `_LARGE_SEGMENT_RANGE`
1000–1400 B). The sum is preserved exactly, so re-segmentation does not
change the burst's contribution to the achieved bitrate.
**Reverification:** on a 40-arrival mock run the wire trace went from ~1
distinct size to 768, spread across small (≤200 B) / mid / large (≥1200 B)
buckets, mean ~990 B, min 84 B / max 1444 B; achieved bitrate still tracked
the input mean (7.93 Mbps for a ~8 Mbps canned mean; the real 5QI 6 run
tracks Table II R5QI 5 Mbps within a few %).
**Caveat:** this is a *modeled* size mix chosen to break the MTU spike, not a
distribution derived from a real capture's TCP dynamics — the flow still has
no congestion-control-driven segment pattern, no real ACK stream, and no
per-object structure (see #20). It is realistic in its marginal size
distribution, not in its causal packet-generation process.
**Status:** Fixed.
