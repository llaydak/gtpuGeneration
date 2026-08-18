# Dataset Validation Log

Tracks every claim this project makes about its generated GTP-U benign+attack
dataset, how it was verified, and its status. The dataset is intended for
publication, so each claim must be independently checkable rather than taken
on faith. Methodology loosely follows "Datasheets for Datasets" (Gebru et
al., 2018, arXiv:1803.09010) — cite in the paper if referencing this process.

Status values: **Verified** (checked, holds), **Fixed** (was wrong, now
corrected and reverified), **Open** (known gap, not yet resolved).

---

## 1. GTP-U wire format is 3GPP-compliant (TS 29.281 / TS 38.415)

**Claim:** Extension header encoding (type, QFI, RQI, PPI, PDU type) matches
the 3GPP bit layout.
**Verification:** Unit tests in `test_phase1_starter.py`
(`test_gtpu_mutation_adapter_builds_scapy_packet`,
`test_gtpu_dict_adapter_builds_scapy_packet`,
`test_gtpu_mutation_rqi_regression_and_ppp_auto_set`,
`test_build_gtpu_packet_raises_value_error_on_ul_rqi_ppi`).
**Status:** Verified.

## 2. Attack packets have a structurally realistic inner packet (T-PDU)

**Claim:** An attack packet's inner payload is a valid, dissectable IP packet,
not raw filler a packet analyzer would flag as malformed.
**Finding (2026-08-04):** `_build_attack_packet` used `Raw(b"X" * n)` with no
inner IP header; in Wireshark the filler mis-parsed as a bogus inner IP.
**Fix:** Wrapped the payload in a real inner IP packet, matching the benign
path. The inner T-PDU was later upgraded from the initial IP/ICMP placeholder
to a direction-aware IP/TCP web-browsing segment (see #8, #15, #16, #17); the
"dissectable inner IP, not raw filler" property still holds.
**Status:** Fixed.

## 3. Attack packets' outer DSCP marking reflects the claimed violation on the wire

**Claim:** A DSCP-violation attack carries the *violating* DSCP in the outer
IP ToS byte, not the session's correct one.
**Finding (2026-08-04):** The wire packet hardcoded `tos=ctx.dscp_marking << 2`
(the correct DSCP), so DSCP-violation attacks only carried the wrong value in
telemetry, never on the wire.
**Fix:** Changed to `tos=gtp_mutation.outer_dscp << 2`. Reverified: an
`outer_dscp=46` mutation re-dissects from the written pcap as `dscp=46`.
**Status:** Fixed.

## 4. Benign LLM batch calls complete without truncation

**Claim:** A `generate_benign_batch` call finishes with valid JSON within its
token ceiling.
**Finding (2026-08-04):** At `llm_batch_size=200` (ceiling 60000) one run hit
exactly 60000 completion tokens and was cut off mid-JSON — 0 usable packets
after burning the full budget.
**Fix (2026-08-05):** `generate()` now captures `finish_reason`
(`self.last_finish_reason`), so truncation is detected explicitly, not
inferred from a parse failure. On truncation the retry loop halves
`batch_size` (and the token ceiling) before retrying. Verified with a mocked
truncate-then-succeed run: 100→truncated→50→succeeded.
**Status:** Fixed — retry is deterministic given a truncation signal, but the
initial `llm_batch_size` is still a guess; monitor `[WARN] Response was
truncated` frequency in production runs.

## 5. `--max-packets` bounds traffic arrivals, not wire segments

**Claim:** N/A — a parameter-semantics gotcha, but one that could silently
reduce diversity: a few large bursts could exhaust a packet budget after only
a handful of real arrivals.
**Finding (2026-08-05):** The loop gated on `seq` (post-segmentation wire
packets), not LLM arrivals.
**Fix:** Loop now gates on `llm_arrivals_used`; help text and prints describe
it as an arrival cap; `llm_arrivals_used`/`llm_arrivals_unused` added to
telemetry, with an `[INFO]` print when a batch's leftover arrivals go unused.
**Status:** Fixed by inspection (arrival-vs-segment distinction is structurally
enforced by which counter gates the loop). Recommend one live run with a small
`--max-packets` to confirm `llm_arrivals_used == max_packets` while
`packet_count` exceeds it.

## 6. Attack campaign violation-type diversity (QFI vs RQI vs DSCP)

**Claim:** A campaign exercises all three violation dimensions (QFI outside
active set, RQI outside allow-list, DSCP mismatch) roughly evenly, not one.
**Finding (2026-08-03):** An early run skewed 6/10 toward RQI.
**Fix:** Added dimension-rotation instructions and 3 real few-shot examples
(one per dimension) to `generate_mutation`'s prompt. Two post-fix runs split
4/4/4 and 3/3/2 across QFI/RQI/DSCP.
**Status:** Fixed, reverified on 2 runs only — sample a larger set (10+) before
citing "balanced" as a dataset-wide property.

## 7. Attack campaign size and injection point are not hardcoded

**Claim:** Each campaign's size and point in the timeline are model-chosen, not
constant — a real attack could occur anywhere with any duration.
**Implementation (2026-08-04):** `generate_mutation` asks the model to decide
`campaign_size`/`injection_fraction` in its first response
(`request_campaign_plan`). Two runs differed: `injection_fraction` 0.400/0.620,
`campaign_size` 12/8.
**Status:** Verified on 2 runs — same small-sample caveat as #6.

## 8. Benign 5QI-6 inner payload matches its claimed application type (TCP)

**Claim:** TS 23.501 Table 5.7.4-1 describes 5QI 6 as Non-GBR TCP-based apps
(www, email, chat, ftp), so the inner T-PDU should be TCP-based.
**Finding (2026-08-05):** The inner payload was an IP/ICMP echo — a placeholder
for a valid dissectable inner packet (see #2), not the claimed TCP class.
**Fix:** Both paths now build an inner IP/TCP web-browsing segment (padded to
the LLM-requested size). The initial fix used a fixed
`TCP(sport=51820, dport=80, seq=1000, ack=1000)` toward `8.8.8.8`; this was
subsequently superseded by per-burst randomized ports/sequence numbers (#15),
true downlink direction and endpoints (#16), and port 443 with high-entropy
payload (#17).
**Status:** Fixed — inner protocol now matches the claimed 5QI-6 traffic class.

## 9. Benign long-run achieved bitrate is plausible

**Claim:** `achieved_bitrate_bps` (long-run total_bytes/duration) should be
realistic for web browsing, without being anchored to any single external
figure (project grounds in TS 23.501, not Table II's 5 Mbps — see #10 and
project memory `project_gtpu_3gpp_grounding`).
**Observation:** Across unanchored runs it came out at 2.70–3.36 Mbps — same
order of magnitude as, and somewhat below, Table II's figure. This is the
long-run average; per-burst instantaneous means are naturally much higher
(12–17 Mbps observed) due to the bursty on/off pattern and should not be
compared to Table II's R5QI directly.
**Status:** Verified as plausible on runs observed; not a formal test.
Recommend an aggregate goodness-of-fit test against a published mobile-traffic
dataset before a strong "realistic" claim in the paper.

## 10. Traffic parameter grounding: 3GPP TS 23.501, not a third-party paper

**Claim:** Benign timing/bitrate is derived from each QFI's own TS 23.501
Table 5.7.4-1 QoS characteristics (Resource Type, Priority, PDB, PER), not from
the Nikolaidis et al. (NOMS 2023) Table II means.
**Status:** Implemented (2026-08-04). **Caveat:** the PDB/Priority/PER numbers
in `_5QI_3GPP_REFERENCE` (`llm_client.py`) were reproduced from memory of the
table, not a live spec copy — cross-check against an actual TS 23.501 before
citing these exact numbers.

## 11. No hardcoded correction of LLM output

**Claim:** Nothing silently clamps, repairs, or rejects-and-retries
LLM-produced fields to look more compliant than they are; evaluation metrics
(schema validity, semantic precision) are read-only, so reported rates reflect
genuine model behavior.
**Status:** Implemented (2026-08-04) — removed `_clamp_extension_headers`,
`_ensure_diverse_structure`, `_evaluate_structured_claims`,
`_infer_anomaly_type`, `_build_reasoning`. See project memory
`feedback_no_hardcoded_llm_correction`.

## 12. Non-LLM ("stats") generation path removed

**Decision (2026-08-05):** The fast non-LLM `mode="stats"` path (sampling
`TABLE_II_5QI_STATS` via `_sample_table_ii_burst`, raw bytes via
`_FastSessionPacketBuilder`) and its helpers (`_sample_table_ii_burst`,
`_checksum16`, `_FastSessionPacketBuilder`, `_PAYLOAD_SIZE_CV`) were removed;
`create_web_browsing_stream` is LLM-only and `--mode` no longer exists. The
project's contribution is LLM-driven generation; the stats path was only a
comparison baseline, and its comparison data already exists (#9). It is
recoverable from git history if a rigorous distribution benchmark is needed
later. `TABLE_II_5QI_STATS` and the `achieved_bitrate` vs. `table_ii_reference`
telemetry comparison were kept as a static reference, not a sampling path.
**Status:** Implemented — test suite (6/6) and both CLIs reverified.

## 13. No public dataset provides ground truth for QFI/extension-header realism

**Claim under test:** Before this project's QFI marking (via GTP-U PDU Session
Container extension headers) can be called "realistic," it should be checked
against real 5G GTP-U traffic that populates this field — if any public dataset
does.
**Method:** Four candidate datasets were inspected directly (with `tshark`:
`gtp.flags.e`, `gtp.ext_hdr`, `gtp.ext_hdr.pdu_ses_con.qos_flow_id`; or by
reading the schema where no packet data exists), not assumed from docs.

| Dataset | Capture environment | GTP-U present? | QFI/ext. header populated? |
|---|---|---|---|
| Mugna46/N3_dataset | Non-native (Kitsune IDS traffic re-tunneled through GTP-U) | Yes (structural) | Not checked — benign traffic isn't 5G-native, moot here |
| 5GAD-2022 (`IdahoLabResearch/5GAD`) | Simulated (free5GC) | **No** — "upfgtp" is the UPF's internal tun interface (already-decapsulated inner packets); `tshark -Y gtp` matched 0 frames in a 374-pkt Normal-1UE sample and a 4-pkt attack file | N/A |
| Wengappuli (Oulu, Dec 2024 thesis) | Simulated (Open5GS/UERANSIM) | **No packet data** — aggregated Prometheus/Loki metrics by design | N/A |
| **5G-NIDD** (Oulu, real RF network) | **Real RF hardware** | Yes | **No** — `gtp.flags.e==1` matched 0 of 5,348 frames in `SSH_BS2.pcapng` and 0 of 90,907 in `UDPScan_BS2.pcapng`; the QFI field never appears |

**Finding:** Not one of the four — including 5G-NIDD, the only RF-captured one —
populates the QFI/PDU Session Container header on the wire. 5G-NIDD carries a
valid TEID but `gtp.flags.e` is unset on every sampled packet, meaning its
gNB/UPF was not configured to mark per-flow QoS at the GTP-U layer.
**Implication:** There is no empirical baseline to validate this project's
QFI-marking realism against, so the 3GPP-spec-grounded approach
(`_5QI_3GPP_REFERENCE`, TS 23.501 / 29.281 / 38.415 — see #1, #10) is the only
rigorous path; state this absence explicitly on publication.
**Status:** Verified (absence of ground truth confirmed by inspection). Re-open
if a public 5G dataset that populates GTP-U extension headers appears.

## 14. Reported inter-arrival time is comparable to Table II's T5QI

**Claim:** The published per-burst inter-arrival figure should be directly
comparable to Table II's T5QI (100 ms for 5QI 6), so a reader can sanity-check
achieved timing against the reference.
**Finding (2026-08-06):** `avg_inter_arrival_ms` was a flat average over every
telemetry record. But each LLM arrival ("burst") is split into many wire
segments (see #5, #23), and every non-first segment carries only a tiny
intra-burst gap (see #18), not a real sampled arrival gap. These sub-ms gaps
vastly outnumbered the real ones in the average — an observed run reported
3.22 ms despite the burst-arrival process itself averaging ~101 ms, on T5QI.
**Fix:** Each telemetry record is now tagged `is_burst_start` (true only for a
burst's first wire segment), and the reported `avg_burst_inter_arrival_ms` is
computed over those records only, making it directly comparable to T5QI.
`achieved_bitrate_bps` was also switched from an average-of-ratios to a direct
`total_bytes*8/simulated_duration_seconds` measure, insensitive to segmentation
granularity.
**Note:** T5QI is a *sanity comparator*, not a target the LLM is prompted to
hit — timing is grounded in TS 23.501 (#10), so agreement is a plausibility
check, not a fitted result (cf. the same caveat for bitrate in #9).
**Status:** Fixed — reverified against a prior run: 413 burst-start records,
avg ≈101.2 ms vs. T5QI=100 ms. (That run predated the field, so burst-starts
were reconstructed via the then-valid `inter_arrival_ms != 1.0` proxy; the
proxy no longer holds since #18, so reuse the `is_burst_start` field directly.)

## 15. Inner TCP header is not a static, repeated artifact

**Claim:** With a real TCP inner T-PDU (#8), following one flow (5-tuple +
sequence numbers) should show plausible, internally-consistent TCP behavior —
not the same header on every packet.
**Finding (2026-08-06):** A generated PCAP had `sport=51820, seq=1000, ack=1000`
identical on all 18,647 packets — both paths reused one fixed `TCP()` object.
**Fix:** `create_web_browsing_stream` gives each burst its own ephemeral port
and ISN; the sequence number advances across the burst's segments by each
segment's TCP data length (size − 40 B header), and only the last segment
carries `PSH` (interior segments `ACK`). `_build_attack_packet` similarly
randomizes sport/seq/ack per packet.
**Status:** Fixed — reverified: within a burst, sequence numbers advance
correctly (e.g. `3589583794 → 3589585154 → 3589586514`), and consecutive
bursts land on different ports/ISNs.

## 16. PDU Session Container direction matches the packet's direction (TS 38.415)

**Claim:** The container's PDU Type must agree with the packet's actual
direction. Per TS 38.415, DL PDU Session Information (type 0) is UPF → NG-RAN;
UL (type 1) is NG-RAN → UPF.
**Finding (2026-08-06):** A generated PCAP was self-contradictory on every
packet: outer `192.168.100.10 → .20` (gNB→UPF = uplink), inner
`10.45.0.2 → 8.8.8.8` (UE→internet = uplink), but container `pdu_type=0` (DL).
The DL default is itself correct — RQI/PPI are DL-only, required for them to be
serializable — but nothing flipped the packet's direction to match. Secondary:
web browsing is downlink-dominant, so modeling ~62 KB bursts on the uplink put
the byte volume on the wrong side.
**Fix:** Both paths now emit true downlink G-PDUs — outer `upf_ip → gnodeb_ip`,
inner `_WEB_SERVER_IP → _UE_IP` — so `pdu_type=0` is correct, RQI is
meaningful, and the volume sits on the direction that carries it.
**Status:** Fixed — reverified: outer `192.168.100.20 → .10`, `pdu_type=0`,
inner `93.184.216.34 → 10.45.0.2`.

## 17. Payload bytes are not a zero-entropy artifact

**Claim:** Inner payload bytes must not carry a signature a detector could
separate benign from attack on, independently of the QoS violation under study.
**Finding (2026-08-06):** Padding was `b"X" * pad_len` (entropy ≈ 0). Entropy
and compression-ratio are common IDS features, so a model could learn the
padding artifact rather than the anomaly. Cleartext port 80 was also modeled.
**Fix:** Padding is now `os.urandom(pad_len)`, modeling incompressible
TLS-encrypted application data, with the inner server port moved to 443 so the
high entropy is self-consistent.
**Status:** Fixed — measured payload entropy 7.81–7.89 bits/byte (8.0 ideal).

## 18. Inter-packet timing is not a fixed constant

**Claim:** Wire-level packet spacing should be physically achievable and not
deterministic.
**Finding (2026-08-06):** 98% of gaps were exactly 1.000 ms (16,920 of 18,646)
— a fixed `_INTRA_BURST_GAP_MS`. Real back-to-back MTU frames are separated by
serialization time (~0.012 ms for 1444 B at 1 Gbps), never a constant.
**Fix:** Intra-burst spacing is now each segment's serialization delay at an N3
line rate (`_N3_LINK_BPS`, 1 Gbps) × a random jitter factor
(`_INTRA_BURST_JITTER_RANGE`), with a small floor, plus a rare larger gap
(`_INTRA_BURST_PAUSE_PROB`/`_RANGE_MS`) modeling an ACK-clock/RAN-scheduler
pause. Burst-arrival gaps (the T5QI-comparable ones, #14) are untouched.
**Status:** Fixed — reverified: intra-burst gaps span a distribution of
sub-ms values (µs-granularity limited by libpcap timestamps), not one constant.
**Cost side effect:** simulated time now advances almost entirely via
burst-arrival gaps rather than accumulated 1 ms segment gaps, so covering a
given `--duration` needs ~45% more LLM arrivals (and tokens) than before. This
is correct — the old figure was inflated by the artifact — but must be
accounted for when estimating run cost.

## 19. IP identification and TTL fields are not static

**Claim:** IP header fields that vary in real stacks should vary here too.
**Finding (2026-08-06):** All 18,647 packets carried `IP id = 1`, `TTL = 64`
on both headers — Scapy's constant defaults. Real stacks vary IP ID per packet
(RFC 6864), and a downlink response arrives with TTL already decremented.
**Fix:** IP ID is drawn per packet on both headers; inner TTL is drawn per TCP
connection from a plausible post-path range (52–62).
**Status:** Fixed — reverified: 130/130 distinct outer and 129/130 distinct
inner IP IDs across a 130-packet sample, with inner TTLs varying per connection.

## 20. Known remaining realism gaps (open)

Recorded so they are not mistaken for verified properties. None are spec
violations; all are traffic-modeling simplifications.

- **No TCP connection lifecycle.** No handshake, teardown, pure-ACKs, or
  retransmissions; flows appear mid-stream ("Follow TCP Stream" is one-sided).
- **Single server, single UE, no DNS.** Real browsing resolves names and fans
  out across many servers/connections; this models one server IP and one UE.
- **Benign background is downlink-only.** A real capture point would also see
  the uplink request/ACK stream. (Attack packets can be uplink — see #21 — but
  the benign background is DL.)
- **Single fixed TEID (`0xDEADBEEF`).** Real N3 allocates a TEID per direction;
  a magic constant is both simplified and an obvious synthetic marker.
- **GTP-U S flag set on every G-PDU.** Sequence numbers are optional per
  TS 29.281; typical free5GC/Open5GS N3 runs `S=0`. Not a violation, but
  atypical, and adds 4 bytes per packet.
- **QFI numerically equals 5QI (both 6).** Permitted, but QFI is an arbitrary
  0–63 identifier that need not align with the 5QI in a real deployment.

**Status:** Open — disclose in any publication.

---

## 21. Uplink attack targets the field the UPF actually verifies (TS 29.244 / 23.501 §5.7)

**Claim:** An uplink (`--direction UL`, pdu_type=1) `qfi_qer_mismatch` attack
carries a QFI outside the session's authorized set — exactly what the UPF's
uplink QoS-flow-ID verification must reject — with a spec-correct UL container
(QFI only; no downlink-only RQI/PPI).
**Rationale:** For downlink the UPF *produces* QFI/RQI/DSCP, so a DL mutation
models a compromised-UPF egress. On the uplink the UPF is the *verifier*
(TS 29.244 PDR/QER matching), so UL QFI mismatch is the load-bearing "semantic
attack against the UPF" case.
**Verification:** `_evaluate_semantic_precision(..., direction="UL")` marks only
`violates_active_qfis` as the enforced anomaly and records
`enforcement_point = "UPF (UL QoS-flow-ID verification)"`; the builder emits
`pdu_type=1` with RQI/PPI absent (rejected by `build_gtpu_packet` if set), and
tshark dissects the container as `UL PDU SESSION INFORMATION (1)` with the
marked QFI and no error. Confirmed on a mixed DL-benign + UL-attack pcap.
**Status:** Verified.

## 22. Attack packets are semantic, not structural (Tier-1 detection-gap proof)

**Claim:** Injected attacks are schema-valid — accepted by a session-unaware
parser — yet detectable only by a session-aware policy check. This is the
offline evidence for the study's "semantics over syntax" claim, independent of
any live UPF.
**Verification:** `detection_gap_report.py` runs two detectors over a pcap: a
STRUCTURAL IDS (tshark: container dissects + fields in 3GPP range) and a
SEMANTIC IDS (session-policy check re-derived from the wire, not generator
labels). The structural IDS flags 0% of attacks (100% schema-valid); the
semantic IDS flags 100% with 0% benign false-positives; the detection gap is
the fraction structurally valid but semantically anomalous. The semantic logic
mirrors `LLMClient._evaluate_semantic_precision`, so labels and proof agree by
construction while staying independently computed.
**Reverification:** Re-run `./upfvenv/bin/python detection_gap_report.py <pcap>`
(report → `<pcap>_detection_gap.json`). On a real UL run
(`injected_attack_stream_20260807_131847`, 29,010 packets, 4 UL attacks with
QFI 7/8/9/10 vs authorized {6}): structural 0%/0%-FPR, semantic 100%/0%-FPR,
gap 4/4; independent tshark dissection confirmed the container parses on 100%
of frames.
**Refinement (2026-08-07):** the structural check is scoped to the GTP-U layer,
NOT Wireshark whole-frame expert-info — tshark's heuristic upper-layer
dissectors (LISP/TLS) misfire on the random inner payload and raise a
"malformed" error on ~1 in 29k *benign* frames, which has nothing to do with
GTP-U well-formedness. The inner T-PDU is opaque user data a UPF forwards
without inspection, so those artifacts are out of scope. Both detectors extract
fields via tshark (not the Scapy library that built the packets), removing
circularity in the "schema-valid" claim.
**Status:** Verified.

##


## 24. Live free5GC UPF does not police the uplink QFI; forwarding costs UPF CPU (empirical)

**Claim:** Against a real UPF the uplink `qfi_qer_mismatch` attack is not
dropped: a G-PDU with a QFI outside the authorized set, on the session's valid
uplink TEID, is forwarded to the data network like authorized traffic — the UPF
enforces the TEID but not the marked QFI. Forwarding costs measurable UPF CPU,
though a single commodity injector does not degrade concurrent legit service.

**Testbed:** free5GC v4.2.3 (free5gc-compose) + gtp5g v0.9.5 on Linux 6.8,
UERANSIM v3.3.0 gNB+UE, subscriber `imsi-208930000000001`. One PDU session on
DNN `internet` (5QI 9). Live N3 parameters read by capture
(`tshark -i br-free5gc -f "udp port 2152"`): UPF N3 `10.100.200.2`, gNB N3
`10.100.200.13`, uplink TEID `0x2`, authorized QFI `1`, UE IP `10.60.0.1`.
Attack sent on-wire with `inject_qfi_attack.py` (forwarding confirmed by a
unique-ICMP-id downlink round trip).

**Enforcement result (three-way control):**

| TEID | QFI | Marked as | Result |
|------|-----|-----------|--------|
| `0x2` (valid) | 1 | authorized | FORWARDED — control, validates method |
| `0x2` (valid) | 7 | **unauthorized** | **FORWARDED** — attack succeeds; QFI not verified |
| `0x999` (invalid) | 1 | authorized | DROPPED — TEID *is* enforced |

The valid-TEID/unauthorized-QFI packet forwarding while the invalid-TEID packet
drops isolates the finding: QFI is not part of free5GC's uplink PDR match. This
grounds #22 empirically — the enforcement point does not catch the QFI/QER
mismatch, so detection must be session-aware.

**Forwarding-cost result (`measure_upf_cost.py`, 12 s/point, 44-byte payload,
unauthorized QFI 7, inner dst `192.0.2.1` blackhole):**

| target pps | achieved pps | UPF CPU avg | legit RTT avg | loss |
|-----------:|-------------:|------------:|--------------:|-----:|
| 0 | 0 | 2.5% | 14.05 ms | 0% |
| 1,000 | 1,000 | 38.3% | 14.36 ms | 0% |
| 10,000 | 10,000 | 112.3% | 14.01 ms | 0% |
| 50,000 | 44,414 | 115.6% | 13.95 ms | 0% |
| 150,000 | 44,062 | 124.5% | 14.11 ms | 0% |

**Interpretation:** two demonstrated downsides — (1) enforcement bypass
(unauthorized QFI accepted), and (2) a steep per-packet UPF CPU cost (2.5% idle
→ 38% at 1k pps → over one core by 10k pps). **No** observed service
degradation at this scale: legit RTT (~14 ms) and loss (0%) unaffected at every
rate. A single-threaded UDP sender caps at ~44k pps, so the UPF was never
saturated — the "no degradation" result is bounded by the injector, not shown
to be a property of the UPF.

**Caveats:**
- CPU% is coarse `docker stats` (cgroup) accounting; the robust claim is the
  2.5% → >100% delta, not the exact figure.
- The sweep is sender-limited above ~44k pps; finding the degradation knee
  needs a faster/parallel injector or a resource-capped UPF
  (`docker update --cpus=1 upf`).
- Frame as "free5GC does not police the uplink QFI" (QFI is not a UL PDR match
  field), **not** "free5GC violates 3GPP": TS 23.501 §5.7 permits QFI as a PDI
  match field but does not strictly mandate policing the UE's uplink marking.
- TEID/QFI are session-ephemeral; the values above are from one session.

**Reproduce:** bring up free5gc-compose (gtp5g loaded, subscriber provisioned),
start the UE, read the live TEID/QFI off N3, then
`sudo ./upfvenv/bin/python3 inject_qfi_attack.py --qfi 7` (enforcement) and
`./upfvenv/bin/python3 measure_upf_cost.py` (cost).

**Status:** Verified (free5GC v4.2.3 + gtp5g v0.9.5 on Linux 6.8).
