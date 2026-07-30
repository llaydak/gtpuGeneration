"""Synthetic PDU Session state generator for 5G Core N4/PFCP QoS rules."""

import random
from dataclasses import dataclass
from typing import Optional, Dict, List


@dataclass
class SessionContext:
    """A synthetic PDU session state, as it would exist after PFCP/N4 setup.

    Mutations are only semantically meaningful *relative to* a session's
    QER/FAR mapping so this is generated first and fed into every prompt,
    instead of mutating against a single fixed reference session.
    """
    teid: int
    active_qfis: List[int]                # QFIs legitimately provisioned for this session
    qfi_to_5qi: Dict[int, int]             # which 5QI each QFI is supposed to map to
    qfi_to_qer: Dict[int, int]             # which QER enforces each QFI
    reflective_qos_enabled_qfis: List[int]  # QFIs where RQI=1 is actually valid
    dscp_marking: int                      # expected outer DSCP for this session's default flow
    pdu_type: int = 0                      # 0: DL (Downlink), 1: UL (Uplink)

    @classmethod
    def random_synthetic(cls, seed: Optional[int] = None) -> "SessionContext":
        rng = random.Random(seed)
        teid = rng.randint(1, 0xFFFFFFF)
        qfis = sorted(rng.sample(range(1, 64), k=rng.randint(2, 4)))
        return cls(
            teid=teid,
            active_qfis=qfis,
            qfi_to_5qi={q: rng.choice([1, 5, 6, 7, 9, 69, 79]) for q in qfis},
            qfi_to_qer={q: rng.randint(1, 32) for q in qfis},
            reflective_qos_enabled_qfis=rng.sample(qfis, k=max(1, len(qfis) // 2)),
            dscp_marking=rng.choice([0x00, 0x08, 0x28, 0x2E]),
            pdu_type=0,  # Locked to DL (0) for Phase 1 single-direction experimental scope
        )

    def to_prompt_block(self) -> str:
        direction_str = "DL (Downlink)" if self.pdu_type == 0 else "UL (Uplink)"
        return (
            f"- TEID: {self.teid}\n"
            f"- Session Direction: {direction_str} (pdu_type={self.pdu_type})\n"
            f"- Active QFIs for this session: {self.active_qfis}\n"
            f"- QFI -> 5QI mapping: {self.qfi_to_5qi}\n"
            f"- QFI -> QER mapping: {self.qfi_to_qer}\n"
            f"- QFIs where Reflective QoS (RQI=1) is legitimately allowed: "
            f"{self.reflective_qos_enabled_qfis}\n"
            f"- Session's expected outer DSCP marking: 0x{self.dscp_marking:02x}"
        )
