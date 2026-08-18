"""PDU Session state for 5G Core N4/PFCP QoS rules."""

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class SessionContext:
    """A PDU session state, as it would exist after PFCP/N4 setup.

    Mutations are only semantically meaningful *relative to* a session's
    QER/FAR mapping, so this is built first and fed into every prompt. The
    pipeline uses one fixed web-browsing session -- see
    ``_make_web_browsing_session`` in generate_llm_pcap.py.
    """
    teid: int
    active_qfis: List[int]                # QFIs legitimately provisioned for this session
    qfi_to_5qi: Dict[int, int]             # which 5QI each QFI is supposed to map to
    qfi_to_qer: Dict[int, int]             # which QER enforces each QFI
    reflective_qos_enabled_qfis: List[int]  # QFIs where RQI=1 is actually valid
    dscp_marking: int                      # expected outer DSCP for this session's default flow
    pdu_type: int = 0                      # 0: DL (Downlink), 1: UL (Uplink)

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
