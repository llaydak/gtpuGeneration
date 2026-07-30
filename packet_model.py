"""GTP-U extension header and packet mutation dataclasses."""

import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List

from gtpu_scapy import KNOWN_EXTENSION_TYPES
from session_context import SessionContext


@dataclass
class ExtensionHeader:
    ext_type: int      # e.g. 0x85 PDU Session Container
    qfi: int = 0
    rqi: int = 0
    ppi: int = 0
    pdu_type: int = 0

    def is_valid_schema(self) -> bool:
        return (self.ext_type in KNOWN_EXTENSION_TYPES and
                0 <= self.qfi <= 63 and self.rqi in {0, 1} and 0 <= self.ppi <= 7 and
                self.pdu_type in {0, 1})


@dataclass
class GTP_U_Mutation:
    teid: int
    extension_headers: List[ExtensionHeader] = field(default_factory=lambda: [ExtensionHeader(0x85)])
    outer_dscp: int = 0
    anomaly_type: str = "qfi_qer_mismatch"
    reasoning: str = ""
    seq_flag: int = 0
    npdu_flag: int = 0
    sequence_number: int = 0
    npdu_number: int = 0
    payload_size: Optional[int] = None
    inter_arrival_ms: Optional[float] = None
    timestamp: Optional[float] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()

    def is_valid_schema(self) -> bool:
        return (0 <= self.teid <= 0xFFFFFFFF and
                0 <= self.outer_dscp <= 0x3F and
                1 <= len(self.extension_headers) <= 3 and
                all(h.is_valid_schema() for h in self.extension_headers))

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_json(cls, ctx: SessionContext, mut_json: Dict) -> "GTP_U_Mutation":
        headers = [ExtensionHeader(
                       ext_type=h.get("type", h.get("ext_type", 0x85)),
                       qfi=h.get("qfi", 0),
                       rqi=h.get("rqi", 0),
                       ppi=h.get("ppi", 0),
                       pdu_type=h.get("pdu_type", 0)
                   )
                   for h in mut_json["extension_headers"]]
        return cls(
            teid=mut_json.get("teid", ctx.teid),
            extension_headers=headers,
            outer_dscp=mut_json.get("outer_dscp", ctx.dscp_marking),
            anomaly_type=mut_json.get("anomaly_type", mut_json.get("traffic_class", "qfi_qer_mismatch")),
            reasoning=mut_json.get("reasoning", ""),
            payload_size=mut_json.get("payload_size"),
            inter_arrival_ms=mut_json.get("inter_arrival_ms"),
        )

