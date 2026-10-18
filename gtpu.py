"""GTP-U mutation model and Scapy wire builder (3GPP TS 29.281 / TS 38.415).

The dataclasses are the LLM-facing model (parse + schema-validate a mutation);
build_gtpu_packet turns one into a G-PDU carrying a PDU Session Container.
FIELD_BOUNDS is the single source of the 3GPP ranges — the prompt schema in
llm_client.py, is_valid_schema, and the builder's own validation all read it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from scapy.contrib.gtp import GTPPDUSessionContainer, GTP_U_Header
from scapy.packet import Packet, Raw

from session_context import SessionContext

PDU_SESSION_CONTAINER_TYPE = 0x85

# 3GPP-defined GTP-U extension header types (TS 29.281 / 38.415 / 38.425 /
# 36.425). is_valid_schema tests membership only, so this is a set; the name of
# each type is kept as a comment. The pipeline generates 0x85 exclusively — the
# rest let the schema check accept any real 3GPP type instead of just 0x85.
KNOWN_EXTENSION_TYPES = frozenset({
    0x03,  # udp_port — UDP Port encapsulation
    0x40,  # pdcp_pdu_number — 16-bit PDCP Sequence Number (Handover/Dual Connectivity)
    0x81,  # suspend_request — Cellular IoT Suspend Request
    0x82,  # suspend_response — Cellular IoT Suspend Response
    0x83,  # long_pdcp_pdu_number — Long PDCP SN (NR/LTE Dual Connectivity)
    0x84,  # xw_ran_container — WLAN/LTE Interworking
    0x85,  # pdu_session_container — 5G Core QFI / RQI / PPI (N3/N9)
    0xC0,  # nr_ran_container — 5G RAN User Plane Control (Xn-U/F1-U)
})

# 3GPP specification field boundaries (TS 29.281, TS 38.415, RFC 2474).
FIELD_BOUNDS = {
    "qfi": {"min": 0, "max": 63},
    "rqi": {"min": 0, "max": 1},
    "ppi": {"min": 0, "max": 7},
    "pdu_type": {"min": 0, "max": 1},
    "outer_dscp": {"min": 0, "max": 0x3F},
}


def in_bounds(name: str, value: Any) -> bool:
    b = FIELD_BOUNDS[name]
    return isinstance(value, int) and b["min"] <= value <= b["max"]


# --- model ------------------------------------------------------------------
@dataclass
class ExtensionHeader:
    ext_type: int      # e.g. 0x85 PDU Session Container
    qfi: int = 0
    rqi: int = 0
    ppi: int = 0
    pdu_type: int = 0

    def is_valid_schema(self) -> bool:
        return (self.ext_type in KNOWN_EXTENSION_TYPES and
                all(in_bounds(f, getattr(self, f))
                    for f in ("qfi", "rqi", "ppi", "pdu_type")))


@dataclass
class GTP_U_Mutation:
    teid: int
    extension_headers: List[ExtensionHeader] = field(
        default_factory=lambda: [ExtensionHeader(PDU_SESSION_CONTAINER_TYPE)])
    outer_dscp: int = 0
    anomaly_type: str = "qfi_qer_mismatch"
    reasoning: str = ""
    sequence_number: int = 0
    npdu_number: int = 0
    payload_size: Optional[int] = None
    inter_arrival_ms: Optional[float] = None

    def is_valid_schema(self) -> bool:
        return (0 <= self.teid <= 0xFFFFFFFF and
                in_bounds("outer_dscp", self.outer_dscp) and
                1 <= len(self.extension_headers) <= 3 and
                all(h.is_valid_schema() for h in self.extension_headers))

    @classmethod
    def from_json(cls, ctx: SessionContext, mut_json: Dict) -> "GTP_U_Mutation":
        headers = [ExtensionHeader(
                       ext_type=h.get("type", h.get("ext_type", PDU_SESSION_CONTAINER_TYPE)),
                       qfi=h.get("qfi", 0),
                       rqi=h.get("rqi", 0),
                       ppi=h.get("ppi", 0),
                       pdu_type=h.get("pdu_type", 0),
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


# --- wire -------------------------------------------------------------------
class GTPUPDUSessionContainer(GTPPDUSessionContainer):
    """Project-facing name for Scapy's PDU Session Container implementation."""

    name = "GTP-U PDU Session Container"


def build_gtpu_packet(
    teid: int,
    *,
    pdu_type: Optional[int] = None,
    payload: Optional[Packet | bytes] = None,
    sequence_number: int = 0,
    npdu_number: int = 0,
    **container_fields: Any,
) -> GTP_U_Header:
    """Build a GTP-U G-PDU carrying a PDU Session Container.

    ``container_fields`` are the fields exposed by Scapy's
    ``GTPPDUSessionContainer`` (for example ``QMP``, ``SNP`` and ``PPP``).
    The current Scapy model deliberately uses the TS 38.415 field names,
    rather than the older draft's ``qfi/rqi/ppi`` byte layout.
    """
    if not 0 <= teid <= 0xFFFFFFFF:
        raise ValueError("teid must be in the range 0..0xffffffff")
    if not 0 <= sequence_number <= 0xFFFF:
        raise ValueError("sequence_number must be in the range 0..0xffff")
    if not 0 <= npdu_number <= 0xFF:
        raise ValueError("npdu_number must be in the range 0..0xff")

    fields = dict(container_fields)
    for lower, upper in (("qfi", "QFI"), ("rqi", "RQI"), ("ppi", "PPI")):
        if lower not in fields:
            continue
        if upper in fields:
            raise ValueError(f"use either {lower} or {upper}, not both")
        value = fields.pop(lower)
        if not in_bounds(lower, value):
            b = FIELD_BOUNDS[lower]
            raise ValueError(f"{lower} must be in the range {b['min']}..{b['max']}")
        fields[upper] = value

    has_rqi_or_ppi = fields.get("RQI", 0) > 0 or fields.get("PPI", 0) > 0
    if pdu_type is None:
        pdu_type = 0  # Default to DL (0) since RQI and PPI live in Downlink headers
    elif pdu_type == 1 and has_rqi_or_ppi:
        raise ValueError("RQI and PPI fields are downlink (DL) only and cannot be serialized with pdu_type=1 (UL)")
    if pdu_type not in (0, 1):
        raise ValueError("pdu_type must be 0 (DL) or 1 (UL)")

    if fields.get("PPI", 0) > 0 and "PPP" not in fields:
        fields["PPP"] = 1

    container = GTPUPDUSessionContainer(type=pdu_type, **fields)
    # S=0: sequence numbers are optional (TS 29.281) and a typical free5GC /
    # Open5GS N3 does not set them. E=1 still forces the 4-byte optional block
    # (seq/npdu/next-ext) onto the wire, so the extension header serialises
    # correctly; the seq field is simply carried as 0 and ignored, matching the
    # testbed. Pass sequence_number>0 only if a caller wants S=1 behaviour.
    packet = GTP_U_Header(
        version=1,
        PT=1,
        E=1,
        S=1 if sequence_number else 0,
        PN=0,
        gtp_type=255,
        teid=teid,
        seq=sequence_number,
        npdu=npdu_number,
        next_ex=PDU_SESSION_CONTAINER_TYPE,
    ) / container

    if payload is not None:
        packet = packet / (Raw(load=payload) if isinstance(payload, bytes) else payload)
    return packet


def _get(src: Any, key: str, default: Any = None) -> Any:
    return src.get(key, default) if isinstance(src, dict) else getattr(src, key, default)


def build_gtpu_packet_from_mutation(
    src: Any,
    payload: Optional[Packet | bytes] = None,
    **override_kwargs: Any,
) -> GTP_U_Header:
    """Build a G-PDU from a GTP_U_Mutation or an equivalent raw dict.

    Container fields are read from the top level or from the PDU Session
    Container entry in ``extension_headers``, the top level winning.
    """
    kwargs: Dict[str, Any] = {}
    for key in ("teid", "sequence_number", "npdu_number", "pdu_type",
                "qfi", "rqi", "ppi", "QFI", "RQI", "PPI"):
        value = _get(src, key)
        if value is not None:
            kwargs[key] = value

    for h in _get(src, "extension_headers", []) or []:
        if _get(h, "type", _get(h, "ext_type")) != PDU_SESSION_CONTAINER_TYPE:
            continue
        for key in ("qfi", "rqi", "ppi", "QFI", "RQI", "PPI", "pdu_type"):
            value = _get(h, key)
            if value is not None:
                kwargs.setdefault(key, value)

    kwargs.update(override_kwargs)
    kwargs.setdefault("teid", 0)
    return build_gtpu_packet(payload=payload, **kwargs)
