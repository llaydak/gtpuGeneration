"""Scapy helpers for building GTP-U packets with a PDU Session Container.

Scapy already provides the TS 38.415 PDU Session Container model in
``scapy.contrib.gtp``.  This module keeps that model as the source of truth
and adds validation plus a small builder for the GTP-U header chain.
"""

# it's now always DL unless a caller explicitly passes pdu_type=1. I confirmed this: build_gtpu_packet(teid=1, qfi=5) 
# (no RQI/PPI at all) now also comes out as type=0, where previously it defaulted to UL.
# If UL traffic matters for the study, worth adding pdu_type as a field 
# the LLM/knowledge graph samples explicitly with the RQI/PPI constraint 
# enforced downstream by this same ValueError guard
# rather than leaving it to the builder's default.

from __future__ import annotations

from typing import Any, Dict, Optional

from scapy.contrib.gtp import GTPPDUSessionContainer, GTP_U_Header
from scapy.packet import Packet, Raw


PDU_SESSION_CONTAINER_TYPE = 0x85
GTPU_PORT = 2152

SELF_HOSTED_MODELS_URL = "http://192.168.100.38:11434"
MODEL_VARIANT = "mistral:7b"

# Known GTP-U extension header types (3GPP TS 29.281 / 38.415 / 38.425 / 36.425).
# Complete & exhaustive set of all 3GPP spec-defined extension header types.
KNOWN_EXTENSION_TYPES = {
    0x03: "udp_port",                  # UDP Port encapsulation
    0x40: "pdcp_pdu_number",           # 16-bit PDCP Sequence Number (Handover/Dual Connectivity)
    0x81: "suspend_request",           # Cellular IoT Suspend Request
    0x82: "suspend_response",          # Cellular IoT Suspend Response
    0x83: "long_pdcp_pdu_number",      # Long PDCP SN (NR/LTE Dual Connectivity)
    0x84: "xw_ran_container",          # WLAN/LTE Interworking
    0x85: "pdu_session_container",     # 5G Core QFI / RQI / PPI (N3/N9)
    0xC0: "nr_ran_container",          # 5G RAN User Plane Control (Xn-U/F1-U)
    0xC1: "pdu_set_marker",            # Rel-18 Extended Reality (XR)
}

ALLOWED_ANOMALIES = {
    "qfi_qer_mismatch",                 # QFI not provisioned or QER rule mismatch
    "unsupported_extension_injection",  # PDU Set Marker (0xC1) or other exotic header abuse
    "cross_flow_interference",          # burst-based, individually-valid packets exploiting missing resource bounds
    "timing_window_race",               # PFCP N4 policy update + GTP-U packet in propagation window (two-stage)
}



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

	normalized_fields = dict(container_fields)
	for source_name, scapy_name, maximum in (
		("qfi", "QFI", 63),
		("rqi", "RQI", 1),
		("ppi", "PPI", 7),
	):
		if source_name in normalized_fields:
			if scapy_name in normalized_fields:
				raise ValueError(f"use either {source_name} or {scapy_name}, not both")
			value = normalized_fields.pop(source_name)
			if not isinstance(value, int) or not 0 <= value <= maximum:
				raise ValueError(f"{source_name} must be in the range 0..{maximum}")
			normalized_fields[scapy_name] = value

	has_rqi_or_ppi = (normalized_fields.get("RQI", 0) > 0 or normalized_fields.get("PPI", 0) > 0)

	if pdu_type is None:
		pdu_type = 0  # Default to DL (0) since RQI and PPI live in Downlink headers
	elif pdu_type == 1 and has_rqi_or_ppi:
		raise ValueError("RQI and PPI fields are downlink (DL) only and cannot be serialized with pdu_type=1 (UL)")

	if pdu_type not in (0, 1):
		raise ValueError("pdu_type must be 0 (DL) or 1 (UL)")

	if normalized_fields.get("PPI", 0) > 0 and "PPP" not in normalized_fields:
		normalized_fields["PPP"] = 1

	container = GTPUPDUSessionContainer(type=pdu_type, **normalized_fields)
	packet = GTP_U_Header(
		version=1,
		PT=1,
		E=1,
		S=1,
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


def extract_container_kwargs(mutation_or_dict: Any) -> Dict[str, Any]:
	"""Adapter converting a GTP_U_Mutation instance, dictionary, or raw header dict
	(e.g., {"qfi": x, "rqi": y, "ppi": z}) into kwargs accepted by build_gtpu_packet().
	"""
	kwargs: Dict[str, Any] = {}

	if isinstance(mutation_or_dict, dict):
		if "teid" in mutation_or_dict:
			kwargs["teid"] = mutation_or_dict["teid"]
		if "sequence_number" in mutation_or_dict:
			kwargs["sequence_number"] = mutation_or_dict["sequence_number"]
		if "npdu_number" in mutation_or_dict:
			kwargs["npdu_number"] = mutation_or_dict["npdu_number"]
		if "pdu_type" in mutation_or_dict:
			kwargs["pdu_type"] = mutation_or_dict["pdu_type"]

		for key in ("qfi", "rqi", "ppi", "QFI", "RQI", "PPI"):
			if key in mutation_or_dict:
				kwargs[key] = mutation_or_dict[key]

		ext_headers = mutation_or_dict.get("extension_headers", [])
		for h in ext_headers:
			if isinstance(h, dict):
				ext_type = h.get("type", h.get("ext_type"))
				if ext_type == PDU_SESSION_CONTAINER_TYPE:
					for key in ("qfi", "rqi", "ppi", "QFI", "RQI", "PPI"):
						if key in h and key not in kwargs:
							kwargs[key] = h[key]
					if "pdu_type" in h and "pdu_type" not in kwargs:
						kwargs["pdu_type"] = h["pdu_type"]
			elif hasattr(h, "ext_type") and getattr(h, "ext_type") == PDU_SESSION_CONTAINER_TYPE:
				for key in ("qfi", "rqi", "ppi"):
					if hasattr(h, key) and key not in kwargs:
						kwargs[key] = getattr(h, key)
				if hasattr(h, "pdu_type") and "pdu_type" not in kwargs:
					kwargs["pdu_type"] = getattr(h, "pdu_type")
	else:
		if hasattr(mutation_or_dict, "teid"):
			kwargs["teid"] = getattr(mutation_or_dict, "teid")
		if hasattr(mutation_or_dict, "sequence_number"):
			kwargs["sequence_number"] = getattr(mutation_or_dict, "sequence_number")
		if hasattr(mutation_or_dict, "npdu_number"):
			kwargs["npdu_number"] = getattr(mutation_or_dict, "npdu_number")
		if hasattr(mutation_or_dict, "pdu_type"):
			kwargs["pdu_type"] = getattr(mutation_or_dict, "pdu_type")

		ext_headers = getattr(mutation_or_dict, "extension_headers", [])
		for h in ext_headers:
			ext_type = getattr(h, "ext_type", getattr(h, "type", None))
			if ext_type == PDU_SESSION_CONTAINER_TYPE:
				for key in ("qfi", "rqi", "ppi"):
					if hasattr(h, key) and key not in kwargs:
						kwargs[key] = getattr(h, key)
				if hasattr(h, "pdu_type") and "pdu_type" not in kwargs:
					kwargs["pdu_type"] = getattr(h, "pdu_type")

	return kwargs


def build_gtpu_packet_from_mutation(
	mutation_or_dict: Any,
	payload: Optional[Packet | bytes] = None,
	**override_kwargs: Any,
) -> GTP_U_Header:
	"""Build a GTP-U Scapy packet from a GTP_U_Mutation object or dictionary."""
	kwargs = extract_container_kwargs(mutation_or_dict)
	kwargs.update(override_kwargs)
	if "teid" not in kwargs:
		kwargs["teid"] = 0
	return build_gtpu_packet(payload=payload, **kwargs)


def decode_gtpu_packet(data: bytes) -> GTP_U_Header:
	"""Decode bytes and require a GTP-U packet with a PDU Session Container."""
	packet = GTP_U_Header(data)
	if not isinstance(packet, GTP_U_Header):
		raise ValueError("data is not a GTP-U packet")
	if packet.gtp_type != 255 or packet.E != 1 or packet.next_ex != PDU_SESSION_CONTAINER_TYPE:
		raise ValueError("packet does not contain a PDU Session Container extension")
	return packet


__all__ = [
	"GTPUPDUSessionContainer",
	"GTP_U_Header",
	"PDU_SESSION_CONTAINER_TYPE",
	"build_gtpu_packet",
	"build_gtpu_packet_from_mutation",
	"extract_container_kwargs",
	"decode_gtpu_packet",
]

