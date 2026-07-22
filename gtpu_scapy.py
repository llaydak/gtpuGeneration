"""Scapy helpers for building GTP-U packets with a PDU Session Container.

Scapy already provides the TS 38.415 PDU Session Container model in
``scapy.contrib.gtp``.  This module keeps that model as the source of truth
and adds validation plus a small builder for the GTP-U header chain.
"""

from __future__ import annotations

from typing import Any, Optional

from scapy.contrib.gtp import GTPPDUSessionContainer, GTP_U_Header
from scapy.packet import Packet, Raw


PDU_SESSION_CONTAINER_TYPE = 0x85
GTPU_PORT = 2152


class GTPUPDUSessionContainer(GTPPDUSessionContainer):
	"""Project-facing name for Scapy's PDU Session Container implementation."""

	name = "GTP-U PDU Session Container"


def build_gtpu_packet(
	teid: int,
	*,
	pdu_type: int = 1,
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
	if pdu_type not in (0, 1):
		raise ValueError("pdu_type must be 0 (DL) or 1 (UL)")
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
	"decode_gtpu_packet",
]
