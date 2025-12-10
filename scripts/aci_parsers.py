"""
ACI DN (Distinguished Name) parsing utilities.

This module provides regex patterns and helper functions for parsing
Cisco ACI Distinguished Names (DNs) into structured components.
"""

import re
from typing import Dict, Any, Optional
from aci_models import (
    EPGBinding, L3OutBinding, PathInfo, VRFInfo,
    BridgeDomainInfo, SubnetInfo, EndpointInfo
)


# -------------------------------------------------------
#  COMPILED REGEX PATTERNS (compiled once, reused everywhere)
# -------------------------------------------------------

# ACI Object DNs
RE_VRF = re.compile(r"uni/tn-(?P<tenant>[^/]+)/ctx-(?P<vrf>[^/]+)")
RE_BD = re.compile(r"uni/tn-(?P<tenant>[^/]+)/BD-(?P<bd>[^/]+)")
RE_EPG = re.compile(r"uni/tn-(?P<tenant>[^/]+)/ap-(?P<ap>[^/]+)/epg-(?P<epg>[^/]+)")
RE_EPG_DN = re.compile(r"uni/tn-[^/]+/ap-(?P<ap>[^/]+)/epg-(?P<epg>[^/]+)")
RE_CEP = re.compile(r"uni/tn-(?P<tenant>[^/]+)/ap-(?P<ap>[^/]+)/epg-(?P<epg>[^/]+)/cep-(?P<cep>[^/]+)")

# L3Out DNs
RE_L3OUT = re.compile(r"uni/tn-(?P<tenant>[^/]+)/out-(?P<l3out>[^/]+)")
RE_L3OUT_DN = re.compile(r"uni/tn-[^/]+/out-(?P<l3out>[^/]+)/lnodep-[^/]+/lifp-(?P<lifp>[^/]+)")
RE_L3OUT_PATH = re.compile(r"uni/tn-(?P<tenant>[^/]+)/out-(?P<out>[^/]+)/lnodep-[^/]+/lifp-(?P<lifp>[^/]+)")

# Topology and Infrastructure
RE_PATH_TDN = re.compile(r"topology/pod-(?P<pod>\d+)/(?:prot)?paths-(?P<node>\d+(?:-\d+)?)/pathep-\[(?P<iface>[^\]]+)\]")
RE_AAEP_TDN = re.compile(r"attentp-([^\]]+)$")
RE_VLAN_POOL_TDN = re.compile(r"vlanns-\[(?P<pool>[^\]]+)\]")


def parse_regex(regex: re.Pattern, text: str) -> Optional[Dict[str, Any]]:
    """
    Safe helper to parse text using a compiled regex pattern.

    Args:
        regex: Compiled regex pattern
        text: Text to parse

    Returns:
        Dictionary of named groups if match found, None otherwise
    """
    m = regex.search(text)
    return m.groupdict() if m else None


def extract_tenant_from_dn(dn: str) -> str:
    """
    Extract tenant name from a DN.

    Args:
        dn: Distinguished Name string

    Returns:
        Tenant name or "unknown" if not found
    """
    parts = dn.split("/")
    if len(parts) >= 2 and parts[1].startswith("tn-"):
        return parts[1][3:]
    return "unknown"


def format_epg_label(dn: str) -> str:
    """
    Create a friendly label for EPG or L3Out DNs.

    Normal EPG:
        uni/tn-T/ap-App/epg-EPG -> EPG: App/EPG

    L3Out InstP:
        uni/tn-T/out-EXT1/instP-EPG -> L3: EXT1/EPG

    Args:
        dn: Distinguished Name string

    Returns:
        Formatted label string
    """
    # Normal EPG format
    if "/ap-" in dn and "/epg-" in dn:
        ap = dn.split("/ap-")[1].split("/")[0]
        epg = dn.split("/epg-")[1].split("/")[0]
        return f"EPG: {ap}/{epg}"

    # L3Out InstP
    if "/out-" in dn and "/instP-" in dn:
        out = dn.split("/out-")[1].split("/")[0]
        epg = dn.split("/instP-")[1].split("/")[0]
        return f"L3: {out}/{epg}"

    # Fallback
    last = dn.split("/")[-1]
    if last.startswith(("rsprov-", "rscons-")):
        return last.split("-", 1)[-1]
    return last


# -------------------------------------------------------
# Dataclass Factory Functions
# -------------------------------------------------------

def parse_epg_binding(dn: str, encap: str) -> Optional[EPGBinding]:
    """
    Parse EPG binding from DN and encap.

    Args:
        dn: Distinguished Name (e.g., uni/tn-T/ap-A/epg-E/...)
        encap: Encapsulation (e.g., vlan-100)

    Returns:
        EPGBinding instance or None if parse fails
    """
    match = parse_regex(RE_EPG, dn)
    if match:
        return EPGBinding(
            tenant=match["tenant"],
            app_profile=match["ap"],
            epg=match["epg"],
            encap=encap
        )
    return None


def parse_l3out_binding(dn: str, encap: str) -> Optional[L3OutBinding]:
    """
    Parse L3Out binding from DN and encap.

    Args:
        dn: Distinguished Name (e.g., uni/tn-T/out-O/lnodep-.../lifp-I)
        encap: Encapsulation (e.g., vlan-100)

    Returns:
        L3OutBinding instance or None if parse fails
    """
    match = parse_regex(RE_L3OUT_PATH, dn)
    if match:
        return L3OutBinding(
            tenant=match["tenant"],
            l3out=match["out"],
            interface=match["lifp"],
            encap=encap
        )
    return None


def parse_path_info(tdn: str) -> Optional[PathInfo]:
    """
    Parse physical path from topology DN.

    Args:
        tdn: Topology DN (e.g., topology/pod-1/paths-201/pathep-[eth1/1])

    Returns:
        PathInfo instance or None if parse fails
    """
    match = parse_regex(RE_PATH_TDN, tdn)
    if match:
        return PathInfo(
            pod=match["pod"],
            node=match["node"],
            interface=match["iface"]
        )
    return None


def parse_vrf_info(dn: str) -> Optional[VRFInfo]:
    """
    Parse VRF from DN.

    Args:
        dn: Distinguished Name (e.g., uni/tn-T/ctx-V)

    Returns:
        VRFInfo instance or None if parse fails
    """
    match = parse_regex(RE_VRF, dn)
    if match:
        return VRFInfo(
            tenant=match["tenant"],
            vrf=match["vrf"]
        )
    return None


def parse_bd_info(dn: str) -> Optional[BridgeDomainInfo]:
    """
    Parse Bridge Domain from DN.

    Args:
        dn: Distinguished Name (e.g., uni/tn-T/BD-B)

    Returns:
        BridgeDomainInfo instance or None if parse fails
    """
    match = parse_regex(RE_BD, dn)
    if match:
        return BridgeDomainInfo(
            tenant=match["tenant"],
            bd=match["bd"]
        )
    return None


def parse_subnet_info(dn: str, cidr: str, parent_type: str) -> Optional[SubnetInfo]:
    """
    Parse subnet info from DN and CIDR.

    Args:
        dn: Distinguished Name
        cidr: CIDR notation (e.g., 10.0.0.0/24)
        parent_type: "BD" or "L3Out"

    Returns:
        SubnetInfo instance or None if parse fails
    """
    tenant = extract_tenant_from_dn(dn)

    if parent_type == "BD":
        match = parse_regex(RE_BD, dn)
        if match:
            return SubnetInfo(
                tenant=tenant,
                cidr=cidr,
                parent=match["bd"],
                parent_type="BD"
            )
    elif parent_type == "L3Out":
        match = parse_regex(RE_L3OUT, dn)
        if match:
            return SubnetInfo(
                tenant=tenant,
                cidr=cidr,
                parent=match["l3out"],
                parent_type="L3Out"
            )

    return None


def parse_endpoint_info(dn: str, ip: Optional[str] = None, mac: Optional[str] = None,
                       encap: Optional[str] = None, fabric_path: Optional[str] = None) -> Optional[EndpointInfo]:
    """
    Parse endpoint information from DN and attributes.

    Args:
        dn: Distinguished Name (e.g., uni/tn-T/ap-A/epg-E/cep-MAC)
        ip: IP address
        mac: MAC address
        encap: Encapsulation
        fabric_path: Fabric path DN

    Returns:
        EndpointInfo instance or None if parse fails
    """
    match = parse_regex(RE_CEP, dn)
    if match:
        return EndpointInfo(
            tenant=match["tenant"],
            app_profile=match["ap"],
            epg=match["epg"],
            ip=ip,
            mac=mac or match.get("cep"),
            encap=encap,
            fabric_path=fabric_path
        )
    return None
