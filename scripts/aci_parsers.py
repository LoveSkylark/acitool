"""
ACI DN (Distinguished Name) parsing utilities.

This module provides regex patterns and helper functions for parsing
Cisco ACI Distinguished Names (DNs) into structured components.
"""

import re
from typing import Dict, Any, Optional


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
