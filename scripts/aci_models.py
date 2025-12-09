"""
Data models for ACI objects.

These dataclasses provide structured representations of ACI entities
and bindings for type safety and clarity.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class EPGBinding:
    """Represents an EPG (Endpoint Group) binding."""
    tenant: str
    app_profile: str
    epg: str
    encap: str

    def __str__(self) -> str:
        return f"{self.tenant}/{self.app_profile}/{self.epg} ({self.encap})"


@dataclass
class L3OutBinding:
    """Represents an L3Out interface binding."""
    tenant: str
    l3out: str
    interface: str
    encap: str

    def __str__(self) -> str:
        return f"{self.tenant}/{self.l3out}/{self.interface} ({self.encap})"


@dataclass
class PathInfo:
    """Represents a fabric path (physical port or VPC)."""
    pod: str
    node: str
    interface: str

    def __str__(self) -> str:
        return f"Pod-{self.pod}/Node-{self.node}/{self.interface}"


@dataclass
class VRFInfo:
    """Represents a VRF (Virtual Routing and Forwarding) context."""
    tenant: str
    vrf: str

    def __str__(self) -> str:
        return f"{self.tenant}/ctx-{self.vrf}"


@dataclass
class BridgeDomainInfo:
    """Represents a Bridge Domain."""
    tenant: str
    bd: str

    def __str__(self) -> str:
        return f"{self.tenant}/BD-{self.bd}"


@dataclass
class SubnetInfo:
    """Represents a subnet in ACI."""
    tenant: str
    cidr: str
    parent: str  # BD name or L3Out name
    parent_type: str  # "BD" or "L3Out"

    def __str__(self) -> str:
        return f"{self.tenant}/{self.parent_type}:{self.parent} - {self.cidr}"


@dataclass
class ContractInfo:
    """Represents a contract with its scope."""
    tenant: str
    name: str
    scope: str  # "local", "global", "tenant", "application-profile"
    dn: str

    def __str__(self) -> str:
        return f"{self.tenant}/brc-{self.name} (scope: {self.scope})"


@dataclass
class EPGContractRelation:
    """Represents an EPG's relationship to a contract."""
    epg_label: str
    tenant: str
    is_imported: bool
    is_provider: bool  # True = provider, False = consumer

    def __str__(self) -> str:
        role = "provides" if self.is_provider else "consumes"
        imported = " (imported)" if self.is_imported else ""
        return f"{self.epg_label} {role}{imported}"


@dataclass
class VLANPoolRange:
    """Represents a VLAN pool range."""
    pool_name: str
    pool_dn: str
    from_vlan: int
    to_vlan: int

    def contains(self, vlan_id: int) -> bool:
        """Check if this range contains the given VLAN ID."""
        return self.from_vlan <= vlan_id <= self.to_vlan

    def __str__(self) -> str:
        return f"{self.pool_name} (range: {self.from_vlan}–{self.to_vlan})"


@dataclass
class NodeInfo:
    """Represents a fabric node."""
    node_id: str
    node_name: str
    pod_id: Optional[str] = None
    fabric_state: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.node_name} [{self.node_id}]"


@dataclass
class EndpointInfo:
    """Represents a discovered endpoint (MAC/IP)."""
    tenant: str
    app_profile: str
    epg: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    encap: Optional[str] = None
    fabric_path: Optional[str] = None

    def __str__(self) -> str:
        addr = self.ip or self.mac or "unknown"
        return f"{addr} in {self.tenant}/{self.app_profile}/{self.epg}"
