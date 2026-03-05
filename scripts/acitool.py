#!/usr/bin/env python3

import os
import re
import sys
import datetime
import logging
import getpass
import argparse
import requests
import urllib3
from dotenv import load_dotenv
from functools import lru_cache
from ipaddress import ip_address, ip_network
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Dict, List, Optional, Tuple, Set, Any

# Import local modules
from config import (
    API_NODE_CLASS, API_CLASS, EXCLUDED_CIDRS, ROUTE_EXCLUDED_PROTOS,
    RETRY_TOTAL, RETRY_BACKOFF_FACTOR, RETRY_STATUS_FORCELIST, RETRY_ALLOWED_METHODS,
    API_CACHE_SIZE, NODE_INVENTORY_CACHE_SIZE
)
from aci_parsers import (
    RE_VRF, RE_BD, RE_EPG, RE_EPG_DN,
    RE_L3OUT, RE_L3OUT_DN, RE_L3OUT_PATH,
    RE_PATH_TDN, RE_AAEP_TDN, RE_VLAN_POOL_TDN,
    parse_regex, extract_tenant_from_dn, format_epg_label,
    parse_epg_binding, parse_l3out_binding, parse_path_info,
    parse_vrf_info, parse_bd_info, parse_subnet_info, parse_endpoint_info
)
from aci_tree import ACITreeBuilder
from aci_models import VLANPoolRange

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Add a file handler so errors are written to disk without appearing on the terminal
_log_file = os.path.expanduser("~/.aci_tool.log")
_file_handler = logging.FileHandler(_log_file)
_file_handler.setLevel(logging.ERROR)
_file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
logger.addHandler(_file_handler)

# -------------------------------
# Argument Parsing
# -------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Script to look up IP, port, VLAN, or tenant bindings inside ACI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ip_parser = subparsers.add_parser("ip", help="Search by IP address or prefix")
    ip_parser.add_argument("ip", help="Full IP address (e.g., 10.5.1.1) or string prefix (e.g., 10.5.1)")
    ip_parser.add_argument("-p", "--prefix", default=None, help="Filter results by subnet mask length (e.g., /24, /32)")
    ip_parser.add_argument("-t", "--tenant", default=None, help="Limit search to a single tenant (e.g., myTenant)")

    port_parser = subparsers.add_parser("port", help="Search by physical port")
    port_parser.add_argument("port", help="Physical port (e.g., 1/1)")
    port_parser.add_argument("-i", "--id", help="Node ID (e.g., 203)")
    port_parser.add_argument("-n", "--name", help="Node name (e.g., leaf203)")

    vlan_parser = subparsers.add_parser("vlan", help="Search by VLAN")
    vlan_parser.add_argument("vlan", help="VLAN ID")

    tenant_parser = subparsers.add_parser("tenant", help="List static and SVI bindings for a tenant")
    tenant_parser.add_argument("tenant", help="Tenant name")

    vpc_parser = subparsers.add_parser("vpc", help="Search by VPC interface")
    vpc_parser.add_argument("nodes", help="VPC node pair (e.g., 221-222)")
    vpc_parser.add_argument("interface", help="VPC interface name (e.g., VPC-CUST-A01)", nargs="?", default=None)

    clean_parser = subparsers.add_parser("clean", help="Show unused VRFs or BDs")
    clean_sub = clean_parser.add_subparsers(dest="clean_cmd", required=True)
    clean_sub.add_parser("aaep", help="List AAEPs not assigned to any interface or static path")
    clean_sub.add_parser("vlan", help="List VLAN pools not used by any Domain or AAEP")
    clean_sub.add_parser("vrf", help="List VRFs with no BD or L3Out attached")
    clean_sub.add_parser("bd",  help="List BDs with no EPG or L3Out attached")
    clean_sub.add_parser("epg", help="List EPGs without contracts, members, or static bindings")
    clean_sub.add_parser("empty", help="List EPGs with no MAC, IP addresses, or static bindings")
    clean_sub.add_parser("contract", help="List contracts with no provider/consumer or only one side assigned")
    clean_sub.add_parser("subnet", help="List all subnets in the fabric")
    clean_filter_parser = clean_sub.add_parser("filter", help="List filters not attached to any contract subject")
    clean_filter_parser.add_argument("-t", "--tenant", default=None, help="Limit to a single tenant")

    contract_parser = subparsers.add_parser("contract", help="Contract lookup")
    contract_parser.add_argument("contract", help="Contract name")
    contract_parser.add_argument("-t", "--tenant", help="Only search inside this tenant")
    contract_parser.add_argument("-f", "--filters", action="store_true", default=False, help="Show only filter entries (requires --tenant)")

    subnet_parser = subparsers.add_parser("subnet", help="List all subnets in use in the ACI fabric")
    subnet_parser.add_argument("filter", nargs="?", default=None, help="Filter by IP prefix string (e.g., 10.5.1) or CIDR containment (e.g., 10.1.0.0/16)")
    subnet_parser.add_argument("-t", "--tenant", help="Filter by tenant name", default=None)
    subnet_parser.add_argument("-p", "--prefix", help="Filter by subnet mask (e.g., /24, /30)", default=None)

    aaep_parser = subparsers.add_parser("aaep", help="List Attachable Access Entity Profiles or show connection map")
    aaep_parser.add_argument("name", nargs="?", default=None, help="Optional AAEP name to show connection map")
    aaep_parser.add_argument("-l", "--list-endpoints", nargs="?", const=True, default=False, help="List all MAC/IP addresses connected to the AAEP, optionally filter by EPG path (e.g., Tenant/App/EPG)")

    route_parser = subparsers.add_parser("route", help="Show consolidated routing table for a VRF across all leaf nodes")
    route_parser.add_argument("vrf", help="VRF to look up in <tenant>:<vrf> format (e.g., myTenant:myVRF)")
    route_parser.add_argument("filter", nargs="?", default=None, help="Filter routes by prefix string (e.g., 172.16.0) or CIDR subnet containment (e.g., 10.0.0.0/8)")
    route_parser.add_argument("-p", "--prefix", default=None, help="Filter by subnet mask length (e.g., /24, /32)")
    route_scope = route_parser.add_mutually_exclusive_group()
    route_scope.add_argument("-l", "--local", action="store_true", default=False, help="Show only routes native to this VRF (exclude imported/leaked routes)")
    route_scope.add_argument("-x", "--external", action="store_true", default=False, help="Show only routes imported from other VRFs/tenants via contracts")
    route_parser.add_argument("-d", "--detail", action="store_true", default=False, help="Include direct, local, am and broadcast routes")

    return parser.parse_args()

# -------------------------------
# ACI Client Class
# -------------------------------

class ACIClient:
    def __init__(self, apic_url: str, token_file: str = "~/.aci_token", verify_ssl: bool = False) -> None:
        self.apic_url = apic_url
        self.session = requests.Session()
        self.token_file = os.path.expanduser(token_file)
        self.token = self.load_token_from_file()
        self.verify_ssl = verify_ssl

        # Configure retry strategy for resilient HTTP requests
        retry_strategy = Retry(
            total=RETRY_TOTAL,
            backoff_factor=RETRY_BACKOFF_FACTOR,
            status_forcelist=RETRY_STATUS_FORCELIST,
            allowed_methods=RETRY_ALLOWED_METHODS
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Disable SSL warnings only if verification is disabled
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @lru_cache(maxsize=API_CACHE_SIZE)
    def query_api(self, endpoint: str, filter_str: str = "") -> list:
        """Unified cached API query. Passes filter_str as query-target-filter via URL encoding."""
        params = {"query-target-filter": filter_str} if filter_str else None
        try:
            response = self.session.get(
                f"{self.apic_url}{endpoint}",
                params=params,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            return response.json().get("imdata", [])
        except requests.RequestException as e:
            logger.error(f"API request failed: {e}")
            return []

    @lru_cache(maxsize=1)
    def get_tep_pool(self):
        """Return the fabric infrastructure TEP pool as an ip_network, or None."""
        data = self.query_api("/api/node/mo/uni/infra/settings.json")
        for item in data:
            tep = item.get("infraSetPol", {}).get("attributes", {}).get("tepPool", "")
            if tep:
                try:
                    return ip_network(tep, strict=False)
                except ValueError:
                    pass
        return None

    def load_token_from_file(self):
        if os.path.exists(self.token_file):
            with open(self.token_file, "r") as f:
                return f.read().strip()
        return None

    def save_token_to_file(self):
        dir_path = os.path.dirname(self.token_file)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(self.token_file, "w") as f:
            f.write(self.token)

    def is_token_valid(self):
        if not self.token:
            return False
        self.session.cookies["APIC-cookie"] = self.token
        try:
            r = self.session.get(f"{self.apic_url}/api/node/mo/uni.json", verify=self.verify_ssl)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def prompt_credentials(self):
        return input("Username: "), getpass.getpass("Password: ")

    def login(self):
        if self.token and self.is_token_valid():
            return

        # Try environment variables first, then prompt
        username = os.environ.get('APIC_USERNAME')
        password = os.environ.get('APIC_PASSWORD')

        # Filter out empty strings and None values
        if not username or not username.strip():
            username = None
        if not password or not password.strip():
            password = None

        if not username or not password:
            username, password = self.prompt_credentials()

        for attempt in range(2):
            payload = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}
            try:
                response = self.session.post(f"{self.apic_url}/api/aaaLogin.json", json=payload, verify=self.verify_ssl)
                response.raise_for_status()
                json_data = response.json()
                self.token = json_data["imdata"][0]["aaaLogin"]["attributes"]["token"]
                self.session.cookies["APIC-cookie"] = self.token
                self.save_token_to_file()
                return
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    # Write directly to log file — bypass logger to avoid printing to terminal
                    with open(_log_file, "a") as _lf:
                        _lf.write(f"{datetime.datetime.now()} ERROR: Login attempt {attempt + 1} failed (401): {e}\n")
                    if attempt == 0:
                        username, password = self.prompt_credentials()
                        continue
                    print("Login failed: invalid credentials.")
                    exit(1)
                logger.error(f"Login failed: {e}")
                print(f"Login failed: {e}")
                exit(1)
            except requests.RequestException as e:
                logger.error(f"Login failed: {e}")
                print(f"Login failed: {e}")
                exit(1)
            except (KeyError, IndexError, TypeError) as e:
                logger.error(f"Unexpected login response format: {e}")
                print(f"Unexpected login response format: {e}")
                exit(1)

    def ip_in_cidr(self, ip, cidr):
        try:
            return ip_address(ip) in ip_network(cidr, strict=False)
        except ValueError:
            return False

    def get_pod_for_node(self, data, node_id=None, node_name=None):
        for item in data:
            attr = item.get("topSystem", {}).get("attributes", {})
            if node_id and attr.get("id") == str(node_id):
                return attr.get("podId"), node_id
            if node_name and attr.get("name") == node_name:
                return attr.get("podId"), attr.get("id")

        id_or_name = node_id if node_id else node_name
        logger.warning(f"Could not find pod ID for node '{id_or_name}'")
        return None

    def process_endpoint(self, data, tenant_filter=None):
        found = False
        for item in data:
            attr = item.get("fvIp", {}).get("attributes", {})
            addr = attr.get("addr", "")
            dn = attr.get("dn", "")
            fabric_path = attr.get("fabricPathDn", "")

            endpoint = parse_endpoint_info(dn, ip=addr, fabric_path=fabric_path)
            path = parse_path_info(fabric_path)

            if endpoint and path:
                if tenant_filter and endpoint.tenant != tenant_filter:
                    continue
                print(f"IP found in:")
                print(f"  {endpoint.tenant}\n    AP:{endpoint.app_profile}\n      {endpoint.epg}\n")
                print(f"  Physical location: Pod-{path.pod}, Node-{path.node} MAC:[{endpoint.mac}]")
                print(f"  Interface Selector: {path.interface}")
                found = True

        return found

    def process_subnet(self, data, ip, prefix_mode=False, prefix_filter=None, tenant_filter=None):
        tree = {}
        for item in data:
            attr = item.get("fvSubnet", {}).get("attributes", {})
            cidr = attr.get("ip", "")
            if cidr in EXCLUDED_CIDRS:
                continue
            if prefix_mode:
                if not cidr.startswith(ip):
                    continue
            elif not self.ip_in_cidr(ip, cidr):
                continue
            if prefix_filter:
                try:
                    if ip_network(cidr, strict=False).prefixlen != int(prefix_filter.lstrip("/")):
                        continue
                except ValueError:
                    continue

            dn = attr.get("dn", "")

            # BD subnet
            info = parse_subnet_info(dn, cidr, "BD")
            if info:
                if tenant_filter and info.tenant != tenant_filter:
                    continue
                leaf_list = tree.setdefault(info.tenant, {}).setdefault("BD:", {}).setdefault("_leaf", [])
                label = f"{info.parent} - {cidr}"
                if label not in leaf_list:
                    leaf_list.append(label)
                continue

            # EPG subnet
            match = parse_regex(RE_EPG, dn)
            if match:
                if tenant_filter and match["tenant"] != tenant_filter:
                    continue
                node = tree.setdefault(match["tenant"], {}).setdefault("AP:", {}).setdefault(match["ap"], {})
                leaf_list = node.setdefault("_leaf", [])
                label = f"{match['epg']} - {cidr}"
                if label not in leaf_list:
                    leaf_list.append(label)

        if tree:
            self.print_tree(tree, label="IP not found, possible Subnet:")

    def process_external_subnet(self, data, ip, prefix_mode=False, prefix_filter=None, tenant_filter=None):
        tree = {}

        for item in data:
            attr = item.get("l3extSubnet", {}).get("attributes", {})
            cidr = attr.get("ip", "")
            if cidr in EXCLUDED_CIDRS:
                continue
            if prefix_mode:
                if not cidr.startswith(ip):
                    continue
            elif not self.ip_in_cidr(ip, cidr):
                continue
            if prefix_filter:
                try:
                    if ip_network(cidr, strict=False).prefixlen != int(prefix_filter.lstrip("/")):
                        continue
                except ValueError:
                    continue

            dn = attr.get("dn", "")
            l3out_match = parse_regex(RE_L3OUT, dn)
            if not l3out_match:
                continue

            if tenant_filter and l3out_match["tenant"] != tenant_filter:
                continue

            instp_match = re.search(r"/instP-([^/]+)/", dn)
            network = instp_match.group(1) if instp_match else cidr

            node = tree.setdefault(l3out_match["tenant"], {}).setdefault(f"L3Out: {l3out_match['l3out']}", {})
            leaf_list = node.setdefault("_leaf", [])
            label = f"{network} - {cidr}"
            if label not in leaf_list:
                leaf_list.append(label)

        if tree:
            self.print_tree(tree, label="Possible L3out:")

    def process_peer(self, data, ip_to_lookup, kind, tenant_filter=None):
        tree = {}
        for item in data:
            attr = item.get(kind, {}).get("attributes", {})
            addr = attr.get("addr") or attr.get("id")

            if not self.ip_in_cidr(ip_to_lookup, addr):
                continue

            dn = attr.get("dn", "")
            if kind == "l3extIp":
                match = parse_regex(RE_L3OUT_PATH, dn)
                if match:
                    if tenant_filter and match["tenant"] != tenant_filter:
                        continue
                    node = tree.setdefault(match["tenant"], {}).setdefault(f"L3Out: {match['out']}", {})
                    leaf_list = node.setdefault("_leaf", [])
                    label = f"{match['lifp']} - {addr}"
                    if label not in leaf_list:
                        leaf_list.append(label)

            elif kind == "bgpPeer":
                match = re.search(r"pod-([^/]+)/node-([^/]+)/.*?/dom-([^:/]+)", dn)
                if match:
                    _, _, tenant = match.groups()
                    if tenant_filter and tenant != tenant_filter:
                        continue
                    node = tree.setdefault(tenant, {}).setdefault("BGP Peers:", {})
                    leaf_list = node.setdefault("_leaf", [])
                    label = f"Peer IP: {addr}"
                    if label not in leaf_list:
                        leaf_list.append(label)

        if tree:
            label = f"Matching {'OSPF' if kind == 'l3extIp' else 'BGP'} Peers:"
            self.print_tree(tree, label=label)
            return True
        return False

    def process_static_route(self, data, ip_to_lookup, tenant_filter=None):
        tree = {}

        for item in data:
            attr = item.get("ipRouteP", {}).get("attributes", {})
            prefix = attr.get("ip", "")
            if prefix in EXCLUDED_CIDRS or not self.ip_in_cidr(ip_to_lookup, prefix):
                continue

            match = re.search(r"uni/tn-([^/]+)/out-([^/]+)/instP-([^/]+)", attr.get("dn", ""))
            if match:
                tenant, l3out, instP = match.groups()
                if tenant_filter and tenant != tenant_filter:
                    continue
                node = tree.setdefault(tenant, {}).setdefault(f"L3Out: {l3out}", {})
                leaf_list = node.setdefault("_leaf", [])
                label = f"{instP} - {prefix}"
                if label not in leaf_list:
                    leaf_list.append(label)

        if tree:
            self.print_tree(tree, label="Matching Static Routes:")
            return True
        return False

    def find_vlan_in_vlan_pools(self, pools, vlan_id) -> List[VLANPoolRange]:
        """
        Check which VLAN pools contain the specified VLAN ID.
        Returns a list of VLANPoolRange objects.
        """
        results = []

        for pool in pools:
            pool_attrs = pool["fvnsVlanInstP"]["attributes"]
            pool_dn = pool_attrs["dn"]
            pool_name = pool_attrs["name"]

            # Fetch all encap blocks for this pool
            blocks = self.query_api(
                f"/api/mo/{pool_dn}.json?query-target=children&target-subtree-class=fvnsEncapBlk"
            )

            for blk in blocks:
                blk_attrs = blk["fvnsEncapBlk"]["attributes"]
                try:
                    from_vlan = int(blk_attrs["from"].split("vlan-")[1])
                    to_vlan = int(blk_attrs["to"].split("vlan-")[1])
                except (IndexError, ValueError, KeyError):
                    continue  # skip malformed entries

                if from_vlan <= vlan_id <= to_vlan:
                    pool_range = VLANPoolRange(
                        pool_name=pool_name,
                        pool_dn=blk_attrs["dn"],
                        from_vlan=from_vlan,
                        to_vlan=to_vlan
                    )
                    results.append(pool_range)

        return results

    def tree_add(self, tree, *levels, label):
        if not levels:
            raise ValueError("At least one level must be provided")

        *path_levels, last_level = levels
        node = tree
        for level in path_levels:
            node = node.setdefault(level, {})

        node = node.setdefault(last_level, {})

        parts = label.split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})

        leaf = parts[-1]
        leaf_list = node.setdefault('_leaf', [])
        if leaf not in leaf_list:   # only add if not already present
            leaf_list.append(leaf)

    def collect_epgs(self, epg_items, rel_key):
        epg_map = {}

        for item in epg_items:
            attr = item[rel_key]["attributes"]
            tDn = attr.get("tDn", "")
            dn  = attr.get("dn", "")

            # Only select entries that point to our contract
            matching_dn = next((c_dn for c_dn in self.contract_dn_map if c_dn in tDn), None)
            if not matching_dn:
                continue

            tenant = self.epg_tenant(dn)

            # Scope determines whether imported or local
            scope = self.contract_dn_map[matching_dn].get("scope", "local")
            is_imported = (scope == "imported")

            
            label = self.epg_label(dn)

            # Store as tuple: (label, is_imported)
            epg_map.setdefault(tenant, set()).add((label, is_imported))

        # Convert sets to sorted list of tuples
        return {
            tenant: sorted(list(epgs), key=lambda x: x[0]) 
            for tenant, epgs in epg_map.items()
        }

    def epg_tenant(self, dn):
        """Extract tenant from EPG or L3Out DN."""
        parts = dn.split("/")
        if len(parts) >= 2 and parts[1].startswith("tn-"):
            return parts[1][3:]
        return "unknown"

    def epg_label(self, dn):
        """
        Friendly name for both normal EPGs and L3Out EPGs.

        Normal EPG:
            uni/tn-T/ap-App/epg-EPG       -> App/EPG

        L3Out InstP:
            uni/tn-T/out-EXT1/l3extInstP-EPG -> EXT1/EPG
        """
        # Normal EPG format
        if "/ap-" in dn and "/epg-" in dn:
            ap  = dn.split("/ap-")[1].split("/")[0]
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

    def list_all_subnets(self, tenant_filter=None, prefix_filter=None, ip_filter=None):
        """
        List all subnets in use in the ACI fabric (BD + L3Out), optionally filter by tenant, subnet mask, or IP.
        ip_filter: string prefix (e.g., "10.5.1") or CIDR containment (e.g., "10.1.0.0/16")
        """
        tree = {}

        # Parse ip_filter — string prefix match or CIDR containment
        filter_prefix = None
        filter_network = None
        if ip_filter:
            if "/" in ip_filter:
                try:
                    filter_network = ip_network(ip_filter, strict=False)
                except ValueError as e:
                    print(f"Error: Invalid CIDR format '{ip_filter}': {e}")
                    return
            else:
                filter_prefix = ip_filter

        def subnet_matches(ip_cidr):
            """Check if subnet matches the active ip_filter and prefix_filter."""
            try:
                net = ip_network(ip_cidr, strict=False)

                if filter_prefix and not ip_cidr.startswith(filter_prefix):
                    return False

                if prefix_filter and net.prefixlen != int(prefix_filter.lstrip("/")):
                    return False

                if filter_network:
                    if net.version != filter_network.version:
                        return False
                    if not net.subnet_of(filter_network):
                        return False

                return True
            except (ValueError, TypeError):
                return False

        # -----------------------
        # 1. BD / SVI Subnets
        # -----------------------
        bd_subnets = self.query_api("/api/node/class/fvSubnet.json")
        for item in bd_subnets:
            attr = item.get("fvSubnet", {}).get("attributes", {})
            dn = attr.get("dn", "")
            ip = attr.get("ip", "")

            if ip in EXCLUDED_CIDRS:
                continue

            match = parse_regex(RE_BD, dn)
            if not match:
                continue

            tenant = match["tenant"]
            bd = match["bd"]

            if tenant_filter and tenant != tenant_filter:
                continue

            if not subnet_matches(ip):
                continue

            tree.setdefault(tenant, {}).setdefault("BD Subnets:", []).append(f"{bd} - {ip}")

        # -----------------------
        # 2. L3Out Subnets
        # -----------------------
        l3out_subnets = self.query_api("/api/node/class/l3extSubnet.json")
        for item in l3out_subnets:
            attr = item.get("l3extSubnet", {}).get("attributes", {})
            dn = attr.get("dn", "")
            ip = attr.get("ip", "")

            if ip in EXCLUDED_CIDRS:
                continue

            match = parse_regex(RE_L3OUT, dn)
            if not match:
                continue

            tenant = match["tenant"]
            l3out = match["l3out"]

            if tenant_filter and tenant != tenant_filter:
                continue

            if not subnet_matches(ip):
                continue

            tree.setdefault(tenant, {}).setdefault("L3Out Subnets:", []).append(f"{l3out} - {ip}")

        # -----------------------
        # Print result
        # -----------------------
        if tree:
            filters = []
            if filter_prefix:
                filters.append(f"starting with {filter_prefix}")
            if filter_network:
                filters.append(f"within {filter_network}")
            if prefix_filter:
                filters.append(f"prefix {prefix_filter}")
            filter_label = f" ({', '.join(filters)})" if filters else ""
            self.print_tree(tree, label=f"ACI Subnets in use (BD + L3Out){filter_label}:")
        else:
            print("[!] No subnets found matching the criteria.")

    @lru_cache(maxsize=NODE_INVENTORY_CACHE_SIZE)
    def get_node_inventory(self):
        """
        Fetch and cache APIC fabric node inventory.
        Returns a dict mapping node_id -> node_name.
        Cached for the entire runtime (lru_cache maxsize=1).
        """
        nodes = self.query_api("/api/node/class/fabricNode.json")
        node_map = {}

        for item in nodes:
            attr = item.get("fabricNode", {}).get("attributes", {})
            if attr.get("fabricSt") != "active":
                continue  # skip inactive nodes

            node_id = attr.get("id")
            node_name = attr.get("name")
            node_map[node_id] = node_name

        return node_map

    def normalize_node_label(self, pod, node_string):
        """
        Convert raw node string (e.g., '205' or '209-210') to:
            'leaf3 (205)'
            'Leaf1 & Leaf2 (209-210)'
        based on cached APIC node inventory.
        """
        node_map = self.get_node_inventory()   # cached lookup

        node_ids = node_string.split("-")
        resolved_names = []

        for nid in node_ids:
            name = node_map.get(nid, f"Node{nid}")  # fallback if unknown
            resolved_names.append(name)

        if len(node_ids) == 1:
            return f"{resolved_names[0]} [{node_ids[0]}]"
        else:
            return f"{resolved_names[0]} & {resolved_names[1]} [{node_string}]"


    # =========================================================================
    # Command Handler Methods
    # =========================================================================

    def handle_clean_vrf(self):
        """List VRFs with no BD or L3Out attached."""
        print("Checking VRFs not attached to any BD or L3Out...\n")

        ctxs = self.query_api("/api/node/class/fvCtx.json")
        l3_refs = self.query_api("/api/node/class/l3extRsEctx.json")
        bd_refs = self.query_api("/api/node/class/fvRsCtx.json")

        all_vrfs = {}
        for item in ctxs:
            parsed = parse_regex(RE_VRF, item["fvCtx"]["attributes"]["dn"])
            if parsed:
                all_vrfs.setdefault(parsed["tenant"], set()).add(parsed["vrf"])

        referenced = {}
        for ref_list, regex in [(bd_refs, RE_BD), (l3_refs, RE_L3OUT)]:
            for item in ref_list:
                key = next(iter(item))
                attr = item[key]["attributes"]
                parsed = parse_regex(regex, attr["dn"])
                if parsed and attr.get("tnFvCtxName"):
                    referenced.setdefault(parsed["tenant"], set()).add(attr["tnFvCtxName"])

        tree = {
            tenant: {"vrfs": sorted(vrfs - referenced.get(tenant, set()))}
            for tenant, vrfs in all_vrfs.items()
            if vrfs - referenced.get(tenant, set())
        }

        if tree:
            self.print_tree(tree)
        else:
            print("All VRFs are in use.")

    def handle_clean_bd(self):
        """List BDs with no EPG or L3Out attached."""
        print("Checking Bridge Domains not attached to any EPG or L3Out...\n")

        bds = self.query_api("/api/node/class/fvBD.json")
        epg_bd = self.query_api("/api/node/class/fvRsBd.json")
        l3_sub = self.query_api("/api/node/class/l3extSubnet.json")

        all_bds = {}
        used_bds = set()

        for item in bds:
            parsed = parse_regex(RE_BD, item["fvBD"]["attributes"]["dn"])
            if parsed:
                tenant = parsed["tenant"]
                bd = parsed["bd"]
                all_bds.setdefault(tenant, set()).add(bd)

        for item in epg_bd:
            attr = item["fvRsBd"]["attributes"]
            bd_name = attr.get("tnFvBDName")
            if bd_name:
                used_bds.add(bd_name)

        for item in l3_sub:
            attr = item["l3extSubnet"]["attributes"]
            bd_name = attr.get("tnFvBDName")
            if bd_name:
                used_bds.add(bd_name)

        unused_bds = {
            tenant: sorted(bd_set - used_bds) for tenant, bd_set in all_bds.items()
        }
        unused_bds = {tenant: bds for tenant, bds in unused_bds.items() if bds}

        if unused_bds:
            self.print_tree(unused_bds)
        else:
            print("No unused Bridge Domains found.")

    def handle_clean_epg(self):
        """List EPGs without contracts, members, or static bindings."""
        print("Checking EPGs without any contract, members, or static bindings...\n")

        epgs = self.query_api("/api/node/class/fvAEPg.json")
        prov = self.query_api("/api/node/class/fvRsProv.json")
        cons = self.query_api("/api/node/class/fvRsCons.json")
        macs = self.query_api("/api/node/class/fvMac.json")
        ips = self.query_api("/api/node/class/fvIp.json")
        paths = self.query_api("/api/node/class/fvRsPathAtt.json")

        all_epgs = {}
        for item in epgs:
            parsed = parse_regex(RE_EPG, item["fvAEPg"]["attributes"]["dn"])
            if parsed:
                all_epgs.setdefault(parsed["tenant"], {}).setdefault(parsed["ap"], set()).add(parsed["epg"])

        used = {}
        for ref_list in (prov, cons, macs, ips, paths):
            for item in ref_list:
                key = next(iter(item))
                parsed = parse_regex(RE_EPG, item[key]["attributes"]["dn"])
                if parsed:
                    used.setdefault(parsed["tenant"], {}).setdefault(parsed["ap"], set()).add(parsed["epg"])

        tree = {}
        for tenant, aps in all_epgs.items():
            for ap, epgset in aps.items():
                unused = sorted(epgset - used.get(tenant, {}).get(ap, set()))
                if unused:
                    tree.setdefault(tenant, {}).setdefault(ap, unused)

        if tree:
            self.print_tree(tree)
        else:
            print("All EPGs have contracts, members, or static bindings.")

    def handle_clean_empty(self):
        """List EPGs with no MAC, IP addresses, or static bindings."""
        print("Checking EPGs with no MAC, IP addresses, or static bindings...\n")

        epgs = self.query_api("/api/node/class/fvAEPg.json")
        macs = self.query_api("/api/node/class/fvMac.json")
        ips = self.query_api("/api/node/class/fvIp.json")
        paths = self.query_api("/api/node/class/fvRsPathAtt.json")

        all_epgs = {}
        for item in epgs:
            parsed = parse_regex(RE_EPG, item["fvAEPg"]["attributes"]["dn"])
            if parsed:
                all_epgs.setdefault(parsed["tenant"], {}).setdefault(parsed["ap"], set()).add(parsed["epg"])

        used = {}
        for dataset in (macs, ips, paths):
            for item in dataset:
                key = next(iter(item))
                parsed = parse_regex(RE_EPG, item[key]["attributes"]["dn"])
                if parsed:
                    used.setdefault(parsed["tenant"], {}).setdefault(parsed["ap"], set()).add(parsed["epg"])

        tree = {}
        for tenant, aps in all_epgs.items():
            for ap, epgset in aps.items():
                empty = sorted(epgset - used.get(tenant, {}).get(ap, set()))
                if empty:
                    tree.setdefault(tenant, {}).setdefault(ap, empty)

        if tree:
            self.print_tree(tree)
        else:
            print("All EPGs have MAC, IP addresses, or static bindings.")

    def handle_clean_aaep(self):
        """List AAEPs not assigned anywhere."""
        print("Checking AAEPs not assigned anywhere...\n")

        aaeps = self.query_api("/api/node/class/infraAttEntityP.json")
        aaep_ref = self.query_api("/api/node/class/infraRsAttEntP.json")

        all_aaeps = {item["infraAttEntityP"]["attributes"]["name"] for item in aaeps}
        used = set()

        for item in aaep_ref:
            key = next(iter(item))
            tDn = item[key]["attributes"].get("tDn", "")
            m = RE_AAEP_TDN.search(tDn)
            if m:
                used.add(m.group(1))

        unused = sorted(all_aaeps - used)

        if unused:
            self.print_tree({"Global": {"AAEPs": unused}})
        else:
            print("All AAEPs are assigned somewhere.")

    def handle_clean_vlan(self):
        """List VLAN Pools not used by any Domain or AAEP."""
        print("Checking VLAN Pools not used by any Domain or AAEP...\n")

        pools = self.query_api("/api/node/class/fvnsVlanInstP.json")
        pool_ref = self.query_api("/api/node/class/infraRsVlanNs.json")

        all_pools = {item["fvnsVlanInstP"]["attributes"]["name"] for item in pools}

        used = set()
        for item in pool_ref:
            tDn = item["infraRsVlanNs"]["attributes"].get("tDn", "")
            m = RE_VLAN_POOL_TDN.search(tDn)
            if m:
                used.add(m.group("pool"))

        unused = sorted(all_pools - used)

        if unused:
            self.print_tree({"Global": {"vlan_pools": unused}})
        else:
            print("All VLAN Pools are referenced.")

    def handle_clean_command(self, clean_cmd: str, tenant_filter: str = None):
        """Dispatch to appropriate clean subcommand handler."""
        handlers = {
            "vrf": self.handle_clean_vrf,
            "bd": self.handle_clean_bd,
            "epg": self.handle_clean_epg,
            "empty": self.handle_clean_empty,
            "aaep": self.handle_clean_aaep,
            "vlan": self.handle_clean_vlan,
            "contract": self.handle_clean_contract,
            "subnet": lambda: self.list_all_subnets(),
            "filter": lambda: self.handle_clean_filter(tenant_filter),
        }

        handler = handlers.get(clean_cmd)
        if handler:
            handler()
        else:
            print(f"Unknown clean command: {clean_cmd}")

    def handle_clean_contract(self):
        """List contracts with no provider/consumer or only one side assigned."""
        print("Checking contracts with missing or incomplete assignments...\n")

        # Get all contracts, providers, and consumers (including vzAny)
        contracts = self.query_api("/api/node/class/vzBrCP.json")
        providers = self.query_api("/api/node/class/fvRsProv.json")
        consumers = self.query_api("/api/node/class/fvRsCons.json")
        vzany_providers = self.query_api("/api/node/class/vzRsAnyToProv.json")
        vzany_consumers = self.query_api("/api/node/class/vzRsAnyToCons.json")

        # Build a map of contract usage: tenant/contract -> {has_provider, has_consumer}
        contract_map = {}

        # First, collect all contracts
        for item in contracts:
            attr = item["vzBrCP"]["attributes"]
            contract_name = attr["name"]
            dn = attr["dn"]
            # DN format: uni/tn-TENANT/brc-CONTRACT
            if "/tn-" in dn and "/brc-" in dn:
                tenant = dn.split("/tn-")[1].split("/")[0]
                key = f"{tenant}/{contract_name}"
                contract_map[key] = {"has_provider": False, "has_consumer": False, "tenant": tenant, "contract": contract_name}

        # Mark contracts that have providers (EPG-level)
        for item in providers:
            attr = item["fvRsProv"]["attributes"]
            tDn = attr.get("tDn", "")
            # tDn format: uni/tn-TENANT/brc-CONTRACT
            if tDn and "/tn-" in tDn and "/brc-" in tDn:
                tenant = tDn.split("/tn-")[1].split("/")[0]
                contract_name = tDn.split("/brc-")[1].split("/")[0]
                key = f"{tenant}/{contract_name}"
                if key in contract_map:
                    contract_map[key]["has_provider"] = True

        # Mark contracts that have consumers (EPG-level)
        for item in consumers:
            attr = item["fvRsCons"]["attributes"]
            tDn = attr.get("tDn", "")
            # tDn format: uni/tn-TENANT/brc-CONTRACT
            if tDn and "/tn-" in tDn and "/brc-" in tDn:
                tenant = tDn.split("/tn-")[1].split("/")[0]
                contract_name = tDn.split("/brc-")[1].split("/")[0]
                key = f"{tenant}/{contract_name}"
                if key in contract_map:
                    contract_map[key]["has_consumer"] = True

        # Mark contracts that have providers (vzAny-level)
        for item in vzany_providers:
            attr = item["vzRsAnyToProv"]["attributes"]
            tDn = attr.get("tDn", "")
            # tDn format: uni/tn-TENANT/brc-CONTRACT
            if tDn and "/tn-" in tDn and "/brc-" in tDn:
                tenant = tDn.split("/tn-")[1].split("/")[0]
                contract_name = tDn.split("/brc-")[1].split("/")[0]
                key = f"{tenant}/{contract_name}"
                if key in contract_map:
                    contract_map[key]["has_provider"] = True

        # Mark contracts that have consumers (vzAny-level)
        for item in vzany_consumers:
            attr = item["vzRsAnyToCons"]["attributes"]
            tDn = attr.get("tDn", "")
            # tDn format: uni/tn-TENANT/brc-CONTRACT
            if tDn and "/tn-" in tDn and "/brc-" in tDn:
                tenant = tDn.split("/tn-")[1].split("/")[0]
                contract_name = tDn.split("/brc-")[1].split("/")[0]
                key = f"{tenant}/{contract_name}"
                if key in contract_map:
                    contract_map[key]["has_consumer"] = True

        # Categorize contracts
        no_assignment = {}  # No provider AND no consumer
        only_provider = {}  # Has provider but no consumer
        only_consumer = {}  # Has consumer but no provider

        for key, info in contract_map.items():
            tenant = info["tenant"]
            contract = info["contract"]

            if not info["has_provider"] and not info["has_consumer"]:
                no_assignment.setdefault(tenant, []).append(contract)
            elif info["has_provider"] and not info["has_consumer"]:
                only_provider.setdefault(tenant, []).append(contract)
            elif not info["has_provider"] and info["has_consumer"]:
                only_consumer.setdefault(tenant, []).append(contract)

        # Display results
        found_issues = False

        if no_assignment:
            found_issues = True
            print("=" * 80)
            print("Contracts with NO provider AND NO consumer:")
            print("=" * 80)
            for tenant in sorted(no_assignment.keys()):
                print(f"\n{tenant}:")
                for contract in sorted(no_assignment[tenant]):
                    print(f"  - {contract}")
            print()

        if only_provider:
            found_issues = True
            print("=" * 80)
            print("Contracts with ONLY provider (no consumer):")
            print("=" * 80)
            for tenant in sorted(only_provider.keys()):
                print(f"\n{tenant}:")
                for contract in sorted(only_provider[tenant]):
                    print(f"  - {contract}")
            print()

        if only_consumer:
            found_issues = True
            print("=" * 80)
            print("Contracts with ONLY consumer (no provider):")
            print("=" * 80)
            for tenant in sorted(only_consumer.keys()):
                print(f"\n{tenant}:")
                for contract in sorted(only_consumer[tenant]):
                    print(f"  - {contract}")
            print()

        if not found_issues:
            print("All contracts have both provider and consumer assigned.")

    def handle_clean_filter(self, tenant_filter: str = None):
        """List vzFilters not attached to any contract subject."""
        scope = f" in tenant '{tenant_filter}'" if tenant_filter else ""
        print(f"Checking for unused filters{scope}...\n")

        all_filters = self.query_api("/api/node/class/vzFilter.json")
        rs_subj_filt = self.query_api("/api/node/class/vzRsSubjFiltAtt.json")

        # Build set of all filter DNs that are referenced by at least one subject
        used_filter_dns = set()
        for item in rs_subj_filt:
            attr = item.get("vzRsSubjFiltAtt", {}).get("attributes", {})
            tDn = attr.get("tDn", "")
            if tDn:
                used_filter_dns.add(tDn)

        # Collect unused filters grouped by tenant
        unused: Dict[str, List[str]] = {}
        for item in all_filters:
            attr = item.get("vzFilter", {}).get("attributes", {})
            dn = attr.get("dn", "")
            name = attr.get("name", "")

            if not dn or "/tn-" not in dn or "/flt-" not in dn:
                continue

            tenant = dn.split("/tn-")[1].split("/")[0]

            if tenant_filter and tenant != tenant_filter:
                continue

            if dn not in used_filter_dns:
                unused.setdefault(tenant, []).append(name)

        if not unused:
            print(f"All filters{scope} are attached to at least one contract subject.")
            return

        for tenant in sorted(unused.keys()):
            print(f"{tenant}:")
            for f in sorted(unused[tenant]):
                print(f"  - {f}")
            print()

    def handle_contract_command(self, contract_name: str, tenant_filter: Optional[str] = None, filters_only: bool = False):
        """Find and display contract providers, consumers, and exports."""
        if filters_only:
            if tenant_filter:
                self.handle_filter_command(contract_name, tenant_filter)
            else:
                # Find all tenants that have a contract with this name
                contracts = self.query_api("/api/node/class/vzBrCP.json")
                tenants = sorted(set(
                    item["vzBrCP"]["attributes"]["dn"].split("/tn-")[1].split("/")[0]
                    for item in contracts
                    if item["vzBrCP"]["attributes"]["name"] == contract_name
                    and "/tn-" in item["vzBrCP"]["attributes"]["dn"]
                ))
                if not tenants:
                    print(f"Contract '{contract_name}' not found.")
                    return
                for tenant in tenants:
                    self.handle_filter_command(contract_name, tenant)
            return

        print(f"Looking up contract: {contract_name}\n")

        # Cached API queries
        contracts = self.query_api("/api/node/class/vzBrCP.json")
        prov_epgs = self.query_api("/api/node/class/fvRsProv.json")
        cons_epgs = self.query_api("/api/node/class/fvRsCons.json")

        # Find all tenants that own a contract with this name
        if tenant_filter:
            tenants = [tenant_filter]
        else:
            tenants = []
            for item in contracts:
                attr = item["vzBrCP"]["attributes"]
                if attr["name"] == contract_name:
                    dn = attr["dn"]
                    tenant = dn.split("/")[1][3:]
                    tenants.append(tenant)
            tenants = sorted(set(tenants))

        # If exact contract not found, try prefix match
        if not tenants:
            prefix_tree = {}
            for item in contracts:
                attr = item["vzBrCP"]["attributes"]
                name = attr["name"]
                dn = attr["dn"]
                tenant = dn.split("/")[1][3:]
                if name.startswith(contract_name):
                    prefix_tree.setdefault(tenant, []).append(name)

            if prefix_tree:
                print(f"No exact match for contract '{contract_name}'.\n")
                sorted_tree = {
                    tenant: sorted(names)
                    for tenant, names in sorted(prefix_tree.items())
                }
                self.print_tree(sorted_tree)
                return

            print(f"❌ Contract '{contract_name}' not found.")
            return

        # Run logic once per tenant
        for tenant in tenants:
            print("\n" + "=" * 80)
            print(f"Processing tenant: {tenant}")
            print("=" * 80 + "\n")

            # Build contract DN map for this tenant
            contract_dn_map = {}
            for item in contracts:
                attr = item["vzBrCP"]["attributes"]
                if attr["name"] == contract_name:
                    dn = attr["dn"]
                    t = dn.split("/")[1][3:]
                    if t == tenant:
                        scope = attr.get("scope", "local")
                        contract_dn_map[dn] = {"tenant": t, "scope": scope}

            if not contract_dn_map:
                print(f"  ⚠️ Contract not found in tenant {tenant}")
                continue

            # Store for helper functions
            self.contract_dn_map = contract_dn_map

            # Exported contracts (only for global scope)
            exported_tree = {}
            if scope == "global":
                exported_tree = {"Exported to:": {}}
                dn = list(contract_dn_map.keys())[0]
                exported_contracts = self.query_api(
                    f"/api/mo/{dn}.json?query-target=subtree&target-subtree-class=vzRtIf"
                )
                pattern = re.compile(r"uni/tn-(?P<tenant>[^/]+)/cif-(?P<cif>[^/]+)")
                for item in exported_contracts:
                    vz = item.get("vzRtIf")
                    if vz and "attributes" in vz:
                        match = pattern.match(vz["attributes"].get("tDn", ""))
                        if match:
                            ext_tenant = match.group("tenant")
                            cif = match.group("cif")
                            exported_tree["Exported to:"].setdefault(cif, []).append(ext_tenant)
                for cif in exported_tree["Exported to:"]:
                    exported_tree["Exported to:"][cif].sort()
                exported_tree["Exported to:"] = dict(sorted(exported_tree["Exported to:"].items()))

            # Providers & Consumers
            providers_map = self.collect_epgs(prov_epgs, "fvRsProv")
            consumers_map = self.collect_epgs(cons_epgs, "fvRsCons")

            # Convert to tree format
            provider_tree = {"Providers": {}}
            for t, epgs in providers_map.items():
                for label, imported in epgs:
                    final_label = f"{label}{' (imported)' if imported else ''}"
                    provider_tree["Providers"].setdefault(t, []).append(final_label)

            consumer_tree = {"Consumers": {}}
            for t, epgs in consumers_map.items():
                for label, imported in epgs:
                    final_label = f"{label}{' (imported)' if imported else ''}"
                    consumer_tree["Consumers"].setdefault(t, []).append(final_label)

            # Final Output
            print(f"Type: {scope}\n")
            self.print_tree(provider_tree)
            print()
            self.print_tree(consumer_tree)
            if scope == "global":
                print()
                if exported_tree["Exported to:"]:
                    self.print_tree(exported_tree)

        if tenant_filter:
            self.handle_filter_command(contract_name, tenant_filter)

    def handle_route_command(self, vrf_path: str, detail: bool = False, route_filter: str = None, prefix_filter: str = None, local_only: bool = False, external_only: bool = False):
        """Show consolidated IPv4 routing table for a VRF across all leaf nodes."""
        if ":" not in vrf_path:
            print("Error: Please specify VRF as <tenant>:<vrf> (e.g., myTenant:myVRF)")
            return

        tenant, vrf = vrf_path.split(":", 1)
        vrf_dn = f"uni/tn-{tenant}/ctx-{vrf}"

        # Verify VRF exists
        vrfs = self.query_api("/api/node/class/fvCtx.json")
        if not any(item["fvCtx"]["attributes"]["dn"] == vrf_dn for item in vrfs):
            print(f"VRF '{vrf}' not found in tenant '{tenant}'.")
            return

        # DN format: topology/pod-X/node-Y/sys/uribv4/dom-TENANT:VRF/db-rt/rt-[prefix]
        dom_name = f"{tenant}:{vrf}"

        routes = self.query_api("/api/node/class/uribv4Route.json", f'wcard(uribv4Route.dn,"dom-{dom_name}")')
        nexthops = self.query_api("/api/node/class/uribv4Nexthop.json", f'wcard(uribv4Nexthop.dn,"dom-{dom_name}")')

        if not routes:
            print(f"No routes found for VRF {tenant}:{vrf}")
            return

        # Build nexthop map: route_dn -> list of (owner, addr, nh_vrf)
        # Nexthop DN: .../rt-[prefix]/nh-[owner]-[addr/mask]-[intf]-[vrf]
        nh_map = {}
        for nh_item in nexthops or []:
            nh_attr = nh_item.get("uribv4Nexthop", {}).get("attributes", {})
            nh_dn = nh_attr.get("dn", "")
            route_dn_match = re.search(r'^(.*)/nh-\[', nh_dn)
            if not route_dn_match:
                continue
            route_dn = route_dn_match.group(1)
            owner = nh_attr.get("owner", "")
            addr  = nh_attr.get("addr", "").split("/")[0]  # strip /mask
            # Extract nexthop VRF (last [...] segment of DN)
            nh_vrf_match = re.search(r'\]-\[([^\]]+)\]$', nh_dn)
            nh_vrf = nh_vrf_match.group(1) if nh_vrf_match else ""
            nh_map.setdefault(route_dn, []).append((owner, addr, nh_vrf))

        # Build unified routing table:
        # prefix -> { (owner, addr) -> [(node_id, nh_vrf), ...] }
        route_table = {}
        for route_item in routes:
            attr = route_item.get("uribv4Route", {}).get("attributes", {})
            dn = attr.get("dn", "")

            node_match = re.search(r'/node-(\d+)/', dn)
            if not node_match:
                continue
            node_id = node_match.group(1)

            prefix = attr.get("prefix", "")
            if not prefix:
                continue

            for owner, addr, nh_vrf in nh_map.get(dn, []):
                key = (owner, addr)
                entry = (node_id, nh_vrf)
                route_table.setdefault(prefix, {}).setdefault(key, [])
                if entry not in route_table[prefix][key]:
                    route_table[prefix][key].append(entry)

        if not route_table:
            print(f"No routes found for VRF {tenant}:{vrf}")
            return

        # Sort prefixes by network address
        def sort_prefix(p):
            try:
                return ip_network(p, strict=False)
            except ValueError:
                return ip_network("255.255.255.255/32")

        sorted_prefixes = sorted(route_table.keys(), key=sort_prefix)

        # Apply optional filter
        if route_filter:
            if "/" in route_filter:
                try:
                    filter_net = ip_network(route_filter, strict=False)
                    sorted_prefixes = [
                        p for p in sorted_prefixes
                        if ip_network(p, strict=False).subnet_of(filter_net)
                    ]
                except ValueError:
                    print(f"Invalid CIDR filter: {route_filter}")
                    return
            else:
                sorted_prefixes = [p for p in sorted_prefixes if p.startswith(route_filter)]

        if prefix_filter:
            try:
                target_len = int(prefix_filter.lstrip("/"))
                sorted_prefixes = [
                    p for p in sorted_prefixes
                    if ip_network(p, strict=False).prefixlen == target_len
                ]
            except ValueError:
                print(f"Invalid prefix filter: {prefix_filter}")
                return

        # Print routing table — no Interface column, interface shown as node(intf)
        cp = 22   # prefix col
        co = 14   # owner/proto col
        cn = 16   # next-hop col
        header = f"{'Prefix':<{cp}} {'Proto':<{co}} {'Via':<{cn}} Leafs"
        print(f"Routing table for VRF {tenant}:{vrf}\n")
        print(header)
        print("-" * len(header))

        tep_pool = self.get_tep_pool()

        def _is_leaked(prefix, v):
            """True if this is a legitimate leaked route (all nexthops via overlay-1, not in TEP pool)."""
            if not all(nh_vrf == "overlay-1" for _, nh_vrf in v):
                return False
            if tep_pool is not None:
                try:
                    if ip_network(prefix, strict=False).subnet_of(tep_pool):
                        return False  # TEP pool = infra, not a leaked route
                except (ValueError, TypeError):
                    pass
            return True

        def _is_infra_overlay(prefix, v):
            """True if this is an ACI infrastructure overlay route (TEP pool or local_only mode)."""
            if not all(nh_vrf == "overlay-1" for _, nh_vrf in v):
                return False
            if local_only:
                return True
            if tep_pool is None:
                return False
            try:
                return ip_network(prefix, strict=False).subnet_of(tep_pool)
            except (ValueError, TypeError):
                return False

        all_nodes = set()
        printed = 0
        for prefix in sorted_prefixes:
            nh_groups = route_table[prefix]

            if external_only:
                # Show only leaked routes (overlay-1, not in TEP pool)
                visible = {k: v for k, v in nh_groups.items() if _is_leaked(prefix, v)}
            else:
                visible = {
                    k: v for k, v in nh_groups.items()
                    if (detail or k[0] not in ROUTE_EXCLUDED_PROTOS)
                    and (detail or not _is_infra_overlay(prefix, v))
                }
            if not visible:
                continue

            for node_id, _ in [e for entries in visible.values() for e in entries]:
                all_nodes.add(node_id)

            printed += 1
            for i, ((owner, addr), node_intfs) in enumerate(sorted(visible.items())):
                proto = owner.split("-")[0] if "-" in owner else owner
                via = addr if addr and addr != "0.0.0.0" else "-"
                leafs_str = ", ".join(
                    nid for nid, _ in sorted(node_intfs, key=lambda x: int(x[0]))
                )
                if i == 0:
                    print(f"{prefix:<{cp}} {proto:<{co}} {via:<{cn}} {leafs_str}")
                else:
                    print(f"{'':>{cp}} {proto:<{co}} {via:<{cn}} {leafs_str}")

        print(f"\nTotal: {printed} prefix(es) across {len(all_nodes)} leaf(s): {', '.join(sorted(all_nodes, key=int))}")

    def handle_tenant_command(self, tenant_name: str):
        """List all static and SVI bindings for a tenant."""
        print(f"Looking for all bindings in tenant: {tenant_name}\n")

        static_paths = self.query_api("/api/node/class/fvRsPathAtt.json")
        svi_paths = self.query_api("/api/node/class/l3extRsPathL3OutAtt.json")

        static_tree = {}
        svi_tree = {}
        TENANT_PREFIX = f"uni/tn-{tenant_name}/"

        # Static EPG-to-Path Bindings
        for item in static_paths:
            attr = item.get("fvRsPathAtt", {}).get("attributes", {})
            dn = attr.get("dn", "")

            if not dn.startswith(TENANT_PREFIX):
                continue

            tDn = attr.get("tDn", "")
            encap = attr.get("encap", "")

            binding = parse_epg_binding(dn, encap)
            path = parse_path_info(tDn)

            if not binding or not path:
                continue

            self.tree_add(
                static_tree,
                f"Pod-{path.pod}",
                self.normalize_node_label(path.pod, path.node),
                path.interface,
                label=f"{binding.app_profile}/{binding.epg} ({binding.encap})"
            )

        # SVI (L3Out) Bindings
        for item in svi_paths:
            attr = item.get("l3extRsPathL3OutAtt", {}).get("attributes", {})
            dn = attr.get("dn", "")

            if not dn.startswith(TENANT_PREFIX):
                continue

            tDn = attr.get("tDn", "")
            encap = attr.get("encap", "")

            binding = parse_l3out_binding(dn, encap)
            path = parse_path_info(tDn)

            if not binding or not path:
                continue

            self.tree_add(
                svi_tree,
                f"Pod-{path.pod}",
                self.normalize_node_label(path.pod, path.node),
                path.interface,
                label=f"{binding.l3out}/{binding.interface} ({binding.encap})"
            )

        # Output
        if static_tree:
            print(f"\nStatic Path Bindings for tenant '{tenant_name}':")
            self.print_tree(static_tree)
        else:
            print("\nNo static path bindings found.")

        if svi_tree:
            print(f"\nSVI (L3Out) Bindings for tenant '{tenant_name}':")
            self.print_tree(svi_tree)
        else:
            print("\nNo SVI bindings found.")

    def search_routes_for_ip(self, ip_str: str, prefix_filter: str = None, tenant_filter: str = None):
        """Search all VRF routing tables for prefixes that contain or match ip_str.
        Accepts a full IP address (containment check) or a string prefix (startswith match).
        Uses a single bulk query across all nodes/VRFs for performance.
        """
        try:
            ip = ip_address(ip_str)
            prefix_mode = False
        except ValueError:
            ip = None
            prefix_mode = True

        target_prefixlen = None
        if prefix_filter:
            try:
                target_prefixlen = int(prefix_filter.lstrip("/"))
            except ValueError:
                print(f"Invalid prefix filter: {prefix_filter}")
                return

        # Single query — all routes across all VRFs and all nodes
        all_routes = self.query_api("/api/node/class/uribv4Route.json", 'wcard(uribv4Route.dn,"db-rt")')
        if not all_routes:
            return

        seen = set()   # (tenant, vrf, prefix) — deduplicate across nodes
        tree = {}

        for route_item in all_routes:
            attr = route_item.get("uribv4Route", {}).get("attributes", {})
            dn = attr.get("dn", "")
            prefix = attr.get("prefix", "")

            if not prefix or prefix in EXCLUDED_CIDRS:
                continue

            # Extract tenant:vrf from DN
            dom_match = re.search(r'/uribv4/dom-([^/]+)/', dn)
            if not dom_match:
                continue
            dom = dom_match.group(1)   # e.g. "myTenant:myVRF"
            if ":" not in dom:
                continue
            tenant, vrf = dom.split(":", 1)

            if tenant_filter and tenant != tenant_filter:
                continue

            key = (tenant, vrf, prefix)
            if key in seen:
                continue

            try:
                net = ip_network(prefix, strict=False)
                if target_prefixlen is not None and net.prefixlen != target_prefixlen:
                    continue
                if prefix_mode:
                    matches = prefix.startswith(ip_str)
                else:
                    matches = ip in net
            except ValueError:
                continue

            if matches:
                seen.add(key)
                node = tree.setdefault(tenant, {}).setdefault(f"VRF: {vrf}", {})
                leaf_list = node.setdefault("_leaf", [])
                if prefix not in leaf_list:
                    leaf_list.append(prefix)

        if tree:
            self.print_tree(tree, label="Route lookup across all VRFs:")

    def handle_ip_command(self, ip_to_lookup: str, prefix_filter: str = None, tenant_filter: str = None):
        """Search for an IP address or string prefix in the ACI fabric."""
        try:
            ip_address(ip_to_lookup)
            is_full_ip = True
        except ValueError:
            is_full_ip = False

        if is_full_ip:
            print(f"Looking up IP: {ip_to_lookup}\n")

            fv_ip_data = self.query_api("/api/node/class/fvIp.json", f'eq(fvIp.addr,"{ip_to_lookup}")')
            l3ext_ip_data = self.query_api("/api/node/class/l3extIp.json")
            bgp_peer_data = self.query_api("/api/node/class/bgpPeer.json")
            static_routes = self.query_api("/api/node/class/ipRouteP.json")
            subnets = self.query_api("/api/node/class/fvSubnet.json")
            external_subnets = self.query_api("/api/node/class/l3extSubnet.json")

            endpoint_found = self.process_endpoint(fv_ip_data, tenant_filter=tenant_filter)
            ospf_found = self.process_peer(l3ext_ip_data, ip_to_lookup, kind="l3extIp", tenant_filter=tenant_filter)
            bgp_found = self.process_peer(bgp_peer_data, ip_to_lookup, kind="bgpPeer", tenant_filter=tenant_filter)
            static_found = self.process_static_route(static_routes, ip_to_lookup, tenant_filter=tenant_filter)

            if not any([endpoint_found, ospf_found, bgp_found, static_found]):
                self.process_subnet(subnets, ip_to_lookup, prefix_filter=prefix_filter, tenant_filter=tenant_filter)
                self.process_external_subnet(external_subnets, ip_to_lookup, prefix_filter=prefix_filter, tenant_filter=tenant_filter)
        else:
            print(f"Looking up IP prefix: {ip_to_lookup}\n")

            fv_ip_data = self.query_api("/api/node/class/fvIp.json", f'wcard(fvIp.addr,"{ip_to_lookup}*")')
            subnets = self.query_api("/api/node/class/fvSubnet.json")
            external_subnets = self.query_api("/api/node/class/l3extSubnet.json")

            self.process_endpoint(fv_ip_data, tenant_filter=tenant_filter)
            self.process_subnet(subnets, ip_to_lookup, prefix_mode=True, prefix_filter=prefix_filter, tenant_filter=tenant_filter)
            self.process_external_subnet(external_subnets, ip_to_lookup, prefix_mode=True, prefix_filter=prefix_filter, tenant_filter=tenant_filter)

        # Always search routing tables across all VRFs
        self.search_routes_for_ip(ip_to_lookup, prefix_filter, tenant_filter)

    def handle_port_command(self, port: str, node_id: Optional[str] = None, node_name: Optional[str] = None):
        """Search for bindings on a physical port."""
        port_str = f"eth{port}"

        # Resolve pod and node
        top_data = self.query_api("/api/node/class/topSystem.json")
        result = self.get_pod_for_node(top_data, node_id, node_name)
        if not result:
            print(f"Error: Could not find pod for node {node_id} ({node_name})")
            exit(1)
        pod_id, node_id = result

        # Fetch bindings
        static_bindings = self.query_api("/api/node/class/fvRsPathAtt.json")
        svi_bindings = self.query_api("/api/class/l3extRsPathL3OutAtt.json")

        tree = {}
        port_pattern = f"topology/pod-{pod_id}/paths-{node_id}/pathep-[{port_str}]"

        # Process L2 (EPG) bindings
        for item in static_bindings:
            attr = next(iter(item.values()))['attributes']
            dn = attr.get("dn", "")
            tDn = attr.get("tDn", "")
            encap = attr.get("encap", "")

            if port_pattern not in tDn:
                continue

            binding = parse_epg_binding(dn, encap)
            if binding:
                category = f"EPG: {binding.app_profile}"
                self.tree_add(tree, binding.tenant, category, label=f"{binding.epg} ({binding.encap})")

        # Process L3 (SVI / L3Out) bindings
        for item in svi_bindings:
            attr = next(iter(item.values()))['attributes']
            dn = attr.get("dn", "")
            tDn = attr.get("tDn", "")
            encap = attr.get("encap", "")

            if port_pattern not in tDn:
                continue

            binding = parse_l3out_binding(dn, encap)
            if binding:
                category = f"L3: {binding.l3out}"
                self.tree_add(tree, binding.tenant, category, label=f"{binding.interface} ({binding.encap})")

        # Print results
        device = self.normalize_node_label(pod_id, node_id)
        if tree:
            print(f"\nBindings for {port_str} on {device}:")
            self.print_tree(tree)
        else:
            print(f"\nNo bindings found for {port_str} on {device}.")

    def handle_vpc_command(self, nodes: str, interface: Optional[str] = None):
        """Search for bindings on a VPC interface."""
        tree = {}

        # Parse node pair
        try:
            node1, node2 = map(int, nodes.split('-'))
        except ValueError:
            print(f"Error: Invalid node pair format '{nodes}'. Expected format: 221-222")
            exit(1)

        # Find pod ID
        top_data = self.query_api("/api/node/class/topSystem.json")
        pod_id = None
        for item in top_data:
            attr = item.get("topSystem", {}).get("attributes", {})
            if attr.get("id") == str(node1):
                pod_id = attr.get("podId")
                break

        if not pod_id:
            print(f"Error: Could not find pod for node {node1}")
            exit(1)

        # If no interface specified, list all VPCs
        if not interface:
            all_bindings = self.query_api("/api/node/class/fvRsPathAtt.json")
            vpc_list = set()
            vpc_prefix = f"topology/pod-{pod_id}/protpaths-{node1}-{node2}/pathep-["

            for item in all_bindings:
                attr = item.get("fvRsPathAtt", {}).get("attributes", {})
                tDn = attr.get("tDn", "")
                if vpc_prefix in tDn:
                    vpc_name = tDn.split("pathep-[")[-1].split("]")[0]
                    vpc_list.add(vpc_name)

            if vpc_list:
                print(f"\nVPCs on nodes {nodes}:")
                for vpc in sorted(vpc_list):
                    print(f"  {vpc}")
            else:
                print(f"\nNo VPCs found on nodes {nodes}.")
            return

        vpc_pattern = f"topology/pod-{pod_id}/protpaths-{node1}-{node2}/pathep-[{interface}]"

        # L2 (Static Path) Bindings
        static_bindings = self.query_api("/api/node/class/fvRsPathAtt.json")
        for item in static_bindings:
            attr = item.get("fvRsPathAtt", {}).get("attributes", {})
            tDn = attr.get("tDn", "")
            dn = attr.get("dn", "")
            encap = attr.get("encap", "")

            if vpc_pattern not in tDn:
                continue

            binding = parse_epg_binding(dn, encap)
            if binding:
                category = f"EPG: {binding.app_profile}"
                self.tree_add(
                    tree,
                    binding.tenant,
                    category,
                    label=f"{binding.epg} ({binding.encap})"
                )

        # L3 (SVI / L3Out) Bindings
        svi_bindings = self.query_api("/api/class/l3extRsPathL3OutAtt.json")
        for item in svi_bindings:
            attr = item.get("l3extRsPathL3OutAtt", {}).get("attributes", {})
            tDn = attr.get("tDn", "")
            dn = attr.get("dn", "")
            encap = attr.get("encap", "")

            if vpc_pattern not in tDn:
                continue

            binding = parse_l3out_binding(dn, encap)
            if binding:
                category = f"L3: {binding.l3out}"
                self.tree_add(tree, binding.tenant, category, label=f"{binding.interface} ({binding.encap})")

        # Print Results
        device = self.normalize_node_label(pod_id, nodes)
        if tree:
            print(f"\nBindings for VPC {interface} on {device[0]}:")
            self.print_tree(tree)
        else:
            print(f"\nNo bindings found for VPC {interface} on {device[0]}.")

    def handle_vlan_command(self, vlan_id: int):
        """Search for VLAN usage in EPGs, L3Outs, and VLAN pools."""
        tree = {}
        vlan_str = f"vlan-{vlan_id}"

        # EPG Bindings
        epg_bindings = self.query_api(
            "/api/node/class/fvRsPathAtt.json", f'eq(fvRsPathAtt.encap,"{vlan_str}")'
        )
        for item in epg_bindings:
            attr = item.get("fvRsPathAtt", {}).get("attributes", {})
            dn = attr.get("dn", "")
            encap = attr.get("encap", "")

            binding = parse_epg_binding(dn, encap)
            if binding:
                category = f"EPG: {binding.app_profile}"
                self.tree_add(
                    tree,
                    binding.tenant,
                    category,
                    label=f"{binding.epg} ({binding.encap})"
                )

        # L3Out Bindings
        l3out_paths = self.query_api(
            "/api/class/l3extRsPathL3OutAtt.json", f'eq(l3extRsPathL3OutAtt.encap,"{vlan_str}")'
        )
        for item in l3out_paths:
            attr = item.get("l3extRsPathL3OutAtt", {}).get("attributes", {})
            dn = attr.get("dn", "")
            encap = attr.get("encap", "")

            binding = parse_l3out_binding(dn, encap)
            if binding:
                category = f"L3: {binding.l3out}"
                self.tree_add(
                    tree,
                    binding.tenant,
                    category,
                    label=f"{binding.interface} ({binding.encap})"
                )

        # Dynamic EPG Members
        endpoints = self.query_api(
            "/api/class/fvCEp.json", f'eq(fvCEp.encap,"{vlan_str}")'
        )
        for item in endpoints:
            attr = item.get("fvCEp", {}).get("attributes", {})
            dn = attr.get("dn", "")
            encap = attr.get("encap", "")

            endpoint = parse_endpoint_info(dn, encap=encap)
            if endpoint:
                category = f"EPG: {endpoint.app_profile}"
                self.tree_add(
                    tree,
                    endpoint.tenant,
                    category,
                    label=f"{endpoint.epg} ({endpoint.encap})"
                )

        # Print Results
        if tree:
            print(f"\nVLAN {vlan_id} found in:")
            self.print_tree(tree)
        else:
            print(f"\nVLAN {vlan_id} not found in any EPG or L3Out bindings.")

        # VLAN Pool Information
        vlaninstp = self.query_api("/api/class/fvnsVlanInstP.json")
        pools = self.find_vlan_in_vlan_pools(vlaninstp, vlan_id)
        if pools:
            print(f"\nVLAN {vlan_id} found in pools:")
            for pool_range in pools:
                print(f"  {pool_range}")
        else:
            print(f"\nVLAN {vlan_id} not found in any VLAN pools.")

    def handle_filter_command(self, contract_name: str, tenant_filter: str):
        """Display filter details for a contract."""
        print("")

        # Cached API queries
        contracts = self.query_api("/api/node/class/vzBrCP.json")
        rs_subj_filt = self.query_api("/api/node/class/vzRsSubjFiltAtt.json")
        filters = self.query_api("/api/node/class/vzFilter.json")
        filter_entries = self.query_api("/api/node/class/vzEntry.json")
        subjects = self.query_api("/api/node/class/vzSubj.json")

        # Find contract DN in specified tenant
        tenant_dn_prefix = f"uni/tn-{tenant_filter}/"
        contract_dn = None
        for item in contracts:
            attr = item["vzBrCP"]["attributes"]
            if attr["name"] == contract_name and attr["dn"].startswith(tenant_dn_prefix):
                contract_dn = attr["dn"]
                break

        if not contract_dn:
            print(f"❌ Contract '{contract_name}' not found in tenant '{tenant_filter}'.")
            return

        # Collect filters assigned to this contract
        used_filters = set()
        for subj_item in subjects:
            subj_attr = subj_item["vzSubj"]["attributes"]
            dn = subj_attr["dn"]
            if not dn.startswith(contract_dn + "/subj-"):
                continue

            for rel in rs_subj_filt:
                rattr = rel.get("vzRsSubjFiltAtt", {}).get("attributes", {})
                if rattr.get("dn", "").startswith(dn):
                    filter_name = rattr.get("tDn", "").split("/")[-1].replace("flt-", "")
                    used_filters.add(filter_name)

        if not used_filters:
            print(f"⚠️ No filters attached to contract '{contract_name}'")
            return

        # Build filter details
        filters_detail_node = {}

        for f_item in filters:
            fattr = f_item.get("vzFilter", {}).get("attributes", {})
            f_name = fattr.get("name")
            f_dn = fattr.get("dn")

            if f_name not in used_filters:
                continue

            rules = []
            for entry in filter_entries:
                eattr = entry.get("vzEntry", {}).get("attributes", {})
                e_dn = eattr.get("dn", "")

                if not e_dn.startswith(f_dn + "/e-"):
                    continue

                def norm(v):
                    return "any" if v in (None, "unspecified") else v

                proto = norm(eattr.get("prot"))
                sF, sT = norm(eattr.get("sFromPort")), norm(eattr.get("sToPort"))
                dF, dT = norm(eattr.get("dFromPort")), norm(eattr.get("dToPort"))

                def compact(a, b):
                    return a if a == b else f"{a}-{b}"

                sPort = compact(sF, sT)
                dPort = compact(dF, dT)

                if sPort == "any" and dPort == "any":
                    rule = f"{proto} any"
                elif sPort == "any":
                    rule = f"{proto} dst:{dPort}"
                elif dPort == "any":
                    rule = f"{proto} src:{sPort}"
                else:
                    rule = f"{proto} src:{sPort} dst:{dPort}"

                rules.append(rule)

            filters_detail_node[f_name] = rules

        # Print the result
        tree = {contract_name: {"Filter Details": filters_detail_node}}
        self.print_tree(tree)

    def handle_subnet_command(self, tenant_filter: Optional[str] = None, prefix_filter: Optional[str] = None, ip_filter: Optional[str] = None):
        """List all subnets in the ACI fabric."""
        self.list_all_subnets(tenant_filter, prefix_filter, ip_filter)

    def handle_aaep_command(self, aaep_name: Optional[str] = None, list_endpoints = False):
        """
        List all Attachable Access Entity Profiles (AAEPs) or show connection map for a specific AAEP.

        Args:
            aaep_name: If provided, show detailed connection map for this AAEP
            list_endpoints: If True or string, list MAC/IP addresses. If string, filter by EPG path
        """
        if aaep_name:
            self.handle_aaep_detail_command(aaep_name, list_endpoints)
        else:
            self.handle_aaep_list_command()

    def handle_aaep_list_command(self):
        """List all Attachable Access Entity Profiles."""
        print("Listing all Attachable Access Entity Profiles (AAEPs):\n")

        aaeps = self.query_api("/api/node/class/infraAttEntityP.json")

        if not aaeps:
            print("No AAEPs found.")
            return

        # Sort AAEPs by name
        aaep_list = sorted([item["infraAttEntityP"]["attributes"]["name"] for item in aaeps])

        tree = {"AAEPs": aaep_list}
        self.print_tree(tree)

        print(f"\nTotal: {len(aaep_list)} AAEP(s)")
        print("\nTip: Use 'acitool aaep <name>' to see the connection map for a specific AAEP")

    def handle_aaep_detail_command(self, aaep_name: str, list_endpoints = False):
        """
        Show connection map for a specific AAEP, including:
        - Domains associated with the AAEP
        - VLAN pools used by those domains
        - Interface policies/profiles that reference the AAEP
        - Physical interfaces where the AAEP is applied
        - Optionally, all MAC/IP addresses connected via this AAEP

        Args:
            aaep_name: Name of the AAEP to inspect
            list_endpoints: If True or string, list MAC/IP addresses. If string, filter by EPG path
        """
        print(f"Connection map for AAEP: {aaep_name}\n")

        # Get AAEP details
        aaeps = self.query_api("/api/node/class/infraAttEntityP.json")
        aaep_obj = None
        aaep_dn = None

        for item in aaeps:
            attr = item["infraAttEntityP"]["attributes"]
            if attr["name"] == aaep_name:
                aaep_obj = attr
                aaep_dn = attr["dn"]
                break

        if not aaep_obj:
            print(f"❌ AAEP '{aaep_name}' not found.")
            return

        tree = {}

        # 1. Find domains associated with this AAEP
        domain_refs = self.query_api("/api/node/class/infraRsDomP.json")
        domains = []

        for item in domain_refs:
            attr = item["infraRsDomP"]["attributes"]
            if aaep_dn in attr.get("dn", ""):
                tDn = attr.get("tDn", "")
                # Parse domain DN to get type and name
                # Possible domain types: physDomP (Physical), vmmDomP (VMM), l2extDomP (L2 External), l3extDomP (L3 External), fcDomP (FC)
                if "/phys-" in tDn:
                    domain_name = tDn.split("/phys-")[1].split("/")[0]
                    domains.append(("Physical", domain_name, tDn))
                elif "/vmmp-" in tDn:
                    # VMM domains have format: uni/vmmp-VMware/dom-DVS_NAME
                    parts = tDn.split("/")
                    vendor = parts[1].replace("vmmp-", "") if len(parts) > 1 else "VMM"
                    domain_name = parts[2].replace("dom-", "") if len(parts) > 2 else "unknown"
                    domains.append((f"VMM ({vendor})", domain_name, tDn))
                elif "/l2dom-" in tDn:
                    domain_name = tDn.split("/l2dom-")[1].split("/")[0]
                    domains.append(("L2 External", domain_name, tDn))
                elif "/l3dom-" in tDn:
                    domain_name = tDn.split("/l3dom-")[1].split("/")[0]
                    domains.append(("L3 External", domain_name, tDn))
                elif "/fcdom-" in tDn:
                    domain_name = tDn.split("/fcdom-")[1].split("/")[0]
                    domains.append(("Fibre Channel", domain_name, tDn))

        # Build domains section
        if domains:
            domain_tree = {}
            for domain_type, domain_name, domain_dn in domains:
                # Get VLAN pool for this domain
                vlan_pool_refs = self.query_api("/api/node/class/infraRsVlanNs.json")
                vlan_pools = []

                for vp_item in vlan_pool_refs:
                    vp_attr = vp_item["infraRsVlanNs"]["attributes"]
                    if domain_dn in vp_attr.get("dn", ""):
                        vp_tDn = vp_attr.get("tDn", "")
                        vp_match = RE_VLAN_POOL_TDN.search(vp_tDn)
                        if vp_match:
                            vlan_pools.append(vp_match.group("pool"))

                if vlan_pools:
                    domain_tree[f"{domain_type}: {domain_name}"] = {"VLAN Pools": vlan_pools}
                else:
                    domain_tree[f"{domain_type}: {domain_name}"] = ["No VLAN pool"]

            tree["Domains"] = domain_tree

        # 2. Find interface policy groups that reference this AAEP
        aaep_refs = self.query_api("/api/node/class/infraRsAttEntP.json")
        policy_groups = []

        for item in aaep_refs:
            attr = item["infraRsAttEntP"]["attributes"]
            tDn = attr.get("tDn", "")

            if f"attentp-{aaep_name}" in tDn:
                dn = attr.get("dn", "")
                # Parse interface policy group DN
                # Format: uni/infra/funcprof/accportgrp-NAME or uni/infra/funcprof/accbundle-NAME
                if "/accportgrp-" in dn:
                    pg_name = dn.split("/accportgrp-")[1].split("/")[0]
                    policy_groups.append(("Access Port", pg_name))
                elif "/accbundle-" in dn:
                    pg_name = dn.split("/accbundle-")[1].split("/")[0]
                    policy_groups.append(("Port Channel/VPC", pg_name))

        if policy_groups:
            pg_tree = {}
            for pg_type, pg_name in policy_groups:
                pg_tree.setdefault(pg_type, []).append(pg_name)
            tree["Interface Policy Groups"] = pg_tree

        # 3. Find physical interfaces using this AAEP (via interface policy groups)
        interface_tree = {}

        # Get all interface selectors
        if policy_groups:
            # Get interface profile relationships
            rs_acc_base_grp = self.query_api("/api/node/class/infraRsAccBaseGrp.json")

            for pg_type, pg_name in policy_groups:
                # Find which interface selectors use this policy group
                for item in rs_acc_base_grp:
                    attr = item["infraRsAccBaseGrp"]["attributes"]
                    tDn = attr.get("tDn", "")

                    if f"-{pg_name}" in tDn:
                        dn = attr.get("dn", "")
                        # Parse: uni/infra/accportprof-PROFILE/hports-SELECTOR-typ-range
                        # OR: uni/infra/fexprof-PROFILE/hports-SELECTOR-typ-range (for FEX)
                        if "/accportprof-" in dn or "/fexprof-" in dn:
                            parts = dn.split("/")
                            profile_name = None
                            selector_name = None

                            for part in parts:
                                if part.startswith("accportprof-"):
                                    profile_name = part.replace("accportprof-", "")
                                elif part.startswith("fexprof-"):
                                    profile_name = part.replace("fexprof-", "")
                                elif part.startswith("hports-"):
                                    selector_name = part.replace("hports-", "").replace("-typ-range", "")

                            if profile_name and selector_name:
                                # Get port blocks for this selector
                                port_blocks = self.query_api(
                                    f"/api/mo/{dn}.json?query-target=children&target-subtree-class=infraPortBlk"
                                )

                                ports = []
                                for pb in port_blocks or []:
                                    pb_attr = pb["infraPortBlk"]["attributes"]
                                    from_port = pb_attr.get("fromPort")
                                    to_port = pb_attr.get("toPort")

                                    if from_port == to_port:
                                        ports.append(f"Port {from_port}")
                                    else:
                                        ports.append(f"Ports {from_port}-{to_port}")

                                # Find which switch profiles use this interface profile
                                rs_acc_port_p = self.query_api("/api/node/class/infraRsAccPortP.json")

                                for sw_item in rs_acc_port_p:
                                    sw_attr = sw_item["infraRsAccPortP"]["attributes"]
                                    if f"accportprof-{profile_name}" in sw_attr.get("tDn", ""):
                                        sw_dn = sw_attr.get("dn", "")
                                        # Parse switch profile: uni/infra/nprof-SWITCH_PROFILE
                                        if "/nprof-" in sw_dn:
                                            sw_profile = sw_dn.split("/nprof-")[1].split("/")[0]

                                            # Get node selectors for this switch profile
                                            node_sels = self.query_api(
                                                f"/api/mo/uni/infra/nprof-{sw_profile}.json?query-target=children&target-subtree-class=infraNodeBlk"
                                            )

                                            nodes = []
                                            for ns in node_sels or []:
                                                ns_attr = ns["infraNodeBlk"]["attributes"]
                                                from_node = ns_attr.get("from_")
                                                to_node = ns_attr.get("to_")

                                                if from_node == to_node:
                                                    nodes.append(from_node)
                                                else:
                                                    nodes.append(f"{from_node}-{to_node}")

                                            if nodes and ports:
                                                for node in nodes:
                                                    node_label = self.normalize_node_label("1", node)
                                                    interface_tree.setdefault(node_label, []).extend([
                                                        f"{selector_name}: {port}" for port in ports
                                                    ])

        if interface_tree:
            tree["Physical Interfaces"] = interface_tree

        # Print the tree
        if tree:
            self.print_tree(tree, label=f"AAEP '{aaep_name}' Connection Map")
        else:
            print(f"⚠️  AAEP '{aaep_name}' exists but has no associations.")

        # 4. List endpoints (MAC/IP addresses) if requested
        if list_endpoints:
            print("\n" + "=" * 80)
            print("Endpoints (MAC/IP Addresses) connected via this AAEP:")
            print("=" * 80 + "\n")

            endpoint_tree = {}
            epg_dns = set()  # Use set to avoid duplicates

            # Strategy: Find EPGs that use domains from this AAEP AND have static/dynamic bindings
            # to this AAEP's interfaces

            # Step 1: Find all EPGs that use domains associated with this AAEP
            domain_dns = [dn for _, _, dn in domains]
            epg_candidates = set()  # EPGs that use our domains

            if domain_dns:
                epg_domains = self.query_api("/api/node/class/fvRsDomAtt.json")

                for item in epg_domains:
                    attr = item["fvRsDomAtt"]["attributes"]
                    tDn = attr.get("tDn", "")

                    # Check if this EPG uses one of our domains
                    if any(domain_dn in tDn for domain_dn in domain_dns):
                        dn = attr.get("dn", "")
                        # Extract EPG DN (remove the domain relation part)
                        # dn format: uni/tn-X/ap-Y/epg-Z/rsdomAtt-[...]
                        if "/rsdomAtt-" in dn:
                            epg_dn = dn.split("/rsdomAtt-")[0]
                        else:
                            epg_dn = "/".join(dn.split("/")[:5])  # Get up to epg-Z
                        epg_candidates.add(epg_dn)

            # Step 2: Build a set of actual topology paths for this AAEP's interfaces
            topology_paths = set()

            # Get all interface selectors that reference this AAEP's policy groups
            rs_acc_base_grp = self.query_api("/api/node/class/infraRsAccBaseGrp.json")

            for pg_type, pg_name in policy_groups:
                for item in rs_acc_base_grp:
                    attr = item["infraRsAccBaseGrp"]["attributes"]
                    tDn = attr.get("tDn", "")

                    if f"-{pg_name}" in tDn:
                        dn = attr.get("dn", "")
                        # Parse: uni/infra/accportprof-PROFILE/hports-SELECTOR-typ-range/rsaccBaseGrp
                        # OR: uni/infra/fexprof-PROFILE/hports-SELECTOR-typ-range/rsaccBaseGrp (for FEX)
                        # We need to query the parent (hports) not the child (rsaccBaseGrp)
                        if "/accportprof-" in dn or "/fexprof-" in dn:
                            # Remove the /rsaccBaseGrp part to get the hports DN
                            hports_dn = dn.rsplit("/", 1)[0] if "/rsaccBaseGrp" in dn else dn

                            # Get port blocks for this selector
                            port_blocks = self.query_api(
                                f"/api/mo/{hports_dn}.json?query-target=children&target-subtree-class=infraPortBlk"
                            )

                            port_numbers = []
                            for pb in port_blocks or []:
                                pb_attr = pb["infraPortBlk"]["attributes"]
                                from_port = pb_attr.get("fromPort")
                                to_port = pb_attr.get("toPort")

                                # Collect individual port numbers
                                if from_port and to_port:
                                    try:
                                        from_num = int(from_port)
                                        to_num = int(to_port)
                                        port_numbers.extend(range(from_num, to_num + 1))
                                    except ValueError:
                                        # Handle non-numeric port identifiers
                                        pass

                            # Find which switch profiles use this interface profile
                            parts = dn.split("/")
                            profile_name = None
                            is_fex = False
                            for part in parts:
                                if part.startswith("accportprof-"):
                                    profile_name = part.replace("accportprof-", "")
                                    break
                                elif part.startswith("fexprof-"):
                                    profile_name = part.replace("fexprof-", "")
                                    is_fex = True
                                    break

                            if profile_name:
                                if is_fex:
                                    # For FEX profiles, we need to find which leaf nodes the FEX is connected to
                                    # The FEX path format is: topology/pod-1/paths-LEAF_ID/extpaths-FEX_ID/pathep-[eth1/PORT]

                                    import re
                                    fex_match = re.search(r'fex(\d+)', profile_name.lower())

                                    if fex_match:
                                        fex_id = fex_match.group(1)

                                        # Query existing static path bindings to find which leaf node(s) this FEX is connected to
                                        # This is more reliable than querying fabric topology
                                        all_paths = self.query_api("/api/node/class/fvRsPathAtt.json")

                                        leaf_ids = set()
                                        for path_item in all_paths:
                                            path_attr = path_item.get("fvRsPathAtt", {}).get("attributes", {})
                                            tDn = path_attr.get("tDn", "")
                                            # Look for paths like: topology/pod-1/paths-LEAF/extpaths-FEX_ID/...
                                            if f"/extpaths-{fex_id}/" in tDn:
                                                leaf_match = re.search(r'/paths-(\d+)/', tDn)
                                                if leaf_match:
                                                    leaf_ids.add(leaf_match.group(1))

                                        if leaf_ids:
                                            # Build FEX topology paths for each leaf
                                            for leaf_id in leaf_ids:
                                                for port_num in port_numbers:
                                                    path = f"topology/pod-1/paths-{leaf_id}/extpaths-{fex_id}/pathep-[eth1/{port_num}]"
                                                    topology_paths.add(path)
                                else:
                                    # Regular access port profile
                                    rs_acc_port_p = self.query_api("/api/node/class/infraRsAccPortP.json")

                                    for sw_item in rs_acc_port_p:
                                        sw_attr = sw_item["infraRsAccPortP"]["attributes"]
                                        if f"accportprof-{profile_name}" in sw_attr.get("tDn", ""):
                                            sw_dn = sw_attr.get("dn", "")
                                            # Parse switch profile: uni/infra/nprof-SWITCH_PROFILE
                                            if "/nprof-" in sw_dn:
                                                sw_profile = sw_dn.split("/nprof-")[1].split("/")[0]

                                                # Get node selectors for this switch profile
                                                node_sels = self.query_api(
                                                    f"/api/mo/uni/infra/nprof-{sw_profile}.json?query-target=children&target-subtree-class=infraNodeBlk"
                                                )

                                                node_ids = []
                                                for ns in node_sels or []:
                                                    ns_attr = ns["infraNodeBlk"]["attributes"]
                                                    from_node = ns_attr.get("from_")
                                                    to_node = ns_attr.get("to_")

                                                    if from_node and to_node:
                                                        try:
                                                            from_num = int(from_node)
                                                            to_num = int(to_node)
                                                            node_ids.extend(range(from_num, to_num + 1))
                                                        except ValueError:
                                                            pass

                                                # Build topology paths for each node/port combination
                                                # Check if this is a Port Channel/VPC (bundle) or regular access port
                                                if pg_type == "Port Channel/VPC":
                                                    # For bundles, the path uses the policy group name, not individual ports
                                                    # VPC format: topology/pod-1/protpaths-NODE1-NODE2/pathep-[PC_NAME]
                                                    # PC format: topology/pod-1/paths-NODE/pathep-[PC_NAME]
                                                    if len(node_ids) > 1:
                                                        # VPC - multiple nodes
                                                        sorted_nodes = sorted(node_ids)
                                                        path = f"topology/pod-1/protpaths-{sorted_nodes[0]}-{sorted_nodes[1]}/pathep-[{pg_name}]"
                                                        topology_paths.add(path)
                                                    else:
                                                        # Port Channel - single node
                                                        for node_id in node_ids:
                                                            path = f"topology/pod-1/paths-{node_id}/pathep-[{pg_name}]"
                                                            topology_paths.add(path)
                                                else:
                                                    # Regular access port
                                                    # Format: topology/pod-1/paths-NODE/pathep-[eth1/PORT]
                                                    for node_id in node_ids:
                                                        for port_num in port_numbers:
                                                            # Handle both regular ports and breakout ports
                                                            path = f"topology/pod-1/paths-{node_id}/pathep-[eth1/{port_num}]"
                                                            topology_paths.add(path)

            # Step 3: Filter EPG candidates to only those with static bindings to our paths
            if epg_candidates and topology_paths:
                all_static_paths = self.query_api("/api/node/class/fvRsPathAtt.json")

                for path_item in all_static_paths:
                    path_attr = path_item.get("fvRsPathAtt", {}).get("attributes", {})
                    tDn = path_attr.get("tDn", "")
                    dn = path_attr.get("dn", "")

                    # Extract EPG DN from the path binding
                    if "/rspathAtt-" in dn:
                        epg_dn = dn.split("/rspathAtt-")[0]

                        # Only add this EPG if:
                        # 1. It's in our candidate list (uses our domains)
                        # 2. This static binding references one of our topology paths
                        if epg_dn in epg_candidates and any(topo_path in tDn for topo_path in topology_paths):
                            epg_dns.add(epg_dn)

            if not epg_dns:
                if epg_candidates:
                    print(f"Found {len(epg_candidates)} EPG(s) using the domains, but none have static bindings to this AAEP's interfaces.\n")
                    print("This could mean:")
                    print("  - The EPGs use the domains but are not statically bound to these specific interfaces")
                    print("  - The interfaces may be used for dynamic bindings (VMM domains) instead")
                    print("  - The EPGs may be bound to different interfaces using the same domain\n")
                else:
                    print("No EPGs found using this AAEP.\n")
                    print("This could mean:")
                    print("  - No EPGs are attached to the domains associated with this AAEP")
                    print("  - The AAEP is configured but not actively in use\n")
                return

            # Get all endpoints (MAC/IP) in bulk
            all_endpoints = self.query_api("/api/node/class/fvCEp.json")
            all_ips = self.query_api("/api/node/class/fvIp.json")

            # Build a map of endpoint DN to IPs for faster lookup
            ip_map = {}
            for ip_item in all_ips:
                ip_attr = ip_item.get("fvIp", {}).get("attributes", {})
                ip_dn = ip_attr.get("dn", "")
                ip_addr = ip_attr.get("addr")

                # Extract CEP DN from IP DN
                # Format: uni/tn-X/ap-Y/epg-Z/cep-MAC/ip-[ADDR]
                if "/cep-" in ip_dn and "/ip-" in ip_dn:
                    cep_dn = ip_dn.split("/ip-")[0]
                    if cep_dn not in ip_map:
                        ip_map[cep_dn] = []
                    if ip_addr:
                        ip_map[cep_dn].append(ip_addr)

            # Process endpoints
            for item in all_endpoints:
                attr = item.get("fvCEp", {}).get("attributes", {})
                dn = attr.get("dn", "")
                mac = attr.get("mac", "")
                encap = attr.get("encap", "")

                # Check if this endpoint belongs to one of our EPGs
                for epg_dn in epg_dns:
                    if epg_dn in dn:
                        # Parse EPG info
                        epg_match = parse_regex(RE_EPG, dn)
                        if epg_match:
                            tenant = epg_match["tenant"]
                            ap = epg_match["ap"]
                            epg = epg_match["epg"]

                            # Get IP addresses for this MAC from our pre-built map
                            ips = ip_map.get(dn, [])

                            # Build the tree entry
                            epg_path = f"{tenant}/{ap}/{epg}"
                            if ips:
                                for ip in ips:
                                    endpoint_tree.setdefault(epg_path, []).append(f"MAC: {mac} | IP: {ip} | VLAN: {encap}")
                            else:
                                endpoint_tree.setdefault(epg_path, []).append(f"MAC: {mac} | VLAN: {encap}")
                        break

            if endpoint_tree:
                # Determine if we're filtering by EPG
                epg_filter = None
                if isinstance(list_endpoints, str):
                    epg_filter = list_endpoints

                # If no EPG filter specified, just show the summary list
                if not epg_filter:
                    total_endpoints = 0
                    for epg_path in sorted(endpoint_tree.keys()):
                        count = len(endpoint_tree[epg_path])
                        total_endpoints += count
                        print(f"  {epg_path:<50} ({count})")

                    print(f"\n{'=' * 80}")
                    print(f"Total: {total_endpoints} endpoint(s) across {len(endpoint_tree)} EPG(s)")
                    print(f"{'=' * 80}")
                    return

                # EPG filter is specified - show detailed table for that EPG
                if epg_filter not in endpoint_tree:
                    print(f"❌ EPG '{epg_filter}' not found or has no endpoints on this AAEP.\n")
                    print("Available EPGs on this AAEP:")
                    for epg in sorted(endpoint_tree.keys()):
                        count = len(endpoint_tree[epg])
                        print(f"  {epg:<50} ({count})")
                    return

                endpoints = endpoint_tree[epg_filter]

                # Determine if we have IPs or not (to adjust column widths)
                has_ip = any('IP:' in ep for ep in endpoints)

                if has_ip:
                    # Header with IP column
                    print(f"\n┌{'─' * 54}┐")
                    print(f"│ {epg_filter:<52} │")
                    print(f"├{'─' * 54}┤")
                    print(f"│ {'MAC Address':<19} │ {'IP Address':<15} │ {'VLAN':<12} │")
                    print(f"├{'─' * 21}┼{'─' * 17}┼{'─' * 14}┤")

                    for endpoint in sorted(endpoints):
                        # Parse: "MAC: xx:xx:xx:xx:xx:xx | IP: x.x.x.x | VLAN: vlan-xxx"
                        parts = endpoint.split(' | ')
                        mac = parts[0].replace('MAC: ', '').strip()
                        ip = parts[1].replace('IP: ', '').strip() if len(parts) > 2 else 'N/A'
                        vlan = parts[2].replace('VLAN: ', '').strip() if len(parts) > 2 else parts[1].replace('VLAN: ', '').strip()

                        print(f"│ {mac:<19} │ {ip:<15} │ {vlan:<12} │")
                    print(f"└{'─' * 54}┘")

                else:
                    # Header without IP column (simpler format)
                    print(f"\n┌{'─' * 36}┐")
                    print(f"│ {epg_filter:<34} │")
                    print(f"├{'─' * 36}┤")
                    print(f"│ {'MAC Address':<19} │ {'VLAN':<12} │")
                    print(f"├{'─' * 21}┼{'─' * 14}┤")

                    for endpoint in sorted(endpoints):
                        # Parse: "MAC: xx:xx:xx:xx:xx:xx | VLAN: vlan-xxx"
                        parts = endpoint.split(' | ')
                        mac = parts[0].replace('MAC: ', '').strip()
                        vlan = parts[1].replace('VLAN: ', '').strip()

                        print(f"│ {mac:<19} │ {vlan:<12} │")

                    print(f"└{'─' * 36}┘")

                # Footer
                print(f"  Endpoints: {len(endpoints)}")
                print(f"\n{'=' * 80}")
                print(f"Total: {len(endpoints)} endpoint(s) in EPG '{epg_filter}'")
                print(f"{'=' * 80}")
            else:
                print("No active endpoints found on EPGs using this AAEP.")
                print("The EPGs are configured but have no learned MAC/IP addresses yet.\n")

    @staticmethod
    def print_tree(tree, label=None):
        """Print tree structure (backward compatibility wrapper)."""
        ACITreeBuilder.print_tree(tree, label)


# =========================================================================
# Main Function
# =========================================================================

def main():
    """Main entry point for the ACI tool."""
    load_dotenv()
    url = os.environ.get('APIC_URL')

    if not url:
        logger.error("APIC_URL environment variable not set")
        logger.info("Please set it in your .env file or environment")
        logger.info("Example: export APIC_URL=https://apic.example.com")
        exit(1)

    # Get VERIFY_SSL setting from environment (defaults to False)
    verify_ssl_env = os.environ.get('VERIFY_SSL', 'false').lower()
    verify_ssl = verify_ssl_env in ('true', 'yes', '1')

    args = parse_args()
    apic = ACIClient(url, verify_ssl=verify_ssl)
    apic.login()

    # Dispatch to appropriate command handler method
    if args.command == "ip":
        apic.handle_ip_command(args.ip, args.prefix, args.tenant)
    elif args.command == "port":
        apic.handle_port_command(args.port, args.id, args.name)
    elif args.command == "vpc":
        apic.handle_vpc_command(args.nodes, args.interface)
    elif args.command == "vlan":
        apic.handle_vlan_command(int(args.vlan))
    elif args.command == "tenant":
        apic.handle_tenant_command(args.tenant)
    elif args.command == "clean":
        apic.handle_clean_command(args.clean_cmd, getattr(args, "tenant", None))
    elif args.command == "contract":
        apic.handle_contract_command(args.contract, args.tenant, args.filters)
    elif args.command == "subnet":
        apic.handle_subnet_command(args.tenant, args.prefix, args.filter)
    elif args.command == "aaep":
        apic.handle_aaep_command(args.name, args.list_endpoints)
    elif args.command == "route":
        apic.handle_route_command(args.vrf, args.detail, args.filter, args.prefix, args.local, args.external)

if __name__ == "__main__":
    main()
