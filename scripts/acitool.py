#!/usr/bin/env python3

import os
import re
import sys
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# -------------------------------
# Constants
# -------------------------------

# API Endpoints
API_NODE_CLASS = "/api/node/class"
API_CLASS = "/api/class"

# Excluded Networks (for filtering common/private ranges)
EXCLUDED_CIDRS = {"0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"}

# -------------------------------
# Argument Parsing
# -------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Script to look up IP, port, VLAN, or tenant bindings inside ACI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ip_parser = subparsers.add_parser("ip", help="Search by IP address")
    ip_parser.add_argument("ip", help="IP to search for")

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

    contract_parser = subparsers.add_parser("contract", help="Contract lookup")
    contract_parser.add_argument("contract", help="Contract name")
    contract_parser.add_argument("-t", "--tenant", help="Only search inside this tenant")

    subnet_parser = subparsers.add_parser("subnet", help="List all subnets in use in the ACI fabric")
    subnet_parser.add_argument("-t", "--tenant", help="Filter by tenant name", default=None)
    subnet_parser.add_argument("-p", "--prefix", help="Filter by subnet mask (e.g., /24, /30)", default=None)

    return parser.parse_args()

# -------------------------------------------------------
#  GLOBAL COMPILED REGEX (runs once, reused everywhere)
# -------------------------------------------------------
# ACI Object DNs
RE_VRF                  = re.compile(r"uni/tn-(?P<tenant>[^/]+)/ctx-(?P<vrf>[^/]+)")
RE_BD                   = re.compile(r"uni/tn-(?P<tenant>[^/]+)/BD-(?P<bd>[^/]+)")
RE_EPG                  = re.compile(r"uni/tn-(?P<tenant>[^/]+)/ap-(?P<ap>[^/]+)/epg-(?P<epg>[^/]+)")
RE_EPG_DN               = re.compile(r"uni/tn-[^/]+/ap-(?P<ap>[^/]+)/epg-(?P<epg>[^/]+)")
RE_CEP                  = re.compile(r"uni/tn-(?P<tenant>[^/]+)/ap-(?P<ap>[^/]+)/epg-(?P<epg>[^/]+)/cep-(?P<cep>[^/]+)")

# L3Out DNs
RE_L3OUT                = re.compile(r"uni/tn-(?P<tenant>[^/]+)/out-(?P<l3out>[^/]+)")
RE_L3OUT_DN             = re.compile(r"uni/tn-[^/]+/out-(?P<l3out>[^/]+)/lnodep-[^/]+/lifp-(?P<lifp>[^/]+)")
RE_L3OUT_PATH           = re.compile(r"uni/tn-(?P<tenant>[^/]+)/out-(?P<out>[^/]+)/lnodep-[^/]+/lifp-(?P<lifp>[^/]+)")

# Topology and Infrastructure
RE_PATH_TDN             = re.compile(r"topology/pod-(?P<pod>\d+)/(?:prot)?paths-(?P<node>\d+(?:-\d+)?)/pathep-\[(?P<iface>[^\]]+)\]")
RE_AAEP_TDN             = re.compile(r"attentp-([^\]]+)$")
RE_VLAN_POOL_TDN        = re.compile(r"vlanns-\[(?P<pool>[^\]]+)\]")

def parse_regex(regex, text: str) -> Optional[Dict[str, Any]]:
    """Small safe helper to reduce boilerplate."""
    m = regex.search(text)
    return m.groupdict() if m else None

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
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Disable SSL warnings only if verification is disabled
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @lru_cache(maxsize=64)
    def cached_api(self, endpoint: str):
        return self.get_api(endpoint) or []

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

        if not username or not password:
            username, password = self.prompt_credentials()

        payload = {
            "aaaUser": {"attributes": {"name": username, "pwd": password}}
        }
        try:
            response = self.session.post(f"{self.apic_url}/api/aaaLogin.json", json=payload, verify=self.verify_ssl)
            response.raise_for_status()

            # Parse and validate response
            json_data = response.json()
            self.token = json_data["imdata"][0]["aaaLogin"]["attributes"]["token"]
            self.session.cookies["APIC-cookie"] = self.token
            self.save_token_to_file()
        except requests.RequestException as e:
            logger.error(f"Login failed: {e}")
            exit(1)
        except (KeyError, IndexError, TypeError) as e:
            logger.error(f"Unexpected login response format: {e}")
            exit(1)

    def get_api(self, api_path):
        if not self.token:
            raise Exception("Not logged in. Call login() first.")
        try:
            response = self.session.get(f"{self.apic_url}{api_path}", verify=self.verify_ssl)
            response.raise_for_status()
            return response.json().get("imdata", [])
        except requests.RequestException as e:
            logger.error(f"API request failed: {e}")
            return None

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

    def process_endpoint(self, data):
        found = False
        for item in data:
            attr = item.get("fvIp", {}).get("attributes", {})
            addr = attr.get("addr", "")
            dn = attr.get("dn", "")
            tDn = attr.get("tDn", "")
            fabric_path = attr.get("fabricPathDn", "")

            dn_match = parse_regex(RE_CEP, dn)
            # For fabric_path we need a simpler pattern match
            fp_match = re.search(r"pod-(?P<pod>\d+)/paths-(?P<node>\d+)/pathep-\[(?P<pathep>[^\]]+)\]", fabric_path)

            if dn_match and fp_match:
                print(f"IP found in:")
                print(f"  {dn_match['tenant']}\n    AP:{dn_match['ap']}\n      {dn_match['epg']}\n")
                print(f"  Physical location: Pod-{fp_match['pod']}, Node-{fp_match['node']} MAC:[{dn_match['mac']}]")
                print(f"  Interface Selector: {fp_match['pathep']}")
                found = True

        return found

    def process_subnet(self, data, ip):
        tree = {}
        for item in data:
            attr = item.get("fvSubnet", {}).get("attributes", {})
            cidr = attr.get("ip", "")
            if not self.ip_in_cidr(ip, cidr):
                continue

            dn = attr.get("dn", "")
            match = re.search(
                r"uni/tn-(?P<tenant>[^/]+)/(?:BD-(?P<bd>[^/]+)/|ap-(?P<ap>[^/]+)/epg-(?P<epg>[^/]+)/)",
                dn
            )

            if not match:
                continue

            tenant, bd, ap, epg = match["tenant"], match["bd"], match["ap"], match["epg"]
            tree.setdefault(tenant, {})
            if bd:
                tree[tenant].setdefault("BD:", []).append(f"{bd} - {cidr}")
            if ap:
                tree[tenant].setdefault("AP:", {}).setdefault(ap, []).append(f"{epg} - {cidr}")

        if tree:
            self.print_tree(tree, label="IP not found, possible Subnet:")

    def process_external_subnet(self, data, ip):
        tree = {}

        for item in data:
            attr = item.get("l3extSubnet", {}).get("attributes", {})
            cidr = attr.get("ip", "")
            if cidr in EXCLUDED_CIDRS or not self.ip_in_cidr(ip, cidr):
                continue

            match = re.search(
                r"uni/tn-(?P<tenant>[^/]+)/out-(?P<out>[^/]+)/instP-(?P<network>[^/]+)/extsubnet-\[(?P<subnet>[^\]]+)\]",
                attr.get("dn", "")
            )
            if not match:
                continue

            tenant, out, network, subnet_info = match.groups()
            tree.setdefault(tenant, {}).setdefault("out:", {}).setdefault(out, []).append(f"{network} - {subnet_info}")

        if tree:
            self.print_tree(tree, label="Possible L3out:")

    def process_peer(self, data, ip_to_lookup, kind):
        tree = {}
        for item in data:
            attr = item.get(kind, {}).get("attributes", {})
            addr = attr.get("addr") or attr.get("id")

            if not self.ip_in_cidr(ip_to_lookup, addr):
                continue

            dn = attr.get("dn", "")
            if kind == "l3extIp":
                match = re.search(r"uni/tn-([^/]+)/out-([^/]+)/lnodep-([^/]+)/lifp-([^/]+)", dn)
                if match:
                    tenant, l3out, _, iface = match.groups()
                    label = f"/{iface} - {addr}"
                    tree.setdefault(tenant, {}).setdefault(f"L3Out: {l3out}", set()).add(label)

            elif kind == "bgpPeer":
                match = re.search(r"pod-([^/]+)/node-([^/]+)/.*?/dom-([^:/]+)", dn)
                if match:
                    _, _, tenant = match.groups()
                    label = f"Peer IP: {addr}"
                    tree.setdefault(tenant, {}).setdefault(f"L3Out: {tenant}", set()).add(label)

        if tree:
            tree = {t: {k: list(v) for k, v in cats.items()} for t, cats in tree.items()}
            label = f"Matching {'OSPF' if kind == 'l3extIp' else 'BGP'} Peers:"
            self.print_tree(tree, label=label)
            return True
        else:
            return False

    def process_static_route(self, data, ip_to_lookup):
        tree = {}

        for item in data:
            attr = item.get("ipRouteP", {}).get("attributes", {})
            prefix = attr.get("ip", "")
            if prefix in EXCLUDED_CIDRS or not self.ip_in_cidr(ip_to_lookup, prefix):
                continue

            match = re.search(r"uni/tn-([^/]+)/out-([^/]+)/instP-([^/]+)", attr.get("dn", ""))
            if match:
                tenant, l3out, instP = match.groups()
                label = f"/{instP} - {prefix}"
                tree.setdefault(tenant, {}).setdefault(f"L3Out: {l3out}", set()).add(label)

        if tree:
            tree = {t: {k: list(v) for k, v in cats.items()} for t, cats in tree.items()}
            self.print_tree(tree, label="Matching Static Routes:")
            return True
        else:
            return False

    def find_vlan_in_vlan_pools(self, pools, vlan_id):
        """
        Check which VLAN pools contain the specified VLAN ID.
        Returns a list of tuples: (pool_name, pool_dn, from_vlan, to_vlan)
        """
        results = []

        for pool in pools:
            pool_attrs = pool["fvnsVlanInstP"]["attributes"]
            pool_dn = pool_attrs["dn"]
            pool_name = pool_attrs["name"]

            # Fetch all encap blocks for this pool
            blocks = self.get_api(
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
                    results.append((pool_name, blk_attrs["dn"], from_vlan, to_vlan))

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

    def list_all_subnets(self, tenant_filter=None, prefix_filter=None):
        """
        List all subnets in use in the ACI fabric (BD + L3Out), optionally filter by tenant and subnet mask.
        """
        tree = {}

        def subnet_matches(ip_cidr, prefix_filter):
            if not prefix_filter:
                return True
            try:
                net = ip_network(ip_cidr, strict=False)
                return net.prefixlen == int(prefix_filter.lstrip("/"))
            except ValueError:
                return False

        # -----------------------
        # 1. BD / SVI Subnets
        # -----------------------
        bd_subnets = self.get_api("/api/class/fvSubnet.json?query-target=self")
        for item in bd_subnets:
            attr = item.get("fvSubnet", {}).get("attributes", {})
            dn = attr.get("dn", "")
            ip = attr.get("ip", "")
            match = parse_regex(RE_BD, dn)

            if not match:
                continue

            tenant = match["tenant"]
            bd = match["bd"]

            if tenant_filter and tenant != tenant_filter:
                continue

            if not subnet_matches(ip, prefix_filter):
                continue

            tree.setdefault(tenant, {}).setdefault("BD Subnets:", []).append(f"{bd} - {ip}")

        # -----------------------
        # 2. L3Out Subnets
        # -----------------------
        l3out_subnets = self.get_api("/api/class/l3extSubnet.json?query-target=self")
        for item in l3out_subnets:
            attr = item.get("l3extSubnet", {}).get("attributes", {})
            dn = attr.get("dn", "")
            ip = attr.get("ip", "")
            match = parse_regex(RE_L3OUT, dn)

            if not match:
                continue

            tenant = match["tenant"]
            l3out = match["l3out"]

            if tenant_filter and tenant != tenant_filter:
                continue

            if not subnet_matches(ip, prefix_filter):
                continue

            tree.setdefault(tenant, {}).setdefault("L3Out Subnets:", []).append(f"{l3out} - {ip}")

        # -----------------------
        # Print result
        # -----------------------
        if tree:
            self.print_tree(tree, label=f"ACI Subnets in use (BD + L3Out){' - ' + prefix_filter if prefix_filter else ''}:")
        else:
            print("[!] No subnets found matching the criteria.")

    @lru_cache(maxsize=1)
    def get_node_inventory(self):
        """
        Fetch and cache APIC fabric node inventory.
        Returns a dict mapping node_id -> node_name.
        Cached for the entire runtime (lru_cache maxsize=1).
        """
        nodes = self.get_api("/api/node/class/fabricNode.json") or []
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


    @staticmethod
    def print_tree(tree, label=None):
        if label:
            print(label)

        def walk(node, depth):
            indent = "  " * depth
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "_leaf":
                        for item in v:
                            print(f"{indent}{item}")
                    else:
                        print(f"{indent}{k}")
                        walk(v, depth + 1)
            elif isinstance(node, list):
                for item in node:
                    print(f"{indent}{item}")
            else:
                print(f"{indent}{node}")

        walk(tree, 0)

def handle_clean_command(apic, clean_cmd):
    # Cached data (only pulled once)

    # -------------------------------------------------------------------------
    # CLEAN VRF
    # -------------------------------------------------------------------------
    if clean_cmd == "vrf":
        print("Checking VRFs not attached to any BD or L3Out...\n")

        ctxs     = apic.cached_api("/api/node/class/fvCtx.json")
        l3_refs  = apic.cached_api("/api/node/class/l3extRsEctx.json")
        bd_refs  = apic.cached_api("/api/node/class/fvRsCtx.json")

        all_vrfs = {}
        for item in ctxs:
            parsed = parse_regex(RE_VRF, item["fvCtx"]["attributes"]["dn"])
            if parsed:
                all_vrfs.setdefault(parsed["tenant"], set()).add(parsed["vrf"])

        referenced = {}
        for ref_list, regex in [(bd_refs, RE_BD), (l3_refs, RE_L3OUT)]:
            for item in ref_list:
                key  = next(iter(item))
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
            apic.print_tree(tree)
        else:
            print("All VRFs are in use.")
        return

    # -------------------------------------------------------------------------
    # CLEAN BD (checking for BD's L3 Out & EPG references)
    # -------------------------------------------------------------------------
    if clean_cmd == "bd":
        print("Checking Bridge Domains not attached to any EPG or L3Out...\n")

        bds = apic.cached_api("/api/node/class/fvBD.json")  # Fetch all BDs
        epg_bd = apic.cached_api("/api/node/class/fvRsBd.json")  # EPG → BD references
        l3_sub = apic.cached_api("/api/node/class/l3extSubnet.json")  # L3Out Subnet references

        all_bds = {}
        used_bds = set()

        # Step 1: Collect all BDs by tenant
        for item in bds:
            parsed = parse_regex(RE_BD, item["fvBD"]["attributes"]["dn"])
            if parsed:
                tenant = parsed["tenant"]
                bd = parsed["bd"]
                all_bds.setdefault(tenant, set()).add(bd)

        # Step 2: Collect BDs used by EPGs (via fvRsBd)
        for item in epg_bd:
            attr = item["fvRsBd"]["attributes"]
            bd_name = attr.get("tnFvBDName")
            if bd_name:
                # Mark this BD as used
                used_bds.add(bd_name)

        # Step 3: Collect BDs used by L3Out Subnets (via l3extSubnet)
        for item in l3_sub:
            attr = item["l3extSubnet"]["attributes"]
            bd_name = attr.get("tnFvBDName")
            if bd_name:
                # Mark this BD as used
                used_bds.add(bd_name)

        # Step 4: Identify unused BDs for each tenant
        unused_bds = {
            tenant: sorted(bd_set - used_bds) for tenant, bd_set in all_bds.items()
        }

        # Step 5: Filter out tenants that have no unused BDs
        unused_bds = {tenant: bds for tenant, bds in unused_bds.items() if bds}

        # Step 6: Print only tenants that have unused BDs
        if unused_bds:
            apic.print_tree(unused_bds)
        else:
            print("No unused Bridge Domains found.")
        return


    # -------------------------------------------------------------------------
    # CLEAN EPG (no contract + no members + no static bindings)
    # -------------------------------------------------------------------------
    if clean_cmd == "epg":
        print("Checking EPGs without any contract, members, or static bindings...\n")

        epgs     = apic.cached_api("/api/node/class/fvAEPg.json")
        prov     = apic.cached_api("/api/node/class/fvRsProv.json")
        cons     = apic.cached_api("/api/node/class/fvRsCons.json")
        macs     = apic.cached_api("/api/node/class/fvMac.json")
        ips      = apic.cached_api("/api/node/class/fvIp.json")
        paths    = apic.cached_api("/api/node/class/fvRsPathAtt.json")

        all_epgs = {}
        for item in epgs:
            parsed = parse_regex(RE_EPG, item["fvAEPg"]["attributes"]["dn"])
            if parsed:
                all_epgs.setdefault(parsed["tenant"], {}).setdefault(parsed["ap"], set()).add(parsed["epg"])

        used = {}
        for ref_list in (prov, cons, macs, ips, paths):
            for item in ref_list:
                key  = next(iter(item))
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
            apic.print_tree(tree)
        else:
            print("All EPGs have contracts, members, or static bindings.")
        return

    # -------------------------------------------------------------------------
    # CLEAN EMPTY EPG (no IP/MAC/static bindings)
    # -------------------------------------------------------------------------
    if clean_cmd == "empty":
        print("Checking EPGs with no MAC, IP addresses, or static bindings...\n")

        epgs     = apic.cached_api("/api/node/class/fvAEPg.json")
        macs     = apic.cached_api("/api/node/class/fvMac.json")
        ips      = apic.cached_api("/api/node/class/fvIp.json")
        paths    = apic.cached_api("/api/node/class/fvRsPathAtt.json")

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
            apic.print_tree(tree)
        else:
            print("All EPGs have MAC, IP addresses, or static bindings.")
        return

    # -------------------------------------------------------------------------
    # CLEAN AAEP
    # -------------------------------------------------------------------------
    if clean_cmd == "aaep":
        print("Checking AAEPs not assigned anywhere...\n")

        aaeps    = apic.cached_api("/api/node/class/infraAttEntityP.json")
        aaep_ref = apic.cached_api("/api/node/class/infraRsAttEntP.json")

        all_aaeps = {item["infraAttEntityP"]["attributes"]["name"] for item in aaeps}
        used      = set()

        for item in aaep_ref:
            key = next(iter(item))
            tDn = item[key]["attributes"].get("tDn", "")
            m = RE_AAEP_TDN.search(tDn)
            if m:
                used.add(m.group(1))

        unused = sorted(all_aaeps - used)

        if unused:
            apic.print_tree({"Global": {"AAEPs": unused}})
        else:
            print("All AAEPs are assigned somewhere.")
        return

    # -------------------------------------------------------------------------
    # CLEAN VLAN POOL
    # -------------------------------------------------------------------------
    if clean_cmd == "vlan":
        print("Checking VLAN Pools not used by any Domain or AAEP...\n")

        pools    = apic.cached_api("/api/node/class/fvnsVlanInstP.json")
        pool_ref = apic.cached_api("/api/node/class/infraRsVlanNs.json")

        all_pools = {item["fvnsVlanInstP"]["attributes"]["name"] for item in pools}

        used = set()
        for item in pool_ref:
            tDn = item["infraRsVlanNs"]["attributes"].get("tDn", "")
            m = RE_VLAN_POOL_TDN.search(tDn)
            if m:
                used.add(m.group("pool"))

        unused = sorted(all_pools - used)

        if unused:
            apic.print_tree({"Global": {"vlan_pools": unused}})
        else:
            print("All VLAN Pools are referenced.")
        return

def handle_contract_command(apic, contract_name, tenant_filter=None):
    """
    Find all tenants owning a contract with this name, then
    run the existing code for each tenant individually.
    Uses apic.collect_epgs(), epg_tenant(), epg_label(), l3out_name_from_dn() for structured output.
    """

    print(f"Looking up contract: {contract_name}\n")

    # ----------------------------------------------------------------------
    # Cached API queries (only once)
    # ----------------------------------------------------------------------
    contracts = apic.cached_api("/api/node/class/vzBrCP.json")
    prov_epgs = apic.cached_api("/api/node/class/fvRsProv.json")
    cons_epgs = apic.cached_api("/api/node/class/fvRsCons.json")

    # ----------------------------------------------------------------------
    # Find all tenants that own a contract with this name
    # ----------------------------------------------------------------------
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
        
    # ----------------------------------------------------------------------
    # If exact contract not found, try prefix match (group by tenant)
    # ----------------------------------------------------------------------
    if not tenants:
        prefix_tree = {}

        for item in contracts:
            attr = item["vzBrCP"]["attributes"]
            name = attr["name"]
            dn = attr["dn"]
            tenant = dn.split("/")[1][3:]  # tn-XYZ → XYZ

            # Only include contracts that start with the prefix
            if name.startswith(contract_name):
                prefix_tree.setdefault(tenant, []).append(name)

        # If we found prefix matches inside (filtered) tenant(s)
        if prefix_tree:
            print(f"No exact match for contract '{contract_name}'.\n")

            # Sort tenants and contracts
            sorted_tree = {
                tenant: sorted(names)
                for tenant, names in sorted(prefix_tree.items())
            }

            apic.print_tree(sorted_tree)
            return

        # Nothing found even with prefix search
        print(f"❌ Contract '{contract_name}' not found.")
        return

    # ----------------------------------------------------------------------
    # Run logic once per tenant
    # ----------------------------------------------------------------------
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

        # Attach DN map to ACI client for helper functions
        apic.contract_dn_map = contract_dn_map

        # ----------------------------------------------------------------------
        # Exported contracts (only for global scope)
        # ----------------------------------------------------------------------
        exported_tree = {}
        if scope == "global":
            exported_tree = {"Exported to:": {}}
            dn = list(contract_dn_map.keys())[0]
            exported_contracts = apic.cached_api(
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
            # Sort CIF tenants and contracts
            for cif in exported_tree["Exported to:"]:
                exported_tree["Exported to:"][cif].sort()
            exported_tree["Exported to:"] = dict(sorted(exported_tree["Exported to:"].items()))

        # ----------------------------------------------------------------------
        # Providers & Consumers
        # ----------------------------------------------------------------------
        providers_map = apic.collect_epgs(prov_epgs, "fvRsProv")
        consumers_map = apic.collect_epgs(cons_epgs, "fvRsCons")

        # Convert provider/consumer maps into tree format
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

        # ----------------------------------------------------------------------
        # Final Output
        # ----------------------------------------------------------------------
        print(f"Type: {scope}\n")
        apic.print_tree(provider_tree)
        print()
        apic.print_tree(consumer_tree)
        if scope == "global":
            print()
            if exported_tree["Exported to:"]:
                apic.print_tree(exported_tree)

    if tenant_filter:
        handle_filter_command(apic, contract_name, tenant_filter)

def handle_tenant_command(apic, tenant_name):
    print(f"Looking for all bindings in tenant: {tenant_name}\n")

    # Cached API calls
    static_paths = apic.cached_api("/api/node/class/fvRsPathAtt.json")
    svi_paths    = apic.cached_api("/api/node/class/l3extRsPathL3OutAtt.json")

    static_tree = {}
    svi_tree = {}

    TENANT_PREFIX = f"uni/tn-{tenant_name}/"

    # -------------------------------------------------------------
    # Static EPG-to-Path Bindings
    # -------------------------------------------------------------
    for item in static_paths:
        attr = item.get("fvRsPathAtt", {}).get("attributes", {})
        dn   = attr.get("dn", "")

        if not dn.startswith(TENANT_PREFIX):
            continue

        tDn   = attr.get("tDn", "")
        encap = attr.get("encap", "")

        epg = parse_regex(RE_EPG_DN, dn)
        path = parse_regex(RE_PATH_TDN, tDn)

        if not epg or not path:
            continue


        apic.tree_add(
            static_tree,
            f"Pod-{path['pod']}",
            apic.normalize_node_label(path['pod'], path['node']),
            path['iface'],
            label=f"{epg['ap']}/{epg['epg']} ({encap})"
        )


    # -------------------------------------------------------------
    # SVI (L3Out) Bindings
    # -------------------------------------------------------------
    for item in svi_paths:
        attr = item.get("l3extRsPathL3OutAtt", {}).get("attributes", {})
        dn   = attr.get("dn", "")

        if not dn.startswith(TENANT_PREFIX):
            continue

        tDn   = attr.get("tDn", "")
        encap = attr.get("encap", "")

        l3 = parse_regex(RE_L3OUT_DN, dn)
        path = parse_regex(RE_PATH_TDN, tDn)

        if not l3 or not path:
            continue

        apic.tree_add(
            svi_tree,
            f"Pod-{path['pod']}",
            apic.normalize_node_label(path['pod'], path['node']),
            path['iface'],
            label=f"{l3['l3out']}/{l3['lifp']} ({encap})"
        )


    # -------------------------------------------------------------
    # Output
    # -------------------------------------------------------------
    if static_tree:
        print(f"\nStatic Path Bindings for tenant '{tenant_name}':")
        apic.print_tree(static_tree)
    else:
        print("\nNo static path bindings found.")

    if svi_tree:
        print(f"\nSVI (L3Out) Bindings for tenant '{tenant_name}':")
        apic.print_tree(svi_tree)
    else:
        print("\nNo SVI bindings found.")

def handle_ip_command(apic, ip_to_lookup):
    print(f"Looking up IP: {ip_to_lookup}\n")

    # -----------------------------
    # Cached API calls
    # -----------------------------
    fv_ip_data        = apic.cached_api(f"/api/node/class/fvIp.json?query-target-filter=eq(fvIp.addr,\"{ip_to_lookup}\")")
    l3ext_ip_data     = apic.cached_api("/api/node/class/l3extIp.json")
    bgp_peer_data     = apic.cached_api("/api/node/class/bgpPeer.json")
    static_routes     = apic.cached_api("/api/node/class/ipRouteP.json")
    subnets           = apic.cached_api("/api/node/class/fvSubnet.json")
    external_subnets  = apic.cached_api("/api/node/class/l3extSubnet.json")

    # -----------------------------
    # Process different types of matches
    # -----------------------------
    endpoint_found = apic.process_endpoint(fv_ip_data)
    ospf_found     = apic.process_peer(l3ext_ip_data, ip_to_lookup, kind="l3extIp")
    bgp_found      = apic.process_peer(bgp_peer_data, ip_to_lookup, kind="bgpPeer")
    static_found   = apic.process_static_route(static_routes, ip_to_lookup)

    # -----------------------------
    # If nothing found, check subnets
    # -----------------------------
    if not any([endpoint_found, ospf_found, bgp_found, static_found]):
        apic.process_subnet(subnets, ip_to_lookup)
        apic.process_external_subnet(external_subnets, ip_to_lookup)

def handle_port_command(apic, args):
    node_id = args.id
    node_name = args.name
    port = args.port
    port_str = f"eth{port}"

    # -----------------------------
    # Resolve pod and node
    # -----------------------------
    top_data = apic.cached_api("/api/node/class/topSystem.json")
    pod_id, node_id = apic.get_pod_for_node(top_data, node_id, node_name)
    if not pod_id:
        print(f"Error: Could not find pod for node {node_id} ({node_name})")
        exit(1)

    # -----------------------------
    # Fetch bindings (cached)
    # -----------------------------
    static_bindings = apic.cached_api("/api/node/class/fvRsPathAtt.json")
    svi_bindings = apic.cached_api("/api/class/l3extRsPathL3OutAtt.json")

    tree = {}

    # -----------------------------
    # Helper to process bindings
    # -----------------------------
    def process_bindings(bindings, regex, category_func, label_func):
        for item in bindings:
            # Extract attributes
            attr = next(iter(item.values()))['attributes']
            dn = attr.get("dn", "")
            tDn = attr.get("tDn", "")
            encap = attr.get("encap", "")

            # Check port match via tDn
            if f"topology/pod-{pod_id}/paths-{node_id}/pathep-[{port_str}]" not in tDn:
                continue

            # Parse DN using regex
            match = parse_regex(regex, dn)
            if match:
                tenant = match["tenant"]
                category = category_func(match)
                label = label_func(match, encap)
                apic.tree_add(tree, tenant, category, label=label)

    # -----------------------------
    # Process L2 (EPG) bindings
    # -----------------------------
    process_bindings(
        static_bindings,
        RE_EPG,
        category_func=lambda m: f"EPG: {m['ap']}",
        label_func=lambda m, encap: f"{m['epg']} ({encap})"
    )

    # -----------------------------
    # Process L3 (SVI / L3Out) bindings
    # -----------------------------
    process_bindings(
        svi_bindings,
        RE_L3OUT_PATH,
        category_func=lambda m: f"L3: {m['out']}",
        label_func=lambda m, encap: f"{m['lifp']} ({encap})"
    )

    # -----------------------------
    # Print results
    # -----------------------------
    device = apic.normalize_node_label(pod_id, node_id)
    if tree:
        print(f"\nBindings for {port_str} on {device}:")
        apic.print_tree(tree)
    else:
        print(f"\nNo bindings found for {port_str} on {device}.")

def handle_vpc_command(apic, args):
    nodes = args.nodes
    interface = args.interface
    tree = {}

    # -----------------------------
    # 1. Parse node pair
    # -----------------------------
    try:
        node1, node2 = map(int, nodes.split('-'))
    except ValueError:
        print(f"Error: Invalid node pair format '{nodes}'. Expected format: 221-222")
        exit(1)

    # -----------------------------
    # 2. Find pod ID
    # -----------------------------
    top_data = apic.cached_api("/api/node/class/topSystem.json")
    pod_id = None
    for item in top_data:
        attr = item.get("topSystem", {}).get("attributes", {})
        if attr.get("id") == str(node1):
            pod_id = attr.get("podId")
            break

    if not pod_id:
        print(f"Error: Could not find pod for node {node1}")
        exit(1)

    vpc_pattern = f"topology/pod-{pod_id}/protpaths-{node1}-{node2}/pathep-[{interface}]"


    # ----------------------------------------
    # If no interface specified, list all VPCs
    # ----------------------------------------
    if not interface:
        all_bindings = apic.cached_api("/api/node/class/fvRsPathAtt.json")
        vpc_list = set()

        vpc_prefix = f"topology/pod-{pod_id}/protpaths-{node1}-{node2}/pathep-["

        for item in all_bindings:
            attr = item.get("fvRsPathAtt", {}).get("attributes", {})
            tDn = attr.get("tDn", "")

            if vpc_prefix in tDn:
                # extract vpc name inside pathep-[XXX]
                vpc_name = tDn.split("pathep-[")[-1].split("]")[0]
                vpc_list.add(vpc_name)

        if vpc_list:
            print(f"\nVPCs on nodes {nodes}:")
            for vpc in sorted(vpc_list):
                    print(f"  {vpc}")
        else:
            print(f"\nNo VPCs found on nodes {nodes}.")

        return

    # -----------------------------
    # 3. L2 (Static Path) Bindings
    # -----------------------------
    static_bindings = apic.cached_api("/api/node/class/fvRsPathAtt.json")
    for item in static_bindings:
        attr = item.get("fvRsPathAtt", {}).get("attributes", {})
        tDn = attr.get("tDn", "")
        dn = attr.get("dn", "")
        encap = attr.get("encap", "")

        if vpc_pattern not in tDn:
            continue

        match = parse_regex(RE_EPG, dn)
        if match:
            tenant = match["tenant"]
            category = f"EPG: {match['ap']}"
            apic.tree_add(
                tree,
                tenant,
                category,
                label = f"{match['epg']} ({encap})"
            )


    # -----------------------------
    # 4. L3 (SVI / L3Out) Bindings
    # -----------------------------
    svi_bindings = apic.cached_api("/api/class/l3extRsPathL3OutAtt.json") 
    for item in svi_bindings:
        attr = item.get("l3extRsPathL3OutAtt", {}).get("attributes", {})
        tDn = attr.get("tDn", "")
        dn = attr.get("dn", "")
        encap = attr.get("encap", "")

        if vpc_pattern not in tDn:
            continue

        match = parse_regex(RE_L3OUT_PATH, dn)
        if match:
            tenant = match["tenant"]
            category = f"L3: {match['out']}"
            label = f"{match['lifp']} ({encap})"
            apic.tree_add(tree, tenant, category, label=label)


    # -----------------------------
    # 5. Print Results
    # -----------------------------
    device = apic.normalize_node_label(pod_id, nodes)
    if tree:
        print(f"\nBindings for VPC {interface} on {device[0]}:")
        apic.print_tree(tree)
    else:
        print(f"\nNo bindings found for VPC {interface} on {device[0]}.")

def handle_vlan_command(apic, vlan_id):
    tree = {}
    vlan_str = f"vlan-{vlan_id}"

    # -----------------------------
    # 1. EPG Bindings
    # -----------------------------
    epg_bindings = apic.get_api(
        f"/api/node/class/fvRsPathAtt.json?query-target-filter=eq(fvRsPathAtt.encap,\"{vlan_str}\")"
    )
    for item in epg_bindings:
        attr = item.get("fvRsPathAtt", {}).get("attributes", {})
        dn = attr.get("dn", "")
        encap = attr.get("encap", "")

        match = RE_EPG.search(dn)
        if match:
            tenant = match["tenant"]
            category = f"EPG: {match['ap']}"
            apic.tree_add(
                tree,
                tenant,
                category,
                label = f"{match['epg']} ({encap})"
            )

    # -----------------------------
    # 2. L3Out Bindings
    # -----------------------------
    l3out_paths = apic.get_api(
        f"/api/class/l3extRsPathL3OutAtt.json?query-target-filter=eq(l3extRsPathL3OutAtt.encap,\"{vlan_str}\")"
    )
    for item in l3out_paths:
        attr = item.get("l3extRsPathL3OutAtt", {}).get("attributes", {})
        dn = attr.get("dn", "")
        encap = attr.get("encap", "")

        match = RE_L3OUT_PATH.search(dn)
        if match:
            tenant = match["tenant"]
            category = f"L3: {match['out']}"
            apic.tree_add(
                tree,
                tenant,
                category,
                label = f"{match['lifp']} ({encap})"
            )

    # -----------------------------
    # 3. Dynamic EPG Members
    # -----------------------------
    endpoints = apic.get_api(
        f"/api/class/fvCEp.json?query-target-filter=eq(fvCEp.encap,\"{vlan_str}\")"
    )
    for item in endpoints:
        attr = item.get("fvCEp", {}).get("attributes", {})
        dn = attr.get("dn", "")
        encap = attr.get("encap", "")

        match = RE_CEP.search(dn)
        if match:
            tenant = match["tenant"]
            category = f"EPG: {match['ap']}"
            apic.tree_add(
                tree,
                tenant,
                category,
                label = f"{match['epg']} ({encap})"
            )


    # -----------------------------
    # 4. Print Results
    # -----------------------------
    if tree:
        print(f"\nVLAN {vlan_id} found in:")
        apic.print_tree(tree)
    else:
        print(f"\nVLAN {vlan_id} not found in any EPG or L3Out bindings.")

    # -----------------------------
    # 5. VLAN Pool Information
    # -----------------------------
    vlaninstp = apic.get_api("/api/class/fvnsVlanInstP.json")
    pools = apic.find_vlan_in_vlan_pools(vlaninstp, vlan_id)
    if pools:
        print(f"\nVLAN {vlan_id} found in pools:")
        for name, dn, v_from, v_to in pools:
            print(f"  {name} (range: {v_from}–{v_to})")
    else:
        print(f"\nVLAN {vlan_id} not found in any VLAN pools.")

def handle_filter_command(apic, contract_name, tenant_filter):
    print("")

    # Cached API queries
    contracts      = apic.cached_api("/api/node/class/vzBrCP.json")
    rs_subj_filt   = apic.cached_api("/api/node/class/vzRsSubjFiltAtt.json")
    filters        = apic.cached_api("/api/node/class/vzFilter.json")
    filter_entries = apic.cached_api("/api/node/class/vzEntry.json")
    subjects       = apic.cached_api("/api/node/class/vzSubj.json")

    # -----------------------------
    # Find contract DN in specified tenant
    # -----------------------------
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

    # -----------------------------
    # Collect filters assigned to this contract
    # -----------------------------
    used_filters = set()
    for subj_item in subjects:
        subj_attr = subj_item["vzSubj"]["attributes"]
        dn = subj_attr["dn"]
        if not dn.startswith(contract_dn + "/subj-"):
            continue

        # Follow the relationships from subject to filter (tDn)
        for rel in rs_subj_filt:
            rattr = rel.get("vzRsSubjFiltAtt", {}).get("attributes", {})
            if rattr.get("dn", "").startswith(dn):
                filter_name = rattr.get("tDn", "").split("/")[-1].replace("flt-", "")
                used_filters.add(filter_name)

    if not used_filters:
        print(f"⚠️ No filters attached to contract '{contract_name}'")
        return

    # -----------------------------
    # Build filter details
    # -----------------------------
    filters_detail_node = {}

    for f_item in filters:
        fattr = f_item.get("vzFilter", {}).get("attributes", {})
        f_name = fattr.get("name")
        f_dn   = fattr.get("dn")

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

    # -----------------------------
    # Print the result
    # -----------------------------
    tree = {contract_name: {"Filter Details": filters_detail_node}}
    apic.print_tree(tree)

def handle_subnet_command(apic, tenant_filter=None, prefix_filter=None):
    apic.list_all_subnets(tenant_filter, prefix_filter)

def main():
    load_dotenv()
    url = os.environ.get('APIC_URL')

    if not url:
        logger.error("APIC_URL environment variable not set")
        logger.info("Please set it in your .env file or environment")
        logger.info("Example: export APIC_URL=https://apic.example.com")
        exit(1)

    args = parse_args()
    apic = ACIClient(url)
    apic.login()

    if args.command == "ip":
        handle_ip_command(apic, args.ip)
    elif args.command == "port":
        handle_port_command(apic, args)
    elif args.command == "vpc":
        handle_vpc_command(apic, args)
    elif args.command == "vlan":
        handle_vlan_command(apic, int(args.vlan))
    elif args.command == "tenant":
        handle_tenant_command(apic, args.tenant)
    elif args.command == "clean":
        handle_clean_command(apic, args.clean_cmd)
    elif args.command == "contract":
        handle_contract_command(apic, args.contract, args.tenant)
    elif args.command == "subnet":
        handle_subnet_command(apic, args.tenant, args.prefix)

if __name__ == "__main__":
    main()
