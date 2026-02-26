# ACI Helper Toolkit

### *Operational CLI utilities for exploring and validating Cisco ACI fabrics*

This toolkit provides a collection of commands that query an ACI fabric using the APIC REST API through an `apic` client wrapper.
All commands share the same goals:

* Reduce time spent troubleshooting fabric bindings
* Make cleaning unused objects safe and visible
* Provide human-readable tree output

---

## Installation

There are two ways to install and use the ACI Tool:

### Option 1: Container Deployment (Recommended)

The easiest way to deploy this tool is using the provided container script. This will build a Docker/Podman container that handles all dependencies and creates an alias for easy command execution from the host.

#### Quick Start

1. **Configure your environment first:**
   ```bash
   git clone https://github.com/LoveSkylark/acitool.git
   cd acitool
   cp .env.example .env
   ```

2. **Edit the `.env` file with your APIC details:**
   ```bash
   # Required: Set your APIC URL
   APIC_URL=https://your-apic-url.com

   # Optional: Set credentials (if not set, you'll be prompted)
   APIC_USERNAME=admin
   APIC_PASSWORD=your-password
   ```

3. **Run the deployment script:**
   ```bash
   ./deploy_container.sh
   ```

**What this does:**
- Reads configuration from `.env` file
- Builds a Docker/Podman container with all required dependencies and your APIC URL
- Creates an alias `acitool` that executes commands from the host directly into the container
- Isolates the tool environment from your system Python installation
- No manual dependency management required

After deployment, simply use:
```bash
acitool <command> [args]
```

### Option 2: Manual Python Environment

If you prefer to run the tool directly with Python or want to customize the environment:

```bash
git clone https://github.com/LoveSkylark/acitool.git
cd acitool/scripts
python3 -m pip install -r requirements.txt
```

Then run commands directly:
```bash
python3 acitool.py <command> [args]
```

**Requirements:**
- Python 3.7+
- requests
- urllib3
- python-dotenv

---

## Configuration

### Environment Variables

The `.env` file in the project root is used for configuration and authentication.

**For Container Deployment:**
- **REQUIRED**: You must configure the `.env` file **before** running `deploy_container.sh`
- Copy `.env.example` to `.env` and set at minimum the `APIC_URL`
- The deployment script reads this file during container build

**For Manual Python Environment:**
- Create a `.env` file in the `acitool/scripts` directory
- Configuration is loaded at runtime

```bash
# Required
APIC_URL=https://your-apic-url.com

# Optional (not recommended for security)
APIC_USERNAME=your-username
APIC_PASSWORD=your-password
```

*If credentials are not set in `.env`, the script will prompt for them interactively.

### Token Caching

Authentication tokens are cached in `~/.aci_token` by default to avoid repeated logins.

---

# Usage

```bash
acitool <command> [args]
```

> **Note:** If using Option 2 (Manual Python), replace `acitool` with `python3 scripts/acitool.py` in all examples below.

### SSL Verification

By default, SSL certificate verification is disabled. To enable SSL verification, modify the `ACIClient` initialization in the script.

---

# Commands Overview

| Command                                                      | Description                                                                  |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `clean <type>`                                               | Find unused VRFs, BDs, EPGs, AAEPs, VLAN pools, etc.                         |
| `contract <name> [--tenant <tenant>]`                        | Show providers, consumers, scope and exports for a contract.                 |
| `tenant <tenant>`                                            | Show all static bindings and SVI bindings in that tenant.                    |
| `ip <address\|prefix> [-p X] [-t tenant]`                   | Look up endpoint, OSPF/BGP peer, static route, subnet or route table.        |
| `port <x/y> [-i <node-id>] [-n <name>]`                     | Show all bindings on a physical port (EPG + L3Out).                          |
| `vpc <nodeA>-<nodeB> [vpc-name]`                             | Show VPC interfaces or their bindings.                                       |
| `vlan <vlan-id>`                                             | Show all EPG/L3Out/CEp bindings and VLAN pool membership.                    |
| `subnet [filter] [--tenant T] [--prefix X]`                  | List all subnets in the fabric, optionally filtered by prefix or CIDR.       |
| `route <tenant>:<vrf> [filter] [-p X] [-l\|-x] [-d]`        | Show consolidated routing table for a VRF across all leaf nodes.             |


---

# CLEAN COMMANDS

Run:

```bash
acitool clean <vrf|bd|epg|empty|aaep|vlan|contract>
```

---

## `clean vrf`

Finds **VRFs with no BD and no L3Out attached**.

Output example:

```
tenantA
└── vrfs
    ├── VRF-UNUSED1
    └── VRF-UNUSED2
```

---

## `clean bd`

Finds **BDs with no EPG and no L3Out subnet**.

---

## `clean epg`

Finds **EPGs that are truly unused** - EPGs with:
- No contracts (provided or consumed)
- No MAC addresses
- No IP addresses
- No static path bindings

This command identifies EPGs that can be safely removed without affecting any traffic or configuration.

---

## `clean empty`

Finds **EPGs with no active endpoints** - EPGs with:
- No MAC addresses
- No IP addresses
- No static path bindings

This command shows EPGs that may have contracts configured but have no actual endpoints or static bindings. They might be intentionally reserved or genuinely unused.

---

## `clean aaep`

Finds **AAEPs not mapped to any interface or domain**.

---

## `clean vlan`

Finds **VLAN pools that are not referenced by any domain or AAEP**.

---

## `clean contract`

Finds **contracts with missing or incomplete assignments**. This command identifies three categories of potentially problematic contracts:

1. **Contracts with NO provider AND NO consumer** - Completely unused contracts that can likely be removed
2. **Contracts with ONLY provider (no consumer)** - Services are being provided but nobody is consuming them
3. **Contracts with ONLY consumer (no provider)** - EPGs are trying to consume a service but nobody is providing it

The command checks both EPG-level and vzAny-level provider/consumer relationships, and correctly handles contracts in the "common" tenant that are consumed/provided by EPGs in other tenants.

Output example:

```
================================================================================
Contracts with NO provider AND NO consumer:
================================================================================

tenant1:
  - unused-contract-1
  - unused-contract-2

================================================================================
Contracts with ONLY provider (no consumer):
================================================================================

tenant2:
  - orphaned-provider

================================================================================
Contracts with ONLY consumer (no provider):
================================================================================

tenant3:
  - missing-provider
```

---

# ROUTE COMMAND

```bash
acitool route <tenant>:<vrf> [filter] [-p PREFIX] [-l|-x] [-d]
```

Shows a **consolidated IPv4 routing table** for a VRF, aggregated across all leaf nodes. Routes that exist on multiple leaves are shown as a single entry with all leaf node IDs listed.

Infrastructure routes (`direct`, `local`, `am`, `broadcast`, `urib_internal`) and routes via the ACI internal `overlay-1` transport are hidden by default.

### Output example:

```
Routing table for VRF myTenant:myVRF

Prefix                 Proto          Via              Leafs
-----------------------------------------------------------------------
0.0.0.0/0              ospf           10.10.10.1       201, 202
10.1.0.0/24            ospf           10.10.10.1       201, 202
10.2.0.0/24            static         10.20.0.1        201
192.168.1.0/30         ospf           10.10.10.2       201, 202

Total: 4 prefix(es) across 2 leaf(s): 201, 202
```

### Filtering Options:

- **filter** (positional, optional): Filter routes by string prefix or CIDR containment
  - String prefix: `acitool route myTenant:myVRF 10.1` shows routes starting with `10.1`
  - CIDR subnet: `acitool route myTenant:myVRF 10.0.0.0/8` shows routes within that subnet

- **-p / --prefix**: Filter by subnet mask length
  - Example: `acitool route myTenant:myVRF -p /32` shows only host routes

- **-l / --local**: Show only routes native to this VRF — excludes routes imported from other VRFs/tenants via contracts. `-l` and `-x` are mutually exclusive.

- **-x / --external**: Show only routes imported from other VRFs or tenants via contracts. Useful for auditing what has been leaked into this VRF. `-l` and `-x` are mutually exclusive.

- **-d / --detail**: Include all infrastructure routes (`direct`, `local`, `am`, `broadcast`, `urib_internal`, overlay-1 TEP routes)

---

# CONTRACT COMMAND

```bash
acitool contract <contract-name> [--tenant TENANT] [-f]
```

### Features:

- Finds contract across all tenants
- If not found: prefix-search by tenant
- Shows providers & consumers
- Marks imported providers/consumers
- If contract is **global**, shows exported tenants
- If `--tenant` is specified the command will show filter entries
- `-f` / `--filters`: Show only the filter entries (subjects and filter rules), skipping providers/consumers

---

# TENANT COMMAND

```bash
acitool tenant <tenant>
```

Shows:

### Static path bindings (EPG → interface)

Grouped by **Pod → Node → Interface**.

### SVI bindings (L3Out → interface)

Again grouped by pod/node/interface.

---

# IP LOOKUP

```bash
acitool ip <address|prefix> [-p PREFIX] [-t TENANT]
```

Searches the ACI fabric for any object associated with a given IP address or IP string prefix. Accepts either a **full IP address** or a **partial string prefix** (e.g., `10.5.1`).

### Full IP lookup

When a complete IP address is provided, the tool searches in priority order:

1. **Endpoint** (fvIp) — the host is learned in an EPG; shows tenant, app profile, EPG, pod/node and interface selector
2. **OSPF neighbor** (l3extIp) — the IP is an OSPF interface address on an L3Out
3. **BGP peer** (bgpPeer) — the IP is a configured BGP peer
4. **Static route** (ipRouteP) — the IP falls within a configured static route prefix
5. **Internal subnet** (fvSubnet) — shown only when none of the above match; the IP falls inside a BD or EPG subnet
6. **External L3Out subnet** (l3extSubnet) — shown only when none of the above match; the IP falls inside an L3Out external subnet
7. **Route table** (uribv4Route) — always shown; lists every VRF routing table entry that contains the IP

### Prefix lookup

When a partial string is provided (e.g., `10.5.1`), the tool:

- Searches for endpoints whose IP starts with the given string
- Shows all BD/EPG subnets whose IP starts with the given string
- Shows all L3Out external subnets whose IP starts with the given string
- Shows all routing table entries whose prefix starts with the given string

### Options

- **-p / --prefix**: Filter all results to a specific subnet mask length
  - Example: `acitool ip 10.5 -p /32` shows only host routes and /32 endpoint subnets
  - Example: `acitool ip 10.5.1.1 -p /24` restricts route table to /24 entries

- **-t / --tenant**: Limit the search to a single tenant
  - Example: `acitool ip 10.5.1.1 -t myTenant` shows only results belonging to `myTenant`
  - Applies to all result types: endpoints, peers, static routes, subnets and route table entries

### Examples

```bash
acitool ip 10.5.1.1                       # full IP lookup across all tenants
acitool ip 10.5.1.1 -t myTenant           # limit to a single tenant
acitool ip 10.5.1.1 -p /32               # only show /32 entries in route table
acitool ip 10.5.1.1 -t myTenant -p /32   # combine tenant and prefix filters
acitool ip 10.5.1                         # prefix search — all objects starting with 10.5.1
acitool ip 10.5 -p /24                   # prefix search, only /24 subnets and routes
```

### Output example (full IP)

```
Looking up IP: 10.5.1.60

IP found in:
  myTenant
    AP:MyApp
      WebEPG

  Physical location: Pod-1, Node-201 MAC:[00:50:56:A8:CA:E3]
  Interface Selector: eth1/1

Route lookup across all VRFs:
myTenant
  VRF: myVRF
    10.5.1.0/24
    10.5.1.60/32
```

---

# PORT LOOKUP

```bash
acitool port <x/y> -i <node-id>
acitool port <x/y> -n <node-name>
```

Shows **all EPG and L3Out bindings on a physical access port**. The node can be identified by numeric ID (`-i`) or by hostname (`-n`).

Both commands show the same information — use whichever identifier is more convenient.

Output is grouped by **tenant → AP/L3Out → EPG/interface (VLAN encap)**.

### Output example:

```
Bindings for eth1/1 on pod-1/node-201:

myTenant
├── EPG: myAppProfile
│   └── myEPG (vlan-100)
└── L3: myL3Out
    └── myInterface (vlan-200)
```

### Examples:

```bash
acitool port 1/1 -i 201          # by node ID
acitool port 1/1 -n leaf-201     # by node name
```

---

# VPC LOOKUP

`acitool vpc` does the same as `acitool port` but for **VPC (port-channel) interfaces** which span two leaf nodes.

```bash
acitool vpc <nodeA>-<nodeB>
acitool vpc <nodeA>-<nodeB> <vpc-name>
```

### List all VPCs on a node pair:

```bash
acitool vpc 201-202
```

Prints all VPC interface names configured on that leaf pair:

```
VPCs on nodes 201-202:
  vpc-server-01
  vpc-server-02
  vpc-firewall
```

Use this to discover VPC names before drilling into a specific one.

### Show bindings on a specific VPC:

```bash
acitool vpc 201-202 myVPC
```

Shows all EPG static path bindings and L3Out SVI bindings on that VPC, grouped by **tenant → AP/L3Out → EPG/interface (VLAN encap)**.

### Output example:

```
Bindings for VPC myVPC on 201-202:

myTenant
├── EPG: myAppProfile
│   └── myEPG (vlan-100)
└── L3: myL3Out
    └── myInterface (vlan-200)
```

---

# VLAN LOOKUP

```bash
acitool vlan <vlan-id>
```

Shows:

* EPG bindings (static paths)
* L3Out bindings
* Dynamic CEp bindings
* VLAN pool membership & ranges

---


# SUBNET LISTING

```bash
acitool subnet
acitool subnet 10.5.1
acitool subnet 10.1.0.0/16
acitool subnet 192.168.0.0/16 --tenant TenantA
acitool subnet --prefix /30
acitool subnet 10.0.0.0/8 --prefix /24
```

Shows all subnets in the fabric, including:
- Bridge Domain subnets (fvSubnet)
- L3Out external subnets (l3extSubnet)

### Filtering Options:

- **filter** (positional, optional): Filter subnets by string prefix or CIDR containment
  - **String prefix**: `acitool subnet 10.5.1` shows all subnets whose IP starts with `10.5.1`
  - **CIDR range**: `acitool subnet 10.1.0.0/16` shows only subnets within `10.1.0.0/16`
  - CIDR filtering automatically handles IPv4/IPv6 version matching (IPv6 subnets are skipped when filtering by IPv4, and vice versa)

- **--tenant**: Filter by tenant name
  - Example: `acitool subnet --tenant Production`

- **--prefix**: Filter by subnet mask length
  - Example: `acitool subnet --prefix /24` shows only /24 subnets

Filters can be combined to narrow results further.

---

# Troubleshooting

## Authentication Issues

**Problem**: "Failed to authenticate"
**Solution**:
- Verify APIC_URL, APIC_USERNAME, APIC_PASSWORD in .env file
- Ensure APIC is reachable from your network
- Check firewall rules and network connectivity
- Verify credentials are correct

## SSL Certificate Warnings

**Problem**: SSL certificate verification warnings
**Solution**:
- SSL verification is disabled by default for self-signed certificates
- To enable verification: Set `verify_ssl=True` in ACIClient initialization
- Install proper CA certificates if using self-signed certs

## Connection Timeouts

**Problem**: Requests timing out
**Solution**:
- The script includes automatic retry logic (3 attempts)
- Check network connectivity to APIC
- Verify APIC is not overloaded
- Consider increasing timeout values in the code

## Empty Results

**Problem**: Commands return no results
**Solution**:
- Verify you have proper RBAC permissions in APIC
- Check if the queried objects actually exist in the fabric
- Review tenant/object names for typos
- Use the `--help` flag to verify command syntax

---

# Examples

## Find all unused EPGs in a specific tenant

```bash
acitool clean epg
```

## Check all bindings on a specific port

```bash
acitool port 1/1 -i 201
acitool port 1/1 -n leaf1
```

## Find what VLAN pools contain VLAN 100

```bash
acitool vlan 100
```

## Look up where an IP address is used

```bash
acitool ip 10.1.1.1
```

## Look up an IP restricted to a single tenant

```bash
acitool ip 10.1.1.1 -t myTenant
```

## Find all objects in the fabric starting with an IP prefix

```bash
acitool ip 10.1.1
```

## Show only /32 host routes for an IP

```bash
acitool ip 10.1.1.1 -p /32
```

## Show all contracts in a tenant with their filters

```bash
acitool contract web-contract --tenant production
```

## Show routing table for a VRF

```bash
acitool route myTenant:myVRF
```

## Show only /32 host routes in a VRF

```bash
acitool route myTenant:myVRF -p /32
```

## Find all routes within a specific subnet

```bash
acitool route myTenant:myVRF 10.0.0.0/8
```

## Find all VPC interfaces on node pair

```bash
acitool vpc 201-202
```

## List all L3Out subnets in a specific tenant

```bash
acitool subnet --tenant external
```

## Find all subnets starting with a string prefix

```bash
acitool subnet 10.5.1
```

## Find all subnets within a specific CIDR range

```bash
acitool subnet 192.168.0.0/16
```

## Find all /24 subnets within the 10.0.0.0/8 range

```bash
acitool subnet 10.0.0.0/8 --prefix /24
```

---

# Security Considerations

- **Token Storage**: Authentication tokens are stored in `~/.aci_token` with default file permissions. Ensure proper file system permissions in production.
- **SSL Verification**: Disabled by default for convenience with self-signed certificates. Enable in production environments.
- **RBAC**: Ensure the APIC user has appropriate read permissions for queried objects.

