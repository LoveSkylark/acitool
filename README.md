# ACI Helper Toolkit

### *Operational CLI utilities for exploring and validating Cisco ACI fabrics*

This toolkit provides a collection of commands that query an ACI fabric using the APIC REST API through an `apic` client wrapper.
All commands share the same goals:

* Reduce time spent troubleshooting fabric bindings
* Make cleaning unused objects safe and visible
* Provide human-readable tree output

---

## Installation

```bash
git clone <your-repo>
cd python
python3 -m pip install -r requirements.txt
```

### Requirements

- Python 3.7+
- requests
- urllib3
- python-dotenv (optional, for environment-based authentication)

---

## Configuration

### Environment Variables

Create a `.env` file in the project root for automatic authentication:

```bash
APIC_URL=https://your-apic-url.com
*APIC_USERNAME=your-username #(Optional, not recomeneded)
*APIC_PASSWORD=your-password #(Optional, not recomeneded)
```

*If environment variables are not set, the script will prompt for credentials interactively.

### Token Caching

Authentication tokens are cached in `~/.aci_token` by default to avoid repeated logins.

---

# Usage

```bash
python3 acitool.py <command> [args]
```

### SSL Verification

By default, SSL certificate verification is disabled. To enable SSL verification, modify the `ACIClient` initialization in the script.

---

# Commands Overview

| Command                                    | Description                                                  |
| ------------------------------------------ | ------------------------------------------------------------ |
| `clean <type>`                             | Find unused VRFs, BDs, EPGs, AAEPs, VLAN pools, etc.         |
| `contract <name> [--tenant <tenant>]`      | Show providers, consumers, scope and exports for a contract. |
| `tenant <tenant>`                          | Show all static bindings and SVI bindings in that tenant.    |
| `ip <address>`                             | Look up endpoint, OSPF/BGP peer, static route or subnet.     |
| `port --id X --port Y`                     | Show all bindings on a physical port (EPG + L3Out).          |
| `vpc --nodes A-B [--interface vpc-name]`   | Show VPC interfaces or their bindings.                       |
| `vlan <vlan-id>`                           | Show all EPG/L3Out/CEp bindings and VLAN pool membership.    |
| `subnet [--tenant T] [--prefix X]`         | List all subnets in the fabric.                              |


---

# CLEAN COMMANDS

Run:

```bash
python3 acitool.py clean <vrf|bd|epg|empty|aaep|vlan>
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

# CONTRACT COMMAND

```bash
python3 acitool.py contract <contract-name> [--tenant TENANT]
```

### Features:

- Finds contract across all tenants
- If not found: prefix-search by tenant
- Shows providers & consumers
- Marks imported providers/consumers
- If contract is **global**, shows exported tenants
- If `tenant` is specified the command will show filter entries

---

# TENANT COMMAND

```bash
python3 acitool.py tenant <tenant>
```

Shows:

### Static path bindings (EPG → interface)

Grouped by **Pod → Node → Interface**.

### SVI bindings (L3Out → interface)

Again grouped by pod/node/interface.

---

# IP LOOKUP

```bash
python3 acitool.py ip <ip-address>
```

Finds:

* Endpoint IP (fvIp)
* OSPF neighbors
* BGP peers
* Static routes
* Internal subnets
* External L3Out subnets

---

# PORT LOOKUP

```bash
python3 acitool.py port --id <node> --port <x/y>
```

Shows **all bindings on physical port ethX/Y**:

* EPG static path binds
* L3Out SVI bindings

Grouped by tenant and AP/L3Out.

---

# VPC LOOKUP

## List VPCs on node pair:

```bash
python3 acitool.py vpc --nodes 221-222
```

## Show bindings on a specific VPC:

```bash
python3 acitool.py vpc --nodes 221-222 <vpc_name>
```

Shows EPG and L3Out bindings.

---

# VLAN LOOKUP

```bash
python3 acitool.py vlan <vlan-id>
```

Shows:

* EPG bindings (static paths)
* L3Out bindings
* Dynamic CEp bindings
* VLAN pool membership & ranges

---


# SUBNET LISTING

```bash
python3 acitool.py subnet
python3 acitool.py subnet --tenant TenantA
python3 acitool.py subnet --prefix /30
```

Shows all subnets in the fabric, including:
- Bridge Domain subnets (fvSubnet)
- L3Out external subnets (l3extSubnet)

Filters can be applied by tenant or prefix pattern.

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
python3 scripts/aci.py clean epg
```

## Check all bindings on a specific port

```bash
python3 scripts/aci.py port 1/10 --id 201
```

## Find what VLAN pools contain VLAN 100

```bash
python3 scripts/aci.py vlan 100
```

## Look up where an IP address is used

```bash
python3 scripts/aci.py ip 10.1.1.1
```

## Show all contracts in a tenant with their filters

```bash
python3 scripts/aci.py contract web-contract --tenant production
```

## Find all VPC interfaces on node pair

```bash
python3 scripts/aci.py vpc 201-202
```

## List all L3Out subnets in a specific tenant

```bash
python3 scripts/aci.py subnet --tenant external
```

---

# Security Considerations

- **Token Storage**: Authentication tokens are stored in `~/.aci_token` with default file permissions. Ensure proper file system permissions in production.
- **SSL Verification**: Disabled by default for convenience with self-signed certificates. Enable in production environments.
- **RBAC**: Ensure the APIC user has appropriate read permissions for queried objects.

