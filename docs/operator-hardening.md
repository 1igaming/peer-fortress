# Operator Hardening Guide

> **Advisory only.** Peer Fortress never applies changes automatically.
> Every command in this guide requires human review and explicit operator execution.

---

## Overview

This guide helps Monero node operators minimize eclipse, sybil, and traffic-analysis risk
at the network layer. It is aligned with Peer Fortress milestone deliverables and draws
on research from [Rucknium / MRL Issue #1124](https://github.com/monero-project/research-lab/issues/1124)
and public Monero Research Lab discussions.

---

## 1. Minimum Baseline Configuration

### 1.1 Enable Tor SOCKS5 proxy

```ini
# monerod.conf (or CLI flags)
proxy=127.0.0.1:9050
anonymous-inbound=<your-v3-onion-address>:18083,127.0.0.1:18083
```

**Why:** Without a Tor proxy, your node reveals its public IP to every peer and
cannot form `.onion` connections, making subnet-level eclipse attacks trivial.

### 1.2 Set an explicit out-peers limit

```ini
out-peers=16
in-peers=32
```

**Why:** The default unconstrained in-peer slots allow an adversary to flood all
incoming connections. Capping in-peers limits sybil surface.

### 1.3 Use `--add-priority-node` for anchor peers

```ini
add-priority-node=<known-good-node-1>:18080
add-priority-node=<known-good-node-2>:18080
```

**Why:** Priority nodes are always maintained regardless of the peer list state.
They serve as sybil-resistant anchors that survive peer-list flooding.

> **Verify independently:** Never copy `.onion` or IP addresses from untrusted
> sources. Cross-reference with the [Monero community peer list](https://www.getmonero.org/resources/developer-guides/daemon-rpc.html).

---

## 2. Running Peer Fortress

### 2.1 Install

```bash
git clone https://github.com/1igaming/peer-fortress
cd peer-fortress
pip install -e .
```

### 2.2 Live RPC analysis

```bash
python -m peer_fortress --rpc http://127.0.0.1:18081/json_rpc --report
```

### 2.3 Save JSON for dashboard

```bash
python -m peer_fortress --rpc http://127.0.0.1:18081/json_rpc --json > report.json
```

Open `ui/index.html` in a browser and click **Load JSON** to view the dashboard.

### 2.4 Check Tor proxy health

```bash
python -m peer_fortress --tor-check
```

Expected output: `REACHABLE | latency=XX ms`

### 2.5 Automated monitoring (cron example)

```cron
# Run Peer Fortress every 15 minutes, save timestamped reports
*/15 * * * * python -m peer_fortress --rpc http://127.0.0.1:18081/json_rpc --json >> /var/log/peer-fortress/$(date +\%Y\%m\%d_\%H\%M).json 2>&1
```

---

## 3. Interpreting Scores

| Score    | Grade  | Action Required                                              |
|----------|--------|--------------------------------------------------------------|
| 80–100   | GOOD   | Routine monitoring only. Re-check after major events.        |
| 60–79    | FAIR   | Review warnings. Consider adding diverse priority nodes.     |
| 40–59    | WEAK   | Act on subnet concentration. Follow subnet playbook.         |
| 0–39     | POOR   | Urgent. Node may be partially or fully eclipsed. Act now.    |

### 3.1 Spy Saturation Score

| Spy Score | Interpretation                                              |
|-----------|-------------------------------------------------------------|
| 0–20      | Clean — no suspicious clustering detected.                  |
| 21–50     | Monitor — some uniformity or subnet overlap.                |
| 51–79     | Warning — multiple heuristics triggered. Review signals.    |
| 80–100    | Critical — potential active sybil flood. Execute playbooks. |

---

## 4. Threat Response Playbooks

Playbooks are generated automatically in the dashboard (**Playbooks** tab)
and via the CLI. **No changes are applied automatically.**

### 4.1 Subnet Concentration (Eclipse)

Triggered when any `/24` subnet holds > 35% of connections.

1. Run `--json` and identify IPs in the hot subnet.
2. Add 3+ priority nodes from **distinct** `/24` subnets before any banning.
3. After confirming the new peers connected, optionally ban the hot-subnet IPs
   manually (edit `monerod.conf` ban_list — requires daemon restart).
4. Re-run Peer Fortress after 30 minutes to confirm recovery.

### 4.2 Duplicate Pruning Seeds (Sybil Flood)

Triggered when multiple peers share a non-zero `pruning_seed`.

> **Context:** Pruning seeds are assigned randomly per node. Identical active
> seeds across distinct IPs strongly indicate co-administration. (Rucknium / MRL #1124)

1. Export the full JSON and list IPs sharing the duplicate seed.
2. Anchor to 3+ trusted priority nodes first.
3. Ban the sybil IPs after operator confirmation.
4. Monitor for 24 hours and report to [getmonero.org/forum](https://forum.getmonero.org) if persistent.

### 4.3 Uniform Support Flags

Triggered when > 80% of clearnet peers share identical `support_flags`.

Standard `monerod` nodes almost never share bit-identical flags at scale.
This pattern is characteristic of scripted, uniform sybil deployments.

1. Check if nodes are well-known relays (large pools can share flags legitimately).
2. If unexplained, add diverse priority nodes and monitor flag distribution improvement.

---

## 5. Tor Egress Hardening

### 5.1 Verify Tor is actually routing traffic

```bash
# Check Tor is accepting SOCKS connections
python -m peer_fortress --tor-check --report

# Verify monerod is using the proxy
grep "proxy" /path/to/monerod.conf
```

### 5.2 Improve `.onion` peer ratio

Target: **≥ 15% `.onion` peers** when running with `--proxy`.

Add known v3 onion seed peers:
```ini
# In monerod.conf — verify each address independently before adding
add-peer=<v3-onion-address>.onion:18080
```

### 5.3 Anonymous inbound configuration

```ini
# Allow inbound .onion connections — generates a v3 hidden service
anonymous-inbound=<your-v3-onion>:18083,127.0.0.1:18083
```

Your node's v3 onion address is displayed at startup:
```
[I TIMESTAMP] **********************************************************************
[I TIMESTAMP] ANONYMOUS INBOUND:  <address>.onion:18083  127.0.0.1:18083
[I TIMESTAMP] **********************************************************************
```

---

## 6. Firewall and System Hardening

### 6.1 Limit exposed ports

Only the following ports should be reachable from the internet:

| Port  | Purpose                        | Exposure           |
|-------|--------------------------------|--------------------|
| 18080 | P2P (clearnet)                 | Internet (optional)|
| 18083 | Anonymous inbound (Tor only)   | Localhost only     |
| 18081 | JSON-RPC                       | **Localhost only** |
| 18082 | ZMQ (if enabled)               | **Localhost only** |

> **Critical:** Never expose port 18081 (JSON-RPC) to the internet without
> firewall restrictions and authentication. This allows arbitrary wallet operations.

### 6.2 Systemd hardening (Linux)

```ini
[Service]
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/monero
NoNewPrivileges=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=
```

### 6.3 Log monitoring

Key log patterns to watch for:
```
# Peer connection storm
grep "New connection" /var/log/monero.log | wc -l

# Rapid peer churn
grep "CLOSE connection" /var/log/monero.log | tail -50

# Tor proxy failures
grep "SOCKS5\|proxy" /var/log/monero.log | grep -i "fail\|error"
```

---

## 7. Scheduled Review Cadence

| Interval    | Action                                                           |
|-------------|------------------------------------------------------------------|
| Every 15min | Automated Peer Fortress JSON report (cron)                       |
| Daily       | Review dashboard — check score trend and spy saturation          |
| Weekly      | Review top subnets — rotate stale priority nodes if needed       |
| After events| Re-run after network upgrades, hard forks, or security disclosures|

---

## 8. Reporting Network Threats

If you detect a sustained sybil campaign (duplicate pruning seeds persisting > 24h,
subnet concentration not resolving with new peers):

1. Export the Peer Fortress JSON report.
2. Anonymize your own node's onion address and IP before sharing.
3. Post to [Monero Research Lab (MRL)](https://github.com/monero-project/research-lab/issues)
   or the [Monero Community Forum](https://forum.getmonero.org).
4. Reference Rucknium's P2P Sybil research and MRL Issue #1124 for context.

---

## 9. Non-Goals

Peer Fortress is **explicitly not** designed to:

- Auto-apply banlists or modify node configuration.
- Perform network-wide crawls or macro telemetry.
- Replace or conflict with monerod's built-in peer management.
- Make consensus or wallet protocol changes.

All remediation is human-approved and manually executed.

---

## References

- [Rucknium — P2P Sybil Research / MRL #1124](https://github.com/monero-project/research-lab/issues/1124)
- [monerod P2P documentation](https://monerodocs.org/interacting/monerod-reference/)
- [Dandelion++ — Monero transaction propagation privacy](https://getmonero.org/resources/moneropedia/dandelion.html)
- [Tor Project — v3 Onion Services](https://community.torproject.org/onion-services/setup/)
- [Monero Community Forum](https://forum.getmonero.org)
- [Peer Fortress CCS Proposal](https://github.com/1igaming/peer-fortress/issues/1)
