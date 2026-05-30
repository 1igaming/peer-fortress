# Peer Fortress (milestone-0)

Operator-local tooling that turns a Monero node's `sync_info` peer list into a **diversity score** and actionable warnings. No consensus changes, no network-wide crawl.

This is **alpha / milestone-0** — a proof of concept for the Peer Fortress CCS proposal. Tor egress health checks, spy heuristics, playbooks, and monerosim scenarios are planned in funded milestones.

## Problem

Home nodes running default `monerod` configs can end up peer-heavy on a single subnet. Core mitigations help ([PR #9939](https://github.com/monero-project/monero/pull/9939), DNS blocklists), but operators still lack a local tool that answers: *"Is my peer set dangerously concentrated right now?"*

[ProbeLab !667](https://repo.getmonero.org/monero-project/ccs-proposals/-/merge_requests/667) measures network-wide topology. Peer Fortress is the **local complement**: diversity scoring on **your node only**.

## Quick start (mock mode — no daemon)

```powershell
cd G:\Monero-CC\repos\peer-fortress
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m peer_fortress
```

Expected output includes a score, bucket breakdown, and warnings for subnet concentration / duplicate hosts.

JSON output:

```powershell
python -m peer_fortress --json
```

## Live RPC mode (stagenet / testnet)

Start `monerod` on stagenet or testnet with RPC enabled (default bind `127.0.0.1`).

| Network | Default RPC port |
|---------|------------------|
| Mainnet | 18081 |
| Stagenet | 38081 |
| Testnet | 28081 |

```powershell
# Stagenet example — no full sync required for peer list once connected
python -m peer_fortress --rpc http://127.0.0.1:38081/json_rpc

# If monerod runs behind Tor proxy, expect .onion peers:
python -m peer_fortress --rpc http://127.0.0.1:38081/json_rpc --expect-tor
```

**Note:** A syncing node may report few peers; the score is less meaningful until P2P is warm.

## Custom fixture

```powershell
python -m peer_fortress --mock path\to\saved_sync_info.json
```

Save a fixture from live RPC:

```powershell
curl -s http://127.0.0.1:38081/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"sync_info"}' > my_sync_info.json
```

## What the score means

Heuristic only — not a security guarantee.

| Signal | Effect |
|--------|--------|
| >50% peers in one /24 (or /48 for IPv6) | Large penalty |
| Low bucket spread vs peer count | Penalty |
| Duplicate host entries | Penalty |
| Low .onion ratio when `--expect-tor` | Penalty |
| Fewer than 8 peers | Warning + small penalty |

Grades: **good** (80+), **fair** (60–79), **weak** (40–59), **poor** (<40).

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Roadmap (funded CCS milestones)

1. CLI + diversity scoring + testnet demo *(this repo — milestone-0)*
2. Spy heuristics (Rucknium / MRL #1124 citations) + Tor egress health module
3. Read-only playbook suggestions + optional local UI
4. monerosim scenario pack (coordinate with Gingeropolous)

## License

MIT — see [LICENSE](LICENSE).

## Non-goals

- No monerod consensus or wallet protocol changes
- No network-wide telemetry or dashboards
- No I2P SAMv3 implementation (see jpk68 WIP)
- No auto-applied banlists — human approval required for any live config change
