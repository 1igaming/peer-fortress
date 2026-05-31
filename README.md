# Peer Fortress (milestone-0)

Operator-local tooling that turns a Monero node's `sync_info` peer list into a **diversity score** and actionable warnings. No consensus changes, no network-wide crawl.

This is **alpha / milestone-0** — a proof of concept for the **[Peer Fortress — Tor & Eclipse Defense](https://github.com/1igaming/peer-fortress/issues/1)** CCS proposal (62 XMR, 4 months). Tor egress health checks, spy heuristics, playbooks, and monerosim scenarios are planned in funded milestones M1–M4. See [ROADMAP.md](ROADMAP.md).

**v0.3.0:** JSON schema validation, rotation advisory, `--out` flag. Release: https://github.com/1igaming/peer-fortress/releases/tag/v0.3.0

**Related:** complements [ProbeLab P2P metrics (!667)](https://repo.getmonero.org/monero-project/ccs-proposals/-/merge_requests/667) with **per-node** scoring, not network-wide telemetry.

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

### Demo output (mock fixture)

```
Peer Fortress v0.1.1-milestone0 — diversity report
Score: 72/100 (fair)
Peers: 12 total | 0 .onion | 12 clearnet
Buckets: 8 unique | max concentration 33% in 192.168.1.0/24
Warnings:
  - More than 25% of peers share one /24 bucket (192.168.1.0/24)
Top buckets:
  192.168.1.0/24: 4
  10.0.0.0/24: 2
  ...

Source: peer_fortress/fixtures/sample_sync_info.json
```

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

## Tor SOCKS5 health check (milestone-0 stub)

When `monerod` runs behind Tor (`--proxy`), verify the local SOCKS5 port before trusting `.onion` peer ratios:

```powershell
python -m peer_fortress --tor-check
python -m peer_fortress --tor-check --socks-host 127.0.0.1 --socks-port 9050 --json
```

Exit code `0` = handshake OK, `1` = proxy down or misconfigured.

## Extended report (`--report`)

```powershell
python -m peer_fortress --report
python -m peer_fortress --tor-check --report
```

Produces a formatted report with score bar, recommendations, and bucket breakdown.

## monerosim scenario templates (stub)

Eclipse rehearsal scenario for Milestone 4:

```powershell
python -m peer_fortress --list-scenarios
python -m peer_fortress --scenario scenarios/eclipse-rehearsal.yaml
```

Templates live in `scenarios/`. Full monerosim integration requires [Fountain5405/monerosim](https://github.com/Fountain5405/monerosim) (coordinate with Gingeropolous).

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

Grades: **good** (80+), **fair** (60-79), **weak** (40-59), **poor** (<40).

## Tests

```powershell
python -m unittest discover -s tests -v
```

CI runs the same suite on push via [GitHub Actions](.github/workflows/ci.yml).

## Roadmap (funded CCS milestones)

See [ROADMAP.md](ROADMAP.md) for full detail. Summary:

| # | Name | Funds | Status |
|---|------|-------|--------|
| M0 | Prototype (diversity + Tor SOCKS5 stub) | pre-funding | **shipped** [v0.3.0](https://github.com/1igaming/peer-fortress/releases/tag/v0.3.0) |
| M1 | CLI, diversity scoring, and testnet demo | 14 XMR | funded milestone |
| M2 | Spy heuristics, Tor egress health, and playbook templates | 16 XMR | funded milestone |
| M3 | Optional local UI and operator hardening guide | 14 XMR | funded milestone |
| M4 | monerosim scenario pack (5 scenarios) and documentation | 18 XMR | funded milestone |

## License

MIT — see [LICENSE](LICENSE).

## Non-goals

- No monerod consensus or wallet protocol changes
- No network-wide telemetry or dashboards
- No I2P SAMv3 implementation (see jpk68 WIP)
- No auto-applied banlists — human approval required for any live config change

## Author

**1igaming** — https://github.com/1igaming
