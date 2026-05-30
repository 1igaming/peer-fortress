# Peer Fortress roadmap

Aligned with the [Peer Fortress CCS proposal](https://github.com/1igaming/peer-fortress/issues/1) (62 XMR, 4 milestones). Milestone-0 is pre-funding and shipped at v0.3.0.

## Milestone 0 — Prototype (shipped)

**Status:** v0.3.0 — https://github.com/1igaming/peer-fortress/releases/tag/v0.3.0

| Feature | Path | CLI |
|---------|------|-----|
| Diversity scoring from `sync_info` | `peer_fortress/diversity.py` | `python -m peer_fortress` |
| Tor SOCKS5 health check | `peer_fortress/tor_health.py` | `--tor-check` |
| Human-readable report | `peer_fortress/report.py` | `--report` |
| JSON output + schema validation | `peer_fortress/schema_validate.py` | `--json --validate-schema` |
| monerosim scenario stub | `scenarios/eclipse-rehearsal.yaml` | `--list-scenarios` |

## Milestone 1 — CLI, diversity scoring, and testnet demo

**Funds:** 14 XMR | **Target:** 4 weeks after Funding Required | **Tag:** `v1.0.0-m1`

- Public repo polish: MIT LICENSE, README, CONTRIBUTING
- CLI: `sync_info` RPC → diversity score (JSON + `--report`)
- Stagenet/testnet walkthrough: `docs/testnet-demo.md` with screenshots or recording
- CI green on default branch

## Milestone 2 — Spy heuristics, Tor egress health, and playbook templates

**Funds:** 16 XMR | **Target:** 8 weeks after Funding Required | **Tag:** `v1.0.0-m2`

- Spy concentration module citing Rucknium / MRL #1124: `peer_fortress/spy_heuristics.py`
- Tor egress: circuit latency sampling, stale-proxy detection, `.onion`/clearnet ratio score
- Read-only playbook templates: `peer_fortress/playbook.py`
- ≥20 unit/integration tests on fixtures

## Milestone 3 — Optional local UI and operator hardening guide

**Funds:** 14 XMR | **Target:** 12 weeks after Funding Required | **Tag:** `v1.0.0-m3`

- Read-only local web UI consuming CLI JSON: `ui/`
- Operator hardening guide: `docs/operator-hardening.md`
- CI smoke test on docs or `--version`

## Milestone 4 — monerosim scenario pack (5 scenarios) and documentation

**Funds:** 18 XMR | **Target:** 16 weeks after Funding Required | **Tag:** `v1.0.0-m4`

- Five YAML scenarios: eclipse, partition, spy flood, Tor circuit collapse, clearnet/Tor split
- Documentation: `docs/monerosim-scenarios.md`
- Coordination with Gingeropolous / monerosim maintainers (!589)
- CI smoke test: scenarios parse without error

## Non-goals (all milestones)

- No monerod consensus or wallet protocol changes
- No network-wide telemetry or dashboards
- No I2P SAMv3 implementation (see jpk68 WIP)
- No auto-applied banlists — human approval required for any live config change

## Complementarity

| Project | Peer Fortress |
|---------|---------------|
| [ProbeLab !667](https://repo.getmonero.org/monero-project/ccs-proposals/-/merge_requests/667) | Operator-local; not a macro crawl |
| jpk68 I2P SAMv3 WIP | No consensus changes |
| [monerosim !589](https://repo.getmonero.org/monero-project/ccs-proposals/-/merge_requests/589) | Scenario consumer, not engine fork |
