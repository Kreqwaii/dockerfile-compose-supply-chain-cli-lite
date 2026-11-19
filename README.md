# dockerfile-compose-supply-chain-cli-lite

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-brightgreen.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**EN:** Fast, 100% offline security & supply-chain linter for `Dockerfile` and `docker-compose.yml` written in pure Python 3.9+ stdlib (zero external dependencies).  
**RU:** Быстрый полностью офлайн-линтер безопасности и цепочки поставок для `Dockerfile` и `docker-compose.yml` на чистом Python 3.9+ stdlib (без внешних зависимостей).

---

## Quick Start / Быстрый старт

```bash
# Scan a Dockerfile and docker-compose.yml
python -m docker_supply_lite samples/Dockerfile.risky samples/docker-compose.risky.yml

# JSON output for CI pipelines
python -m docker_supply_lite samples/Dockerfile.risky --format json --fail-on high

# Markdown report
python -m docker_supply_lite samples/docker-compose.risky.yml --format markdown --fail-on critical
```

---

## Security Rules / Правила проверки

| Rule | Severity | Target | Description |
|------|----------|--------|-------------|
| `DF001` | HIGH | Dockerfile | Unpinned base image (`:latest` or untagged) |
| `DF002` | HIGH | Dockerfile | Container runs as `root` (missing non-root `USER`) |
| `DF003` | CRITICAL | Dockerfile | Remote script piped to shell (`curl`/`wget \| sh`/`bash`) |
| `DF004` | MEDIUM | Dockerfile | `ADD` instruction used with remote URL |
| `DF005` | CRITICAL | Dockerfile | Hardcoded secret or credential in `ENV` / `ARG` |
| `DF006` | LOW | Dockerfile | Missing `HEALTHCHECK` instruction |
| `DC001` | CRITICAL | Compose | Service runs with `privileged: true` |
| `DC002` | HIGH | Compose | Service uses `network_mode: host` |
| `DC003` | CRITICAL | Compose | Docker socket mounted (`/var/run/docker.sock`) |
| `DC004` | HIGH | Compose | Database port exposed on `0.0.0.0` |
| `DC005` | MEDIUM | Compose | Missing `read_only: true` root filesystem |
| `DC006` | MEDIUM | Compose | Missing `mem_limit` / `deploy.resources.limits.memory` |
| `DC007` | HIGH | Compose | Unpinned service image (`:latest` or untagged) |
| `DC008` | CRITICAL | Compose | Hardcoded secret in Compose `environment` |

---

## Need the full Pro Studio?

Need the full Pro Studio (Web UI, SBOM layer inspector, SARIF 2.1.0, CIS Docker Benchmark score, baseline diff)?

- Order / Заказать Pro Studio: [FunPay Profile](https://funpay.com/users/20096179/)

---

## License

MIT — see [LICENSE](LICENSE).
