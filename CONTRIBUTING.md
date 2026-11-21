# Contributing to ShareGuard for Agent Builder

Thanks for helping. This project changes what users can do in production Microsoft 365 tenants, so correctness and safety come before features.

## Ground rules

- Be kind. Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
- **Security issues go to [SECURITY.md](SECURITY.md), not to public issues.**
- Never include real tenant IDs, user names, email addresses, agent names, tokens or audit logs in issues, pull requests, tests or examples. Use `contoso.com` and placeholder GUIDs.
- Open an issue to discuss larger changes before you start.

## Development setup

```bash
git clone https://github.com/OWNER/absg.git
cd absg
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest          # run the test suite
ruff check .    # lint
```

The tests use in-memory fakes of Microsoft Graph and need no tenant or network access.

## Pull requests

1. Branch from `main`.
2. Add or update tests for every behaviour change. A change to enforcement logic (blocking, unblocking, registry or drift rules) needs a test covering both the action and its audit record.
3. Keep `pytest` and `ruff check .` passing.
4. Add an entry under **Unreleased** in [CHANGELOG.md](CHANGELOG.md).
5. Explain *why* in the PR description, and note any change to permissions, data stored, or audit format.

### Changes that need extra care

- **Audit trail format.** Records are hash-chained. Don't change how they're hashed or serialised without a migration note, because existing trails must stay verifiable.
- **Default behaviour.** Defaults must fail safe: never unblock on uncertain evidence, never treat an unreadable registry as "no approvals".
- **Permissions.** Any new Graph or Exchange permission must be documented in `docs/operations-guide.md` and justified in the PR.

## Developer Certificate of Origin

By contributing, you certify that you wrote the contribution or otherwise have the right to submit it under the project's licence. Sign off each commit to confirm this ([DCO 1.1](https://developercertificate.org/)):

```bash
git commit -s -m "Describe your change"
```

## Licence

Contributions are licensed under the [Apache License, Version 2.0](LICENSE), the project's licence. Add this header to new source files:

```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
```
