# Contributing to Nectar Gateway

Thanks for helping! A few ground rules:

1. **CLA.** Every contributor signs the [Contributor License Agreement](CLA.md) once — a bot asks on your first pull request.
2. **Discuss big changes first.** Open an issue before large features so we can agree on the design.
3. **Keep the contract.** nectar-apps drives the gateway through its REST API (`/api/*`, see the README). Changes the panel relies on are announced in `features` of `GET /api/version`; breaking ones bump the API version and `.github/release-requires.json` in nectar_apps.
4. **Tests and lint.** `go vet ./... && go test -race ./...` and `cd ui && npm run build` must pass. New behavior needs tests.
5. **Commits.** [Conventional commits](https://www.conventionalcommits.org) (`feat:`, `fix:`, `docs:`…) — they drive the changelog and version bumps.
6. **Security issues** go to support@techbrain.llc, not public issues.

## Code style

- Go: standard library first, small packages, errors wrapped with context, no panics in request paths.
- Never log secrets (passwords, tokens, private keys).
- Admin UI: React + MUI, no new dependencies without a reason.
