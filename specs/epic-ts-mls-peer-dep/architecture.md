# Architecture: ts-mls Peer Dependency

## Paradigm
This epic is purely a **packaging and documentation change**. No module boundaries, data flows, or application logic change. The TypeScript source is unchanged.

## Module Map

| Module | Purpose | Change |
|---|---|---|
| `package.json` | Dependency declarations | Move ts-mls dep → peerDep + devDep |
| `pnpm-workspace.yaml` | Workspace packages | Add `fixtures/type-check-consumer` |
| `fixtures/type-check-consumer/` | New CI fixture | Create: verifies single-instance behavior |
| `.github/workflows/tests.yml` | CI workflow | Add type-check-fixture job |
| `README.md` | User-facing docs | Document peer dep + topologies |
| `CONTRIBUTING.md` | Contributor docs | Update workspace co-dev topology |
| `.changeset/<name>.md` | Release tracking | Add minor changeset |

## Boundary Rules

No cross-module boundaries are affected. This is a metadata and documentation change only.

## Seams

None — no new cross-package interfaces introduced. The fixture consumes the existing public API.

## Implementation Constraints

- pnpm 10 is required (CI installs with `--frozen-lockfile`): updating `pnpm-lock.yaml` is mandatory when changing `package.json` deps or adding workspace packages.
- The peer range stays at exact `2.0.0-rc.10` (spec §5.1: do not use `^` on pre-release versions).
- The `./mls` subpath export (`src/mls.ts: export * from "ts-mls"`) is intentional and unchanged.
- The fixture package must be `private: true` and NOT be published.
- The fixture's `tsconfig.json` must use `moduleResolution: NodeNext` consistent with the library.

## Story Execution Order

1. **S1** (package.json migration) — must land first; S2's fixture depends on the peer dep being declared to correctly test single-instance behavior.
2. **S2** (CI fixture) — depends on S1's peerDep declaration. Can be verified once S1 is done.
3. **S3** (docs + changeset) — independent, can proceed after S1.
