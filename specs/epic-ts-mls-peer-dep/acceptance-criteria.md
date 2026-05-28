# Acceptance Criteria: ts-mls Peer Dependency

## AC-PKG-1 — Dependency classification correct
`package.json` lists `ts-mls` under `peerDependencies` and `devDependencies`, and **not** under `dependencies`. The published/packed `dist/package.json` (produced by `pnpm build && pnpm pack`) reflects the same classification.

## AC-PKG-2 — Single ts-mls instance after install
Installing the packed/published marmot-ts into a fresh consumer that also declares `ts-mls: "2.0.0-rc.10"` results in **exactly one** ts-mls instance in the consumer's module graph. Verified by `pnpm why ts-mls` showing a single resolved copy.

## AC-PKG-3 — Downstream type-check fixture compiles clean
A minimal fixture consumer that imports `getOwnLeafNode` from `ts-mls` and passes `group.state` (a `ClientState` exposed via `MarmotGroup`) to it compiles with `tsc --noEmit` and **zero** `TS2345` brand-mismatch errors.

## AC-PKG-4 — Workspace co-development topology documented
README or CONTRIBUTING documents the workspace-based co-development topology (marmot-ts + consumer in a pnpm workspace) that produces a single ts-mls instance with a live (unbuilt tarball) marmot-ts, giving live-edit capability without re-introducing the dual-copy problem.

## AC-PKG-5 — Peer version mismatch surfaces as warning
A consumer that installs an incompatible `ts-mls` version receives an explicit peer dependency install warning from pnpm/npm, not a silent second copy. (This is automatic once `peerDependencies` is declared; verified by the fact that peer version mismatches are pnpm's default behavior.)

## AC-PKG-6 — Documentation complete
README and/or CONTRIBUTING states: (a) `ts-mls` is a peer dependency, (b) why (branded types must be single-instance across the module graph), and (c) the recommended consumer install topology (packed/published) and co-development (workspace) topology.
