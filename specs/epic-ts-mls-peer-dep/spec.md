# Feature Request: Declare `ts-mls` a peer dependency so consumers and marmot-ts share one instance

**To:** marmot-ts maintainers
**From:** notestr-web (downstream consumer, same-org fork co-developers)
**Type:** Packaging / public-API type-safety defect
**Affects:** `@internet-privacy/marmot-ts@0.6.0` (and every prior version that exposes `ts-mls` types in its public API)
**Severity:** High — blocks downstream type-checked builds (`tsc` / `next build`) for any consumer that also depends on `ts-mls` or consumes marmot-ts via a link/workspace.
**Status:** Proposed

---

## 1. Summary

marmot-ts re-exposes **`ts-mls` types in its public API** (e.g. `MarmotGroup.state: ClientState`, `group.propose(action: ProposalAction<Proposal>)`, the `getPubkeyLeafNodeIndexes(state)` re-export). `ts-mls` brands several of those types with a **`unique symbol`** (`CustomExtension[__custom_extension_brand]`).

Because marmot-ts currently declares `ts-mls` as a **regular `dependency`**, a consumer that also depends on `ts-mls` ends up with **two physical copies** of `ts-mls` in its module graph (the consumer's and marmot-ts's). `unique symbol` brands are identity-based, so the two copies' types **do not unify even at the identical version**. Every place the consumer passes a marmot-ts-produced `ts-mls` value (e.g. `group.state`) into a `ts-mls` function — or vice versa — becomes a `TS2345` "not assignable" error, and the consumer's type-checked build fails.

**Requested change:** move `ts-mls` from `dependencies` to `peerDependencies` (keeping it in `devDependencies`), and document a workspace-based co-development topology so the linked/dev consumption path also resolves a single `ts-mls`.

---

## 2. Environment / evidence

- `@internet-privacy/marmot-ts@0.6.0`, `ts-mls@2.0.0-rc.10` (marmot-ts pins it exactly).
- Consumer: notestr-web (TypeScript, `moduleResolution: "bundler"`, `strict`, Next.js build), which **also** declares `"ts-mls": "^2.0.0-rc.10"` and imports `ts-mls` primitives directly (`getOwnLeafNode`, `defaultProposalTypes`, `nodeTypes`, `defaultKeyPackageEqualityConfig`).
- Consumer installs marmot-ts via `"@internet-privacy/marmot-ts": "file:<fork>/dist"`, which materialises as a **symlink** `node_modules/@internet-privacy/marmot-ts → <fork>/dist`.

Representative errors from `tsc --noEmit` (9 total, all the same class):

```
src/components/DeviceList.tsx(104,35): error TS2345: Argument of type
  'import(".../marmot-ts/node_modules/.pnpm/ts-mls@2.0.0-rc.10.../ts-mls/dist/src/clientState").ClientState'
  is not assignable to parameter of type
  'import(".../notestr-web/node_modules/ts-mls/dist/src/clientState").ClientState'.
    ...
    Property '[__custom_extension_brand]' is missing in type
      '...marmot-ts/.../ts-mls/.../CustomExtension'
      but required in type
      '...notestr-web/node_modules/ts-mls/.../CustomExtension'.
```

The call site is ordinary, correct usage:

```ts
// notestr-web/src/marmot/forget-device.ts
import { getOwnLeafNode } from "ts-mls";
import type { MarmotGroup } from "@internet-privacy/marmot-ts";

const ownLeaf = getOwnLeafNode(group.state); // group.state is marmot-ts's ts-mls ClientState
```

`group.state` carries the **marmot-ts copy's** `ClientState`; `getOwnLeafNode` expects the **consumer copy's** `ClientState`. Same version, same shape, different brand identity → rejected.

---

## 3. Root cause

Two independent facts combine:

1. **`ts-mls` uses nominal (branded) types.** Types like `CustomExtension` carry a `unique symbol` property (`[__custom_extension_brand]`). A `unique symbol` is identity-bound to the declaration site, so the same declaration compiled into two physically distinct package copies yields **two incompatible brands**. Structural equality is not enough; TypeScript treats them as different types. (This is by design in `ts-mls` and is good practice — it is *not* a bug in `ts-mls`.)

2. **marmot-ts bundles its own `ts-mls`** (regular `dependency`) and exposes `ts-mls` types across its public API surface (`MarmotGroup.state`, `propose`, `commit`, the re-exported `ts-mls` helpers, etc.). When a consumer's module graph contains a second `ts-mls`, the public API types reference marmot-ts's copy while the consumer's direct `ts-mls` usage references the consumer's copy.

The duplicate is *guaranteed* whenever the resolved location of marmot-ts has a sibling `node_modules/ts-mls`. That happens in the two most common dev/consumption topologies:

- **`file:` / `npm link` / `pnpm link` to a built dev tree** (our case): module resolution follows the symlink to its realpath inside the fork, and resolves `ts-mls` to the fork's own `node_modules/ts-mls`.
- **Any install where `ts-mls` cannot be deduped to a single copy** (version skew, nested install).

Because the brand mismatch only surfaces under whole-program type-checking, it is **invisible to per-file transpilers** — e.g. `vitest`/esbuild unit tests pass while `tsc`/`next build` fails. This makes the defect easy to ship unnoticed.

---

## 4. Impact

- **Build-blocking** for any consumer that type-checks (`tsc`, `next build`, `vue-tsc`, etc.) and either (a) also depends on `ts-mls` directly, or (b) consumes marmot-ts via link/workspace.
- **Silent under unit tests** (transpile-only), so CI suites that run only unit tests do not catch it.
- **No safe downstream workaround.** We verified that consumer-side mitigations do **not** work and/or are unacceptable:
  - `tsconfig` `paths` alias for `ts-mls` → no effect (marmot-ts's own `.d.ts` resolve `ts-mls` by their realpath, outside the consumer's path map).
  - Replacing the symlink with a real copy → worse: marmot-ts's *other* deps (`eventemitter3`, etc.) then fail to resolve from the consumer tree.
  - `preserveSymlinks` → requires all of marmot-ts's runtime deps to be hoisted into the consumer, which a `file:`-linked package does not guarantee.
  - Editing `node_modules` → forbidden by policy and ephemeral.

The fix has to live in marmot-ts.

---

## 5. Proposed change

### 5.1 Required: `ts-mls` becomes a peer dependency

In marmot-ts's `package.json`:

```jsonc
{
  "peerDependencies": {
    "ts-mls": "2.0.0-rc.10"
  },
  "devDependencies": {
    "ts-mls": "2.0.0-rc.10"
  }
  // remove "ts-mls" from "dependencies"
}
```

- `peerDependencies` declares the contract: *"the host application supplies `ts-mls`; there must be exactly one instance."* This lets package managers dedupe `ts-mls` to a single copy shared by marmot-ts and the consumer.
- `devDependencies` keeps `ts-mls` available for marmot-ts's own build and tests.
- **Peer range:** start with the exact `2.0.0-rc.10` to match the current pin. Once `ts-mls` reaches a stable release, widen to a normal caret range. (Caret on pre-release versions is intentionally narrow in semver, so do not use `^2.0.0-rc.10` while on `rc` — it will not match later `rc`s.)

### 5.2 Required for our use case: a single-`ts-mls` co-development topology

Because we **actively co-develop** marmot-ts and notestr-web, the dev loop must give live edits *and* one `ts-mls`. `peerDependencies` alone is necessary but not sufficient under `npm link`/`file:`-to-a-dev-tree, because the fork's own `node_modules/ts-mls` (its devDep) is still found via realpath. The supported topology should be a **workspace**:

- A workspace (pnpm/npm workspaces) that contains marmot-ts, `ts-mls`, and the consumer hoists **one** `ts-mls` to the workspace root. marmot-ts (as a workspace package with `ts-mls` as a peer) and the consumer both resolve that single copy → brands unify, live edits flow.
- Please document this as the recommended way to develop against an unreleased marmot-ts, and verify it in CI (see §7).

### 5.3 Recommended: audit the rest of the public API for the same hazard

`ts-mls` is the one biting us today, but the same rule applies to **any dependency whose nominal/branded types appear in marmot-ts's public API**. Please audit `@noble/*`, `applesauce-core`, `applesauce-common`, etc. Anything that (a) is re-exposed in a public type and (b) uses `unique symbol`/branded/`declare`-merged nominal types should also be a peer dependency. Plain structural interfaces (most `applesauce` event types) are safe and can stay regular deps.

### 5.4 Optional: tighten the boundary

Consider whether marmot-ts wants to be the **sole** boundary to `ts-mls` for consumers — i.e. re-export the small set of `ts-mls` primitives consumers actually need (`getOwnLeafNode`, `defaultProposalTypes`, `nodeTypes`, `defaultKeyPackageEqualityConfig`, `getPubkeyLeafNodeIndexes`) so downstreams never import `ts-mls` directly. This removes the duplicate at the source for consumers that don't otherwise need `ts-mls`, but it does not replace §5.1 (a peer is still correct for consumers that do use `ts-mls`).

---

## 6. Acceptance criteria

- **AC-1** marmot-ts's `package.json` lists `ts-mls` under `peerDependencies` (and `devDependencies`), and **not** under `dependencies`. The published/packed `dist/package.json` reflects the same.
- **AC-2** Installing the packed/published marmot-ts into a fresh consumer that also depends on the same `ts-mls` version results in **exactly one** `ts-mls` instance in the consumer's module graph (`npm ls ts-mls` / `pnpm why ts-mls` shows a single resolved copy).
- **AC-3** A minimal downstream type-check fixture (a `.ts` file that does `getOwnLeafNode(group.state)` and `group.propose(() => removeProposal)`) compiles with `tsc --noEmit` and **zero** `TS2345` brand-mismatch errors.
- **AC-4** The documented workspace dev topology produces the same single-instance result **with a live (unbuilt-tarball) marmot-ts** — i.e. editing marmot-ts source is reflected without reintroducing a second `ts-mls`.
- **AC-5** A peer-version mismatch (consumer installs an incompatible `ts-mls`) surfaces as an explicit `peer dep` install warning, not a silent second copy.
- **AC-6** Documentation (README/CONTRIBUTING) states that `ts-mls` is a peer dependency, why (branded types must be single-instance), and the recommended consumer install (packed/published) and co-development (workspace) topologies.

---

## 7. Verification / regression guard

- **Downstream type-check smoke test in marmot-ts CI.** Add a tiny fixture consumer (separate `package.json`, depends on packed marmot-ts + `ts-mls`) and run `tsc --noEmit` against it in CI. This catches any future regression where a branded `ts-mls` type re-enters as a non-peer dep. This is the single most valuable guard — the defect is otherwise invisible until a downstream build breaks.
- **Single-instance assertion.** In the same CI job, assert `npm ls ts-mls` (or `pnpm why`) resolves exactly one copy.
- Optional runtime guard: a dev-only check that warns if two `ts-mls` module instances are detected at runtime (rarely needed; the type-check guard is sufficient).

---

## 8. Alternatives considered (and why they are not the fix)

| Option | Verdict |
|---|---|
| Consumer `tsconfig` `paths` alias for `ts-mls` | **Rejected** — marmot-ts's own `.d.ts` resolve `ts-mls` by realpath, outside the consumer path map. No effect. |
| Consumer copies marmot-ts into `node_modules` instead of symlink | **Rejected** — breaks marmot-ts's *other* deps (`eventemitter3` etc.) and is a `node_modules` hack. |
| Consumer `preserveSymlinks` | **Rejected** — requires all marmot-ts runtime deps hoisted into the consumer; not guaranteed for a linked package; broad blast radius. |
| Bundle/inline `ts-mls` into marmot-ts output | **Rejected** — does not help consumers that *also* use `ts-mls` directly; they still get a second copy. |
| marmot-ts re-exports `ts-mls` surface, consumers drop direct dep | **Secondary** (see §5.4) — good boundary hygiene, larger consumer refactor, does not replace the peer-dependency fix. |
| **`ts-mls` as peer dependency + workspace dev topology** | **Accepted** — the standard fix for a library that exposes a branded third-party type in its public API. |

---

## 9. Risks / migration notes

- **Semver:** moving a dependency to a peer dependency is a consumer-visible contract change. Treat it as at least a minor bump while pre-1.0 (`rc`), and call it out in the changeset/release notes; consumers must ensure they declare `ts-mls` themselves (most already do).
- **Consumers who did *not* previously declare `ts-mls`** will get a missing-peer warning and must add it. Document this in the release notes.
- **No runtime behavior change.** This is purely a dependency-graph/type-identity fix; the emitted JS is unchanged.

---

## 10. References

- RFC 9420 §12.4 (self-Remove proposal semantics) — context for why `MarmotGroup.state`/`Proposal` types are part of the public API consumers must interoperate with.
- `ts-mls@2.0.0-rc.10` — `CustomExtension` branded type (`[__custom_extension_brand]`).
- Downstream evidence: notestr-web `src/marmot/forget-device.ts`, `src/components/DeviceList.tsx:104`, `src/marmot/device-sync.ts`; `tsc --noEmit` output (9 × `TS2345`, all citing two `ts-mls` paths).
- Downstream note documenting the pitfall and the "never monkey-patch marmot-ts" rule: notestr-web `CLAUDE.md` → "marmot-ts (we control the fork)".
