# Architecture — Concurrent-Commit Fork Resolution

## Paradigm

Modular monolith at top level; package-by-feature within `src/client/group/`; hexagonal seams at external boundaries (storage, network). All new snapshot logic is confined to `src/client/group/` with a storage seam (`EpochSnapshotStoreBackend`) that callers inject. No wire-format changes — the feature is purely local state-machine + storage logic.

## Module Map

| Module                             | Purpose                                           | Location                                      | Owned data                                                                                                                           |
| ---------------------------------- | ------------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `group-message.ts` (extended)      | MIP-03 commit ordering + comparator               | `src/core/group-message.ts`                   | `isBetterCandidate`, `isReplayOfApplied` factored from `sortGroupCommits`                                                            |
| `epoch-snapshot.ts` (new)          | Snapshot type, backend interface, factory type    | `src/client/group/epoch-snapshot.ts`          | `EpochSnapshot`, `EpochSnapshotStoreBackend`, `EpochSnapshotStoreFactory`                                                            |
| `marmot-group.ts` (modified)       | MarmotGroup rollback logic, event, options wiring | `src/client/group/marmot-group.ts`            | `RollbackInfo`, `rollback` event, `#snapshots` private field, `rollbackToEpoch()`, modified `ingest()` / `selfUpdate()` / `commit()` |
| `InMemoryEpochSnapshotStore` (new) | Default in-memory snapshot implementation         | `src/extra/in-memory-epoch-snapshot-store.ts` | Implements `EpochSnapshotStoreBackend` using `Map<string, EpochSnapshot>`                                                            |

### Files NOT modified by this epic

- `src/core/client-state.ts` (serialization primitives — use as-is)
- `src/utils/key-value.ts` (storage interface — no changes needed)
- `src/client/group/group-rumor-history.ts` / `group-media-store.ts` (pattern reference only)
- All existing store implementations in `src/extra/`

## Boundary Rules

- No direct imports across module boundaries. `src/core/` has no imports from `src/client/`.
- `epoch-snapshot.ts` may import from `src/core/` (for `SerializedClientState` type) but not from `marmot-group.ts`.
- `marmot-group.ts` imports from `epoch-snapshot.ts` and `src/core/group-message.ts`.
- `InMemoryEpochSnapshotStore` in `src/extra/` imports only from `src/client/group/epoch-snapshot.ts`.
- No new runtime exports from `src/core/` unless required (to avoid `exports.test.ts` snapshot churn).

## Seams

### `EpochSnapshotStoreBackend` (storage seam)

Injected via `MarmotGroupOptions.snapshots?: EpochSnapshotStoreBackend | EpochSnapshotStoreFactory`. Optional with an in-memory default. Callers that do not provide it get `snapshotDepth = 2` retention in memory.

```ts
interface EpochSnapshotStoreBackend {
  get(groupIdHex: string, epoch: bigint): Promise<EpochSnapshot | null>;
  set(
    groupIdHex: string,
    epoch: bigint,
    snapshot: EpochSnapshot,
  ): Promise<void>;
  prune(groupIdHex: string, keepAboveEpoch: bigint): Promise<void>;
  clear(groupIdHex: string): Promise<void>;
}
```

### `isBetterCandidate` / `isReplayOfApplied` (core comparator seam)

Factored out of `sortGroupCommits` in `src/core/group-message.ts` as named exports. Both `sortGroupCommits` and the new `past-epoch` rollback path share the same comparator function.

```ts
// Factored from sortGroupCommits — exported for use in rollback path
function isBetterCandidate(
  candidate: NostrEvent,
  applied: { eventId: string; createdAt: number },
): boolean;

function isReplayOfApplied(
  candidate: NostrEvent,
  applied: { eventId: string; contentHash: Uint8Array },
): boolean;
```

### `rollback` event (consumer seam)

`MarmotGroupEvents` extended with `rollback: (info: RollbackInfo) => void`. Library converges state and emits; app re-issues its own dropped change.

## Implementation Constraints

1. **`.js` extension on all relative imports** — `NodeNext` moduleResolution requirement (CLAUDE.md).
2. **Named exports only** — no default exports (CLAUDE.md).
3. **`bigint` for epoch throughout** — `ClientState.groupContext.epoch` is `bigint`; all epoch comparisons use `BigInt` literals (`1n`, `+ 1n`).
4. **`SerializedClientState` is raw `Uint8Array`** — snapshot payloads are raw TLS bytes from ts-mls; no JSON wrapping.
5. **`this.state` setter maintains `dirty` + `stateChanged` invariant** — rollback must go through the setter (or set `this.#state` + dirty + emit manually) to preserve existing guarantees.
6. **Snapshot before processMessage, not after** — for the current-epoch path in `ingest()`, the snapshot must be taken from the pre-apply state + the event being applied as `appliedCommit`.
7. **Hard-fail if snapshot unavailable** — mirrors MDK: apply without snapshot is a configuration error, not a silent degradation.
8. **Forward-secrecy constraint** — `snapshotDepth = 2` default; prune old snapshots on each state advance. Snapshots hold old `exporter_secret`s.
9. **`exports.test.ts` snapshot** — adding new TypeScript type-only exports does NOT break the snapshot test. Adding new runtime values (class constructors, function exports from `src/core/`) requires updating the `toMatchInlineSnapshot` at `src/__tests__/exports.test.ts`.
10. **`fast-check` not installed** — property test in spec §9 requires adding `fast-check` to devDependencies before implementation.

## Story Dependencies and Order

```
Story 1 (snapshot store + pending discipline)
  → provides EpochSnapshotStoreBackend, wiring, and snapshot-on-advance

Story 2 (rollback path)
  → depends on Story 1 (snapshots must exist before rollback can use them)
  → provides the fork fix and AC-1 convergence test

Story 3 (invalidation + rollback event)
  → depends on Story 2 (rollback must fire before event can be emitted)

Story 4 (past-epoch decryption window)
  → independent of Stories 2–3 (separate decryption code path in Step 1 of ingest())
  → can be implemented after Story 1 (needs snapshot store for key material)
```
