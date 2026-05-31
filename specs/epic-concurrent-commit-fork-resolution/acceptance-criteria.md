# Acceptance Criteria — Concurrent-Commit Fork Resolution

Epic: `epic-concurrent-commit-fork-resolution`
Spec: `specs/epic-concurrent-commit-fork-resolution/spec.md`

---

## Structural / API Shape

**AC-STRUCT-1** — `EpochSnapshot` type and `EpochSnapshotStoreBackend` interface are exported

`src/client/group/epoch-snapshot.ts` MUST export `EpochSnapshot` (with fields `groupId`, `epoch`, `state`, and optional `appliedCommit` containing `eventId`, `createdAt`, and `contentHash`) and `EpochSnapshotStoreBackend` (with methods `get`, `set`, `prune`, and `clear`). Both MUST be re-exported from the `./client` public surface (`src/client/group/index.ts`).

_Test type_: unit

---

**AC-STRUCT-2** — `RollbackInfo` type is exported from the client surface

`src/client/group/marmot-group.ts` MUST export `RollbackInfo` with fields `groupId: Uint8Array`, `targetEpoch: bigint`, `newHeadCommitEventId: string`, `invalidatedMessages: string[]`, and optional `messagesNeedingRefetch: string[]`. The type MUST be accessible via the `./client` subpath export.

_Test type_: unit

---

**AC-STRUCT-3** — `MarmotGroupOptions` accepts an optional `snapshots` field

`MarmotGroupOptions` MUST accept an optional `snapshots?: EpochSnapshotStoreBackend | EpochSnapshotStoreFactory` field. When omitted, `MarmotGroup` MUST default to an in-memory snapshot store with `snapshotDepth = 2`. The existing `MarmotGroupOptions` fields (`store`, `signer`, `ciphersuite`, `network`, `history`, `media`) MUST remain unchanged.

_Test type_: unit

---

**AC-STRUCT-4** — `MarmotGroupEvents` includes a `rollback` slot

`MarmotGroupEvents` (in `src/client/group/marmot-group.ts`) MUST include `rollback: (info: RollbackInfo) => void` as a typed entry alongside existing events. Calling `group.on("rollback", handler)` MUST compile without TypeScript error.

_Test type_: unit

---

**AC-STRUCT-5** — `InMemoryEpochSnapshotStore` is exported from the `./extra` subpath

`src/extra/in-memory-epoch-snapshot-store.ts` MUST export a named class `InMemoryEpochSnapshotStore` that implements `EpochSnapshotStoreBackend`. The class MUST be re-exported from `src/extra/index.ts` and accessible via the `@internet-privacy/marmot-ts/extra` subpath.

_Test type_: unit

---

**AC-STRUCT-6** — `isBetterCandidate` and `isReplayOfApplied` are named exports of `src/core/group-message.ts`

`src/core/group-message.ts` MUST export `isBetterCandidate(candidate: NostrEvent, applied: { eventId: string; createdAt: number }): boolean` and `isReplayOfApplied(candidate: NostrEvent, applied: { eventId: string; contentHash: Uint8Array }): boolean` as named exports. `sortGroupCommits` MUST delegate to `isBetterCandidate` so the MIP-03 ordering comparator has a single implementation used by both sort and rollback.

_Test type_: unit

---

## Phase 1 — Snapshot Store + Pending-Commit Discipline

**AC-SNAP-1** — A snapshot is taken before every commit advance in `ingest()`

When `ingest()` applies a current-epoch commit, `EpochSnapshotStoreBackend.set` MUST be called with the pre-apply `SerializedClientState` and the commit event's `eventId`, `createdAt`, and SHA-256 `contentHash` before `processMessage()` is invoked. If the snapshot store is unavailable or throws, `ingest()` MUST propagate the error rather than apply without a snapshot.

_Test type_: unit

---

**AC-SNAP-2** — A snapshot is taken before `selfUpdate()` and `commit()` advance state

When `selfUpdate()` or `commit()` is about to merge a pending commit (after `hasAck`), `EpochSnapshotStoreBackend.set` MUST be called with the pre-advance state snapshot before `this.state` is updated. The existing `hasAck`-before-advance invariant MUST be preserved.

_Test type_: unit

---

**AC-SNAP-3** — `clearPendingCommit` discards pending state and leaves no orphan snapshot on publish failure

When `selfUpdate()` or `commit()` receives no relay ack (`!hasAck(response)`), the operation MUST NOT advance `this.state`, MUST NOT call `save()`, and MUST NOT promote any pending snapshot. After the failure, `EpochSnapshotStoreBackend.get` for the would-be new epoch MUST return `null`.

_Test type_: unit

---

## Phase 1 — Rollback Path

**AC-ROLL-1** — Two concurrent self-update commits converge to the same state (the core regression test)

Given two `MarmotGroup` instances A and B that are members of the same group at epoch N, when both call `selfUpdate()` and each publishes a self-update commit, and then both ingest both commits, A and B MUST end on the same `groupContext.epoch`, the same `keySchedule.exporterSecret`, and the same ratchet tree. An application message sent by A after convergence MUST be decryptable by B and vice versa. This test MUST fail on the current `addressable-key-packages` HEAD (verifying the regression) and pass after the patch.

_Test type_: integration

---

**AC-ROLL-2** — The winning commit is the MIP-03 winner: earliest `created_at`, then lexicographically smallest `id`

`isBetterCandidate` MUST return `true` when and only when `candidate.created_at < applied.createdAt`, or when `candidate.created_at === applied.createdAt` and `candidate.id < applied.eventId` lexicographically. A test MUST verify all four cases: (a) candidate wins on `created_at`; (b) candidate loses on `created_at`; (c) tie with candidate winning on `id`; (d) tie with candidate losing on `id`.

_Test type_: unit

---

**AC-ROLL-3** — The losing member ends on the winner's state via rollback, not its own commit

After the convergence scenario from AC-ROLL-1, the member whose commit lost (determined by MIP-03) MUST have applied the winning commit's `eventId` as its `lastAppliedCommit` (or equivalent head), not its own commit's id. The state it holds MUST be derivable only by applying the winner to the epoch-N snapshot, not by staying on its own advance.

_Test type_: integration

---

**AC-ROLL-4** — `rollbackToEpoch` restores the pre-commit serialized state byte-for-byte

A unit test MUST call `rollbackToEpoch` with a stored `EpochSnapshot` and assert that `serializeClientState(group.state)` equals the snapshot's `state` bytes before re-applying the winning commit. This confirms the snapshot round-trip is lossless.

_Test type_: unit

---

**AC-ROLL-5** — Both members independently select the same winner

In the convergence scenario, regardless of delivery order (A ingests A-then-B, B ingests B-then-A, or either ingests in arbitrary interleaved order), both members MUST settle on the same winning commit id. A test MUST verify convergence under both delivery orderings.

_Test type_: integration

---

## Phase 1 — Replay Guard

**AC-GUARD-1** — Ingesting the same winning commit a second time does not trigger a rollback

`isReplayOfApplied` MUST return `true` when the candidate event has the same `id` as the applied commit's `eventId`, or when the SHA-256 hash of its content matches the applied commit's `contentHash`. When `isReplayOfApplied` returns `true`, `ingest()` MUST yield `{ kind: "skipped", reason: "self-echo-commit" }` and MUST NOT modify `this.state`, call rollback, or emit a `rollback` event.

_Test type_: unit

---

**AC-GUARD-2** — A commit that loses the MIP-03 race is skipped, not rolled back

When a past-epoch commit arrives that is deterministically worse than the already-applied commit (`isBetterCandidate` returns `false`), `ingest()` MUST yield `{ kind: "skipped", reason: "lost-race" }` and MUST NOT change state or emit a `rollback` event.

_Test type_: unit

---

## Phase 2 — Message Invalidation and Retry

**AC-MSG-1** — Application messages decrypted under the losing epoch are reported invalidated after rollback

After a rollback, `ingest()` MUST yield invalidation records for application messages that were decrypted under the losing epoch. Each invalidation record MUST carry the event id of the message. A test MUST confirm the event ids in `RollbackInfo.invalidatedMessages` match the set of messages that were decrypted prior to rollback.

_Test type_: integration

---

**AC-MSG-2** — Events that failed to decrypt under the wrong epoch keys are retried and decrypt after the winner is applied

After a rollback restores the epoch-N snapshot and re-applies the winner, events previously in the "unreadable" set that were encrypted under the winner's epoch keys MUST be re-attempted and MUST succeed. The final `ingest()` result MUST include those events as successfully decrypted, not as unreadable.

_Test type_: integration

---

## Phase 2 — Rollback Event

**AC-EVT-1** — A `rollback` event fires exactly once per rollback with correct fields

When a rollback occurs, `MarmotGroup` MUST emit exactly one `rollback` event. The `RollbackInfo` payload MUST have `targetEpoch` equal to the epoch of the snapshot restored (the epoch before the losing commit was applied), and `newHeadCommitEventId` equal to the winning commit's Nostr event id. A test MUST register a spy on `group.on("rollback", ...)` and assert one emission with these exact values.

_Test type_: unit / integration

---

**AC-EVT-2** — No `rollback` event fires when there is no competing commit

When only one commit exists for an epoch (no race condition), `ingest()` MUST NOT emit a `rollback` event. A test MUST verify the spy count is zero after normal single-committer ingest.

_Test type_: unit

---

## Phase 3 — Past-Epoch Decryption Window

**AC-PAST-1** — A member one epoch behind decrypts a recent application message within `pastEpochDepth` without a rollback

Given a member at epoch N that has not yet ingested the latest commit, when it receives an application message encrypted under epoch N+1 (within `pastEpochDepth = 5`), it MUST successfully decrypt the message using retained past-epoch decryption material. No rollback MUST be triggered, and no `rollback` event MUST be emitted.

_Test type_: integration

---

**AC-PAST-2** — `pastEpochDepth` bounds the decryption window; messages beyond it are not retried with past keys

A member that is more than `pastEpochDepth` epochs behind MUST NOT use past-epoch decryption for messages outside that window. The message MUST be yielded as unreadable or deferred, not silently dropped and not causing a rollback.

_Test type_: unit

---

## Retention and Forward Secrecy

**AC-RET-1** — Snapshots beyond `snapshotDepth` are pruned on each state advance

After each commit advance, `EpochSnapshotStoreBackend.prune` MUST be called with `keepAboveEpoch = currentEpoch - snapshotDepth`. A test using `InMemoryEpochSnapshotStore` with `snapshotDepth = 2` MUST confirm that after advancing from epoch 0 through epoch 5, snapshots for epochs 0, 1, and 2 are absent and at most snapshots for epochs 3 and 4 remain.

_Test type_: unit

---

**AC-RET-2** — `snapshotDepth` defaults to 2 when not configured

When `MarmotGroup` is constructed without providing a `snapshots` option, `snapshotDepth` MUST default to 2. After three consecutive commit advances, only 2 snapshots MUST be retained (the two most recent pre-commit states).

_Test type_: unit

---

## Regression — Happy Path

**AC-REG-1** — Single-committer path produces no rollback and preserves existing behavior

A test that replicates the current `ingest-commit-race.test.ts` single-committer flow (one commit, no competition) MUST pass without modification. `ingest()` MUST yield the same epoch advance, no rollback event MUST be emitted, and the resulting `groupContext.epoch` MUST be `N + 1n`.

_Test type_: integration

---

**AC-REG-2** — Existing integration tests do not regress

All tests in `src/__tests__/integration/` (end-to-end-invite-join-message, send-chat-message, welcome-grace-window) MUST pass without modification after this epic. No existing test behavior MUST change.

_Test type_: integration

---

## Property Test

**AC-PROP-1** — All members converge regardless of delivery order across K concurrent committers

A property test using `fast-check` MUST generate a group of `K ≥ 2` members, assign each a random self-update commit at the same epoch, and deliver all commits to all members in a random permutation. For every permutation, all members MUST end on the same `groupContext.epoch`, the same `exporter_secret` (byte-equal), and the same winning commit (the MIP-03 minimum). This test validates that the convergence guarantee is not order-dependent.

_Test type_: property
