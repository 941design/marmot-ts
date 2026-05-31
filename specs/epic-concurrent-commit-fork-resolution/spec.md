# Feature request: Resolve concurrent-commit forks via epoch snapshots + MIP-03 rollback (port MDK's convergence machinery)

**Repository:** `internet-privacy/marmot-ts` (and downstream fork `941design/marmot-ts`)
**Verified against:** current `addressable-key-packages` branch HEAD; `@internet-privacy/marmot-ts@0.6.0`; `ts-mls@2.0.0-rc.10`
**Reference implementation:** `parres-hq/mdk` @ master (Rust, on OpenMLS); `parres-hq/whitenoise` (reference app)
**Reporter:** notestr-web maintainers (consumer) — surfaced via web + CLI multi-device sync
**Severity:** High — two devices of one identity in the same group fork permanently and never reconcile. Breaks the multi-device use case, which is a core product promise.
**Type:** Core protocol-correctness fix (MLS state machine / `MarmotGroup` ingest path)
**Status:** Proposed

---

## 1. Summary

When two members of the same group commit at (or "from") the **same epoch** — the textbook case being two devices of one npub, each its own leaf — marmot-ts **forks the group permanently**. Each device advances to its own epoch `N+1` and then **discards the other member's competing commit** as `past-epoch`, so the two devices end up holding **different ratchet trees and different `exporter_secret`s under the same epoch number** and can never again decrypt each other's messages.

This is the symptom behind "web and CLI are both members of `Tasks` but never sync."

The fork is **not** an inherent limitation of MLS-on-Nostr. MIP-03 specifies a deterministic resolution rule, and the Rust reference implementation (**MDK**) implements it in full: snapshot group state before applying a commit, defer merging your own commit until a relay acks it, and — when a deterministically _better_ competing commit arrives for an epoch you already passed — **roll back to the snapshot and re-apply the winner**. marmot-ts has **none** of this machinery. The `past-epoch → skip` branch in `ingest()` is the dead-end where the loser's commit is silently dropped instead of resolved.

**Requested change:** port MDK's convergence design to marmot-ts — (1) per-epoch state snapshots, (2) deferred-merge / pending-commit discipline, (3) a MIP-03 rollback path replacing the `past-epoch` skip, (4) post-rollback message invalidation + retry, (5) a `rollback` event so the app can re-issue its own dropped change, and (6) a bounded past-epoch decryption window.

> **Scope boundary (read first).** This fixes forks **going forward** (fork _prevention_ at ingest). It does **not** heal groups that are _already_ forked today — those have no snapshot to roll back to. Recovering existing diverged groups is a separate out-of-band workstream (§10).

---

## 2. Background / protocol context

- **One leaf per device; no shared membership.** In MLS, the unit of membership is a leaf. Two devices of one npub are **two distinct members**, each with its own credential, signing key, and independently-ratcheting state. There is no protocol mechanism to "sync one membership" across devices (NIP-EE; MIP-00 per-device `d`-tag KeyPackage slots). Convergence is achieved only by **both leaves applying the same ordered sequence of commits** — not by sharing state.
- **MLS imposes a linear epoch history.** Exactly one commit may advance an epoch; the protocol cannot merge two commits for the same epoch (RFC 9420 §12; RFC 9750 §14). Concurrent commits therefore require an out-of-band tiebreak.
- **No Delivery Service on Nostr.** RFC 9420 assumes a DS that orders commits and rejects losers. Relays do not: a relay will accept **both** competing commits. So the tiebreak must be a rule every client computes **identically and locally**.
- **MIP-03 "Commit Message Race Conditions" defines that rule.** On receiving multiple commits for the same epoch, a client MUST apply exactly one: (1) earliest `created_at`; (2) on tie, lexicographically smallest event `id`; discard the rest. A client MUST NOT apply a commit locally until at least one relay confirms receipt (and Welcomes MUST NOT be sent until after that ack). MIP-03 also notes "State Fork Risk" and says clients SHOULD retain previous group states temporarily to enable recovery.
- **MIP-02 makes the collision near-certain at join.** A new member MUST self-update within 24h of joining from a Welcome ("first process outstanding commits, then self-update"). When two devices join the same group, both are _mandated_ to self-update — which is exactly the concurrent-commit condition. MIP-02 does not flag that its own mandate is a fork trigger; the protection has to live in the ingest path.

---

## 3. Code references — where marmot-ts falls short

All references are `src/` (TypeScript) on the current branch.

### 3.1 The dead-end: `past-epoch` skip in `ingest()`

`src/client/group/marmot-group.ts`, commit-processing loop (`ingest()`), the `commitEpoch < currentEpoch` branch:

```ts
// Commits from past epochs were already applied — skip and report them.
if (commitEpoch < currentEpoch) {
  log("skip commit ... reason:past-epoch (commit=%d current=%d)", ...);
  yield { kind: "skipped", event, message, reason: "past-epoch" };
  continue;
}
```

The comment encodes the false assumption: a commit at an epoch below ours was **not necessarily** "already applied" — it may be a **competing** commit for an epoch we advanced past **using our own commit**. Today it is unconditionally discarded. This is the single line where the fork becomes permanent.

(The sibling branches are fine: `commitEpoch === currentEpoch` applies the commit; `commitEpoch > currentEpoch + 1n` defers to the unreadable-retry queue.)

### 3.2 Own commit advances with no snapshot and no pending/clear concept

`selfUpdate()` — advances after a relay ack, overwriting `this.state` with no snapshot of the pre-commit state:

```ts
const { commit, newState } = await createCommit({ /* ... extraProposals: [] */ });
const commitEvent = await createGroupEvent({ message: commit, state: this.state, ... });
const response = await this.network.publish(relays, commitEvent);
if (!hasAck(response)) throw new Error("Failed to publish commit event: no relay acknowledged");
// Advance local state after publish.
this.state = newState;   // <-- pre-commit state (epoch N) is now unrecoverable
await this.save();
```

`commit()` (admin path) and `sendProposal()` follow the same shape (`this.state = newState` after ack). `save()` persists `serializeClientState(this.state)` keyed by `bytesToHex(this.id)` (the group id) only — there is **no per-epoch keying**, so there is nothing to roll back to.

### 3.3 The foundation that already exists

`ingest()` calls `sortGroupCommits(commits)` (MIP-03 ordering) before processing — so the ordering primitive is present. What's missing is using that ordering to **resolve a competition against a commit we already applied**, plus the snapshot to make rollback possible.

### 3.4 What is entirely absent

- No epoch-snapshot store (no equivalent of MDK `epoch_snapshots`).
- No `WrongEpoch`/`past-epoch` rollback path (`is_better_candidate` → `rollback_to_epoch` → re-apply winner).
- No post-rollback message invalidation / retry.
- No pending-commit/`clearPendingCommit` on publish failure.
- No `rollback` event for the consumer.
- No bounded past-epoch decryption window for lagging members.

---

## 4. Root cause

Three facts combine:

1. **Relays accept both competing commits.** marmot-ts _does_ wait for `hasAck` before advancing (consistent with MIP-03 sequencing), so the bug is **not** premature/optimistic advance. Both devices legitimately get an ack and both advance to _their own_ `N+1`.
2. **The loser's commit is discarded, not resolved.** When device A ingests device B's commit (created at epoch `N`), A is already at `N+1`, so it hits the `past-epoch` skip (§3.1) and drops it. B does the same to A's commit.
3. **No snapshot exists to roll back to.** `this.state` was overwritten in place (§3.2), so even if A wanted to converge on B's commit it has no epoch-`N` state to re-apply it from.

Net: two members at "epoch `N+1`" with different trees and different `exporter_secret`s → mutually undecryptable forever. The decisive missing capability is **snapshot + MIP-03 rollback**, not "stop being optimistic."

---

## 5. Reference implementation (MDK) — the pattern to port

Source-verified against `parres-hq/mdk` @ master (line numbers approximate, will drift):

**(a) Deferred merge — `crates/mdk-core/src/groups.rs`.** `self_update` / `add_members` / `remove_members` create a _pending_ commit and do **not** merge. Each carries the doc-comment _"This function doesn't merge the pending commit. Clients must call this … only after successful publish."_ A separate `merge_pending_commit(group_id)` applies it after a relay ack; `clear_pending_commit` rolls it back if publishing failed. WhiteNoise wraps this as `publish_and_merge_commit` — _"local state only advances once a relay has accepted the event."_

**(b) Snapshot before apply — `crates/mdk-core/src/messages/commit.rs::process_commit`.** Calls `epoch_snapshots.create_snapshot(...)` **before** `merge_staged_commit(...)`, and **hard-fails** (`SnapshotCreationFailed`) rather than apply without one: _"Without a snapshot we can't guarantee MIP-03 convergence if a better commit arrives."_

**(c) Rollback on competing commit — `crates/mdk-core/src/messages/error_handling.rs::handle_processing_error`, `ProcessMessageWrongEpoch` arm (~L324–430).** When a competing commit arrives for an epoch already passed, OpenMLS raises `WrongEpoch`; MDK then:

1. guards on `is_commit` (stale proposals / app-messages do **not** trigger rollback);
2. runs `epoch_snapshots::is_better_candidate` — MIP-03 rule: `candidate_ts < applied_ts`; on tie `candidate_id.to_hex() < applied_id.to_hex()`; **plus a SHA-256 content-hash replay guard** so a re-wrapped identical commit (e.g. our own echo) can't trigger a spurious rollback;
3. if better: `rollback_to_epoch` (→ `storage.rollback_group_to_snapshot`) → `invalidate_messages_after_epoch` → `find_failed_messages_for_retry` / `mark_processed_message_retryable` → fire `on_rollback(RollbackInfo { group_id, target_epoch, new_head_event, invalidated_messages, messages_needing_refetch })` → **recurse** to apply the winner;
4. if not better (our commit won, or theirs loses): discard as `Unprocessable`; our applied winner stands.

**(d) Supporting pieces.** `EpochSnapshot` (`epoch_snapshots.rs`) stores pre-commit epoch + applied commit id/timestamp/content-hash + a storage snapshot handle (full group state). `messages/decryption.rs::try_decrypt_with_past_epochs` keeps a **past-epoch decryption window** (default ~5 epochs) so lagging members still decrypt recent application messages **without** a full rollback.

**(e) Division of labor (confirmed by MDK + WhiteNoise).** The **library** converges to the canonical state and _signals_ (`on_rollback`). It does **not** auto-replay your losing change. The **app** re-issues its own dropped mutation on top of the new canonical state, and owns publish-then-merge orchestration and concurrency minimization. This is the empirical answer to "library vs client": convergence in the library, replay/UX policy in the app.

---

## 6. Proposed change for marmot-ts

Six components. Recommended phased delivery noted at the end.

### 6.1 (A) Epoch snapshot store

Before applying **any** commit in `ingest()` (and before advancing on a locally-created commit), persist a snapshot of the **pre-commit** `ClientState` plus the metadata needed for resolution:

```ts
interface EpochSnapshot {
  groupId: Uint8Array; // this.id
  epoch: bigint; // pre-commit epoch the snapshot represents
  state: SerializedClientState; // full serialized ClientState at `epoch`
  appliedCommit?: {
    // the commit we applied to leave `epoch`
    eventId: string;
    createdAt: number;
    contentHash: Uint8Array; // SHA-256 of the commit event content (replay guard)
  };
}
```

- New backend (mirror `GroupStateStoreBackend`): `EpochSnapshotStoreBackend`, keyed by `(groupIdHex, epoch)`. Decision in §13 whether to extend the existing store or add a sibling.
- **Bounded retention** (forward secrecy — §11): keep at most `snapshotDepth` epochs (default small, e.g. 2–5) and/or a max age; prune on advance. Snapshots hold old `exporter_secret`s, so the window must be tight.
- Apply-without-snapshot must be treated as a hard error (mirror MDK), so convergence is never silently unguaranteed.

### 6.2 (B) Deferred-merge / pending-commit discipline

Formalize the "advance only after ack, cleanly undo on failure" contract that today is implicit:

- `selfUpdate` / `commit` / member-change ops create a **pending** commit (hold `newState` + snapshot the pre-commit state) and merge (assign `this.state = newState`, `save()`) only after `hasAck`.
- On publish failure, `clearPendingCommit()` discards the pending `newState` (and any new self-update signer material) — no advance, no snapshot promotion. Today a publish failure throws but there is no explicit pending/clear seam; make it explicit so the snapshot lifecycle is well-defined.

### 6.3 (C) Replace the `past-epoch` skip with a MIP-03 rollback path

Replace §3.1 with resolution:

```ts
if (commitEpoch < currentEpoch) {
  const snapshot = await this.snapshots.get(this.id, commitEpoch);
  if (!snapshot?.appliedCommit) {
    // genuinely already-applied / no competition recorded → skip as today
    yield { kind: "skipped", event, message, reason: "past-epoch" };
    continue;
  }
  if (isReplayOfApplied(event, snapshot.appliedCommit)) {  // content-hash / id match
    yield { kind: "skipped", event, message, reason: "self-echo-commit" };
    continue;
  }
  if (isBetterCandidate(event, snapshot.appliedCommit)) {   // MIP-03: created_at, then id
    await this.rollbackToEpoch(commitEpoch, snapshot);      // restore pre-commit state
    // re-apply the winner (this event) from the restored state, then continue ingest
    ...
  } else {
    yield { kind: "skipped", event, message, reason: "lost-race" };
    continue;
  }
}
```

`isBetterCandidate` = MIP-03 rule (earliest `created_at`, then lexicographically smallest `id`), with the content-hash replay guard. `sortGroupCommits` (§3.3) already encodes the ordering; factor the comparator so both share one source of truth.

### 6.4 (D) Post-rollback message invalidation + retry

After a rollback:

- mark application messages that were decrypted under the **losing** epoch as invalidated (so the app can drop/replace them in its history view);
- re-queue events that failed to decrypt under the wrong keys for retry (they may now decrypt under the winner's epoch);
- preserve the existing unreadable-retry recursion in `ingest()` — feed the re-applied winner + retryables back through it.

### 6.5 (E) `rollback` event for the consumer

Emit a typed event so the app can react (re-issue its own dropped change, refresh history, refetch):

```ts
group.on("rollback", (info: RollbackInfo) => {
  /* app re-issues its own change */
});

interface RollbackInfo {
  groupId: Uint8Array;
  targetEpoch: bigint; // epoch we rolled back to
  newHeadCommitEventId: string; // the winning commit now applied
  invalidatedMessages: string[]; // event ids dropped from the loser epoch
  messagesNeedingRefetch?: string[]; // optional: events to re-pull from relays
}
```

The library does **not** auto-replay the consumer's own change (matches MDK). Document the expected app handler.

### 6.6 (F) Bounded past-epoch decryption window

Retain the last `pastEpochDepth` epochs' message-decryption secrets (default ~5, MDK parity) so a lagging member decrypts recent application messages **without** forcing a rollback. Configurable; bounded for forward secrecy (§11).

### Phasing

- **Phase 1 (closes the fork):** (A) snapshots + (B) pending/clear + (C) rollback path. After this, two members converge and can decrypt each other again.
- **Phase 2 (correct history UX):** (D) invalidation/retry + (E) `rollback` event.
- **Phase 3 (robustness):** (F) past-epoch decryption window.

---

## 7. Public API / surface changes

| Surface                       | Change                                                                                    | Kind                |
| ----------------------------- | ----------------------------------------------------------------------------------------- | ------------------- |
| `MarmotGroup` events          | add `"rollback"` (`RollbackInfo`)                                                         | additive            |
| `EpochSnapshotStoreBackend`   | new backend interface + default in-memory/IDB impls                                       | additive            |
| `MarmotGroup` / client config | `snapshotDepth`, `pastEpochDepth` (+ optional max-age)                                    | additive, defaulted |
| `selfUpdate` / `commit`       | behavior change: snapshot before advance; `clearPendingCommit` on failure                 | behavior            |
| `ingest()`                    | behavior change: `past-epoch` commits may now trigger rollback + re-apply instead of skip | behavior            |
| Exported types                | `EpochSnapshot`, `RollbackInfo`                                                           | additive            |

Behavior changes are confined to the commit/ingest path; the happy single-committer path is unchanged (no competition → no snapshot use → no rollback). Wire format is unchanged (no new event kinds; reuses kind-445 commits and MIP-03 ordering).

---

## 8. Acceptance criteria

- **AC-1 (convergence).** Two members at epoch `N` that each publish a self-update commit converge: after both ingest both commits, they hold the **same** epoch, the **same** group state, and the **same** `exporter_secret`, and each can decrypt an application message the other sends afterward. _(This test fails on current HEAD and passes on the patched build.)_
- **AC-2 (deterministic winner).** The applied commit is the MIP-03 winner: earliest `created_at`, then lexicographically smallest event `id`. Both members independently pick the same winner.
- **AC-3 (loser rolls back).** The member whose commit lost ends on the winner's state via rollback to the epoch-`N` snapshot + re-apply, not on its own commit.
- **AC-4 (replay guard).** Ingesting the **same** winning commit again (e.g. our own relay echo, or a re-wrapped duplicate) does **not** trigger a rollback or change state.
- **AC-5 (message invalidation/retry).** Application messages decrypted under the losing epoch are reported invalidated; events that failed under the wrong keys are retried and decrypt after the winner is applied.
- **AC-6 (`rollback` event).** A `rollback` event fires once per rollback with correct `targetEpoch` and `newHeadCommitEventId`.
- **AC-7 (publish failure).** A commit whose publish gets no relay ack does **not** advance state and leaves no orphan snapshot (`clearPendingCommit`).
- **AC-8 (bounded retention).** Snapshots beyond `snapshotDepth` (and past the max age) are pruned; no unbounded growth.
- **AC-9 (happy-path regression).** With a single committer (no competition), there is no rollback and behavior/state matches pre-patch.
- **AC-10 (past-epoch decrypt, Phase 3).** A member one epoch behind decrypts a recent application message within `pastEpochDepth` without a rollback.

---

## 9. Test plan

**Integration (primary — reproduces the bug).** Two clients, in-memory stores, mock relay (use `src/__tests__/helpers`). Both join `Tasks`; both `selfUpdate()` at the same epoch; ingest both commits on both sides; assert AC-1 (identical epoch/state/exporter, cross-decrypt). Confirm it fails on HEAD and passes patched.

**Unit.**

- `isBetterCandidate` ordering: created_at precedence; id tiebreak; content-hash replay guard returns "not better / replay" (AC-2, AC-4).
- `rollbackToEpoch`: restores serialized pre-commit state byte-for-byte; re-apply yields the winner's state (AC-3).
- invalidation/retry bookkeeping (AC-5); `rollback` event payload (AC-6); `clearPendingCommit` on no-ack (AC-7); retention pruning (AC-8).

**Property test.** Randomly interleave concurrent commits across `K ≥ 2` members and random relay-delivery orderings; assert **all** members converge to one identical state (epoch, tree hash, exporter) and the applied commit equals the MIP-03 winner. This is the strongest guard against ordering-dependent divergence.

---

## 10. Migration — existing forked groups do NOT auto-heal

Phase 1 prevents _future_ forks; it cannot repair a group that already diverged, because no snapshot was ever taken on the old code. This is a **separate workstream**, not part of the fix above:

- **Recovery is out-of-band:** an admin removes and re-adds the diverged leaf (fresh Welcome), or the device re-joins. No MIP and no MDK code defines an automatic heal from an existing divergence (MIP-03 only says, without procedure, to retain prior states for recovery).
- **Optional detection heuristic:** if a member fails to decrypt commits/messages for `≥ M` consecutive epochs, surface a `divergenceSuspected` signal so the app can prompt re-add. Design TBD; flagged here so it isn't conflated with the prevention fix.
- **Consumer action (notestr-web):** after this ships, run a one-time pass that re-invites any device showing as a stale/undecryptable member of an existing group.

---

## 11. Forward-secrecy & security considerations

- **Snapshots retain old group state** (including old `exporter_secret`s) for the retention window — a direct forward-secrecy tradeoff. RFC 9420 §14 / RFC 9750 §14 require minimizing how long forked/previous states live. Mitigate: keep `snapshotDepth` small (default 2–5), enforce a max age, prune aggressively on advance, and protect snapshot storage with the same guarantees as live group state.
- **Past-epoch decryption window (F)** is the same tradeoff for message keys; keep `pastEpochDepth` configurable and documented, default modest.
- **Rollback is sender-authenticated by construction:** the winner is a normally-validated commit (admin callbacks still run); rollback only re-applies a commit that passes the existing `processMessage` verification. The replay guard (AC-4) prevents a re-wrapped duplicate from forcing spurious rollbacks.
- **No new wire surface**, so no new network-level attack surface; the change is local state-machine logic + storage.

---

## 12. Alternatives considered

| Option                                                                                   | Verdict                                                                                                                                                                                                                              |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Snapshot + MIP-03 rollback (this proposal)**                                           | **Accepted** — the MIP-03-mandated, MDK-implemented, OpenMLS-supported pattern. The only approach that actually converges two real members.                                                                                          |
| Serialize commits through a single designated committer (members only propose)           | **Complementary, not sufficient** — reduces collision frequency but cannot eliminate it: MIP-02's post-join self-update is member-initiated, and two admins still collide. Worth offering as an optional policy _on top of_ the fix. |
| Detect-and-heal via re-add only (no prevention)                                          | **Rejected as the fix** — incurs a forward-secrecy window of divergence + constant membership churn, and provides no convergence. Still needed as the _recovery_ path for already-forked groups (§10).                               |
| DAG-of-epochs / merge-friendly decentralized MLS (`draft-kohbrok-mls-decentralized-mls`) | **Rejected** — non-standard, not in RFC 9420, not what Marmot targets; research frontier, not a shipping option.                                                                                                                     |
| Do nothing / document as a known limitation                                              | **Rejected** — breaks multi-device, a core promise; the failure is silent and permanent.                                                                                                                                             |

---

## 13. Design decisions (resolved 2026-05-31)

1. **Snapshot storage:** **Sibling `EpochSnapshotStoreBackend`** — new backend interface with its own lifecycle, separate from live group state. Retention pruning is explicit and does not entangle the existing `GroupStateStoreBackend`.
2. **`snapshotDepth` default:** **2** — covers the join-time double self-update (depth ≥ 1) and one admin+member race. Best forward-secrecy posture; configurable for apps needing more.
3. **Auto-replay policy:** **Library converges + emits `rollback`; app re-issues its own change.** Matches MDK division. No `autoReplayOwnChange` helper in the library layer.
4. **`pastEpochDepth` default:** **5** — MDK parity. Configurable.
5. **Designated-committer option:** **Deferred.** Out of scope for this epic.
6. **Existing-fork detection (§10):** **Deferred.** Out of scope for this epic; flagged as a follow-up workstream.
7. **Phase scope:** **All 3 phases in scope** — Phase 1 (A+B+C: snapshot + pending/clear + rollback), Phase 2 (D+E: invalidation/retry + rollback event), Phase 3 (F: past-epoch decryption window).

---

## 14. References

- RFC 9420 (MLS Protocol) §12 (commits/epochs), §14 (sequencing, forward secrecy).
- RFC 9750 (MLS Architecture) §14 (fork handling, "first valid commit", minimize fork lifetime).
- Marmot MIP-03 (`parres-hq/marmot` `03.md`) — "Commit Message Race Conditions", "State Fork Risk".
- Marmot MIP-02 (`02.md`) — mandatory post-join self-update within 24h.
- NIP-EE — "state is separate … tracked as 2 separate members" (one leaf per device).
- MDK source (`parres-hq/mdk` @ master): `crates/mdk-core/src/groups.rs` (`self_update` / `add_members` / `remove_members` / `merge_pending_commit` / `clear_pending_commit`); `messages/commit.rs::process_commit` (snapshot-before-merge); `messages/error_handling.rs::handle_processing_error` (~L324–430, `ProcessMessageWrongEpoch` arm); `epoch_snapshots.rs` (`EpochSnapshot`, `is_better_candidate` ~L539, `rollback_to_epoch` ~L609); `messages/decryption.rs::try_decrypt_with_past_epochs`; `messages/process.rs` (`OwnCommitPending`).
- WhiteNoise (`parres-hq/whitenoise`): `publish_and_merge_commit`.
- OpenMLS Book — "Fork Resolution"; Cryspen — "MLS Group State Forks: What, Why, How".
- marmot-ts current gap: `src/client/group/marmot-group.ts` — `ingest()` `past-epoch` skip; `selfUpdate()` / `commit()` / `sendProposal()` advance-after-ack; `save()` keyed by group id only; `sortGroupCommits()` (existing MIP-03 ordering primitive).
- Companion specs: `specs/marmot-ts-welcome-grace-window.md`, `specs/marmot-ts-shared-ts-mls-feature-request.md`.
