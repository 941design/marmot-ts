/** @module @category Client - Group */
import type { SerializedClientState } from "../../core/client-state.js";

/**
 * An immutable snapshot of MLS group state at a given epoch.
 *
 * The `state` field holds the raw TLS-serialized `ClientState` bytes
 * produced by `serializeClientState` immediately *before* the commit that
 * advanced the group to `epoch + 1` was applied.  `appliedCommit` records
 * the identity of that commit event so later rollback logic can decide
 * whether a competing commit is a better candidate.
 */
export interface EpochSnapshot {
  /** The MLS group ID bytes (same as `ClientState.groupContext.groupId`). */
  groupId: Uint8Array;
  /** The epoch this snapshot covers (the epoch *before* the advance). */
  epoch: bigint;
  /** Pre-apply serialized `ClientState` — raw TLS bytes, no JSON wrapping. */
  state: SerializedClientState;
  /**
   * Metadata for the commit event that caused the transition away from this
   * epoch.  Absent when the snapshot was written for `selfUpdate` / `commit`
   * paths before the event identity is known.
   */
  appliedCommit?: {
    /** Nostr event ID (hex) of the commit. */
    eventId: string;
    /** `created_at` Unix timestamp of the commit event. */
    createdAt: number;
    /** SHA-256 of the raw `content` field of the commit event (UTF-8 bytes). */
    contentHash: Uint8Array;
  };
}

/**
 * Storage backend contract for epoch snapshots.
 *
 * Keys are `(groupIdHex, epoch)` pairs.  Implementations may be in-memory
 * (reference) or persistent (durable across process restarts).
 *
 * All methods are async so persistent backends can be plugged in without
 * requiring a wrapper.
 */
export interface EpochSnapshotStoreBackend {
  /**
   * Retrieves the snapshot for the given group and epoch.
   * Returns `null` when no snapshot exists for that key.
   */
  get(groupIdHex: string, epoch: bigint): Promise<EpochSnapshot | null>;

  /**
   * Stores a snapshot for the given group and epoch.
   * Overwrites any previously stored snapshot for the same key.
   */
  set(
    groupIdHex: string,
    epoch: bigint,
    snapshot: EpochSnapshot,
  ): Promise<void>;

  /**
   * Removes all snapshots for the given group whose epoch is
   * **less than or equal to** `keepAboveEpoch`.
   *
   * This is intentionally an "at-or-below" prune: pass
   * `currentEpoch - snapshotDepth` to retain exactly `snapshotDepth`
   * epochs of history.
   */
  prune(groupIdHex: string, keepAboveEpoch: bigint): Promise<void>;

  /**
   * Removes all snapshots for the given group.
   * Called when the group is destroyed.
   */
  clear(groupIdHex: string): Promise<void>;
}

/**
 * A factory function that produces an `EpochSnapshotStoreBackend` scoped to
 * a specific group.  Pass this to `MarmotGroupOptions.snapshots` when you
 * want each group to own its own isolated backend instance.
 */
export type EpochSnapshotStoreFactory = (
  groupId: Uint8Array,
) => EpochSnapshotStoreBackend;
