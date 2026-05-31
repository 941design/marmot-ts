import type {
  EpochSnapshot,
  EpochSnapshotStoreBackend,
} from "../client/group/epoch-snapshot.js";

/**
 * In-memory reference implementation of {@link EpochSnapshotStoreBackend}.
 *
 * Snapshots are stored in a `Map` keyed by `"<groupIdHex>:<epoch>"`.  This
 * implementation is suitable for tests and for applications that do not need
 * durable snapshots across process restarts.
 *
 * `MarmotGroup` uses this class as the default when no `snapshots` option is
 * provided to `MarmotGroupOptions`.
 */
export class InMemoryEpochSnapshotStore implements EpochSnapshotStoreBackend {
  readonly #store = new Map<string, EpochSnapshot>();

  #key(groupIdHex: string, epoch: bigint): string {
    return `${groupIdHex}:${epoch}`;
  }

  async get(groupIdHex: string, epoch: bigint): Promise<EpochSnapshot | null> {
    return this.#store.get(this.#key(groupIdHex, epoch)) ?? null;
  }

  async set(
    groupIdHex: string,
    epoch: bigint,
    snapshot: EpochSnapshot,
  ): Promise<void> {
    this.#store.set(this.#key(groupIdHex, epoch), snapshot);
  }

  async prune(groupIdHex: string, keepAboveEpoch: bigint): Promise<void> {
    for (const key of this.#store.keys()) {
      const colonIdx = key.lastIndexOf(":");
      const id = key.slice(0, colonIdx);
      const epochStr = key.slice(colonIdx + 1);
      if (id === groupIdHex && BigInt(epochStr) <= keepAboveEpoch) {
        this.#store.delete(key);
      }
    }
  }

  async clear(groupIdHex: string): Promise<void> {
    for (const key of this.#store.keys()) {
      if (key.startsWith(`${groupIdHex}:`)) {
        this.#store.delete(key);
      }
    }
  }
}
