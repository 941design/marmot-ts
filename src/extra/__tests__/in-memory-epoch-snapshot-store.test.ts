import { describe, expect, it } from "vitest";
import { InMemoryEpochSnapshotStore } from "../in-memory-epoch-snapshot-store.js";
import type { EpochSnapshot } from "../../client/group/epoch-snapshot.js";

function makeGroupId(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

function makeSnapshot(
  groupId: Uint8Array,
  epoch: bigint,
  stateByte = 0xaa,
): EpochSnapshot {
  return {
    groupId,
    epoch,
    state: new Uint8Array([stateByte]) as any,
  };
}

const GROUP_A =
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GROUP_B =
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

describe("InMemoryEpochSnapshotStore", () => {
  describe("get returns null before set", () => {
    it("returns null for any epoch on a fresh store", async () => {
      const store = new InMemoryEpochSnapshotStore();
      expect(await store.get(GROUP_A, 0n)).toBeNull();
      expect(await store.get(GROUP_A, 5n)).toBeNull();
    });

    it("returns null for a different group even if the epoch matches", async () => {
      const store = new InMemoryEpochSnapshotStore();
      const groupId = makeGroupId(0xaa);
      await store.set(GROUP_A, 1n, makeSnapshot(groupId, 1n));
      expect(await store.get(GROUP_B, 1n)).toBeNull();
    });
  });

  describe("set → get round-trip", () => {
    it("retrieves the exact snapshot that was stored", async () => {
      const store = new InMemoryEpochSnapshotStore();
      const groupId = makeGroupId(0x01);
      const snap = makeSnapshot(groupId, 3n, 0x42);
      await store.set(GROUP_A, 3n, snap);
      const retrieved = await store.get(GROUP_A, 3n);
      expect(retrieved).toBe(snap); // same reference
    });

    it("latest write wins for duplicate keys", async () => {
      const store = new InMemoryEpochSnapshotStore();
      const groupId = makeGroupId(0x02);
      const snap1 = makeSnapshot(groupId, 2n, 0x11);
      const snap2 = makeSnapshot(groupId, 2n, 0x22);
      await store.set(GROUP_A, 2n, snap1);
      await store.set(GROUP_A, 2n, snap2);
      expect(await store.get(GROUP_A, 2n)).toBe(snap2);
    });

    it("stores multiple epochs independently", async () => {
      const store = new InMemoryEpochSnapshotStore();
      const groupId = makeGroupId(0x03);
      const snap0 = makeSnapshot(groupId, 0n, 0x01);
      const snap1 = makeSnapshot(groupId, 1n, 0x02);
      const snap2 = makeSnapshot(groupId, 2n, 0x03);
      await store.set(GROUP_A, 0n, snap0);
      await store.set(GROUP_A, 1n, snap1);
      await store.set(GROUP_A, 2n, snap2);
      expect(await store.get(GROUP_A, 0n)).toBe(snap0);
      expect(await store.get(GROUP_A, 1n)).toBe(snap1);
      expect(await store.get(GROUP_A, 2n)).toBe(snap2);
    });
  });

  describe("prune removes entries at or below epoch", () => {
    it("removes entries whose epoch <= keepAboveEpoch", async () => {
      const store = new InMemoryEpochSnapshotStore();
      const groupId = makeGroupId(0x04);
      for (let e = 0n; e <= 5n; e++) {
        await store.set(GROUP_A, e, makeSnapshot(groupId, e));
      }

      // Prune epochs 0, 1, 2 (keepAboveEpoch = 2n means <= 2n are deleted)
      await store.prune(GROUP_A, 2n);

      expect(await store.get(GROUP_A, 0n)).toBeNull();
      expect(await store.get(GROUP_A, 1n)).toBeNull();
      expect(await store.get(GROUP_A, 2n)).toBeNull();
      // 3, 4, 5 survive
      expect(await store.get(GROUP_A, 3n)).not.toBeNull();
      expect(await store.get(GROUP_A, 4n)).not.toBeNull();
      expect(await store.get(GROUP_A, 5n)).not.toBeNull();
    });

    it("only prunes the specified group, not others", async () => {
      const store = new InMemoryEpochSnapshotStore();
      const groupId = makeGroupId(0x05);
      await store.set(GROUP_A, 0n, makeSnapshot(groupId, 0n));
      await store.set(GROUP_A, 1n, makeSnapshot(groupId, 1n));
      await store.set(GROUP_B, 0n, makeSnapshot(groupId, 0n));
      await store.set(GROUP_B, 1n, makeSnapshot(groupId, 1n));

      await store.prune(GROUP_A, 0n);

      // GROUP_A epoch 0 pruned, epoch 1 survives
      expect(await store.get(GROUP_A, 0n)).toBeNull();
      expect(await store.get(GROUP_A, 1n)).not.toBeNull();
      // GROUP_B untouched
      expect(await store.get(GROUP_B, 0n)).not.toBeNull();
      expect(await store.get(GROUP_B, 1n)).not.toBeNull();
    });

    it("is a no-op when store is empty", async () => {
      const store = new InMemoryEpochSnapshotStore();
      await expect(store.prune(GROUP_A, 100n)).resolves.toBeUndefined();
    });

    it("is a no-op when keepAboveEpoch is negative (no epochs pruned)", async () => {
      const store = new InMemoryEpochSnapshotStore();
      const groupId = makeGroupId(0x06);
      await store.set(GROUP_A, 0n, makeSnapshot(groupId, 0n));
      // keepAboveEpoch = -1n means prune epochs <= -1, which is none
      await store.prune(GROUP_A, -1n);
      expect(await store.get(GROUP_A, 0n)).not.toBeNull();
    });
  });

  describe("clear removes all entries for a group", () => {
    it("removes all epochs for the group", async () => {
      const store = new InMemoryEpochSnapshotStore();
      const groupId = makeGroupId(0x07);
      for (let e = 0n; e <= 4n; e++) {
        await store.set(GROUP_A, e, makeSnapshot(groupId, e));
      }
      await store.clear(GROUP_A);
      for (let e = 0n; e <= 4n; e++) {
        expect(await store.get(GROUP_A, e)).toBeNull();
      }
    });

    it("only removes the specified group, not others", async () => {
      const store = new InMemoryEpochSnapshotStore();
      const groupId = makeGroupId(0x08);
      await store.set(GROUP_A, 0n, makeSnapshot(groupId, 0n));
      await store.set(GROUP_B, 0n, makeSnapshot(groupId, 0n));
      await store.clear(GROUP_A);
      expect(await store.get(GROUP_A, 0n)).toBeNull();
      expect(await store.get(GROUP_B, 0n)).not.toBeNull();
    });

    it("is a no-op on an already-cleared group", async () => {
      const store = new InMemoryEpochSnapshotStore();
      await expect(store.clear(GROUP_A)).resolves.toBeUndefined();
    });
  });
});
