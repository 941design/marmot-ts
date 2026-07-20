import { PrivateKeyAccount } from "applesauce-accounts/accounts";
import type { NostrEvent } from "applesauce-core/helpers/event";
import type { Rumor } from "applesauce-common/helpers/gift-wrap";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { InviteManager } from "../invite-manager.js";
import type {
  ReceivedGiftWrap,
  StoredInviteEntry,
  UnreadInvite,
} from "../invite-manager.js";
import type { GenericKeyValueStore } from "../../utils/key-value.js";
import { WELCOME_EVENT_KIND } from "../../core/protocol.js";

/**
 * Simple in-memory backend for testing
 */
class MemoryBackend<T> implements GenericKeyValueStore<T> {
  private map = new Map<string, T>();

  async getItem(key: string): Promise<T | null> {
    return this.map.get(key) ?? null;
  }

  async setItem(key: string, value: T): Promise<T> {
    this.map.set(key, value);
    return value;
  }

  async removeItem(key: string): Promise<void> {
    this.map.delete(key);
  }

  async clear(): Promise<void> {
    this.map.clear();
  }

  async keys(): Promise<string[]> {
    return Array.from(this.map.keys());
  }
}

/**
 * Create a mock gift wrap event (kind 1059)
 */
function createMockGiftWrap(id: string, recipientPubkey: string): NostrEvent {
  return {
    id,
    kind: 1059,
    pubkey: "sender-pubkey",
    created_at: Math.floor(Date.now() / 1000),
    tags: [["p", recipientPubkey]],
    content: "encrypted-content",
    sig: "signature",
  };
}

/**
 * Create a mock Welcome rumor (kind 444)
 */
function createMockWelcomeRumor(
  id: string,
  senderPubkey: string,
  keyPackageEventId = "test-key-package-id",
): Rumor {
  return {
    id,
    kind: WELCOME_EVENT_KIND,
    pubkey: senderPubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ["relays", "wss://relay1.test", "wss://relay2.test"],
      ["e", keyPackageEventId],
      ["encoding", "base64"],
    ],
    content: "base64-encoded-welcome-message",
  };
}

/** Helper to read the seen IDs from the store */
async function getSeenIds(
  store: GenericKeyValueStore<StoredInviteEntry>,
): Promise<string[]> {
  const entry = await store.getItem("__seen");
  if (entry && entry.type === "seen") return entry.ids;
  return [];
}

describe("InviteManager", () => {
  let store: GenericKeyValueStore<StoredInviteEntry>;
  let account: PrivateKeyAccount<any>;
  let inviteManager: InviteManager;

  beforeEach(async () => {
    store = new MemoryBackend<StoredInviteEntry>();
    account = PrivateKeyAccount.generateNew();

    inviteManager = new InviteManager({
      signer: account.signer,
      store,
    });
  });

  describe("ingestEvent", () => {
    it("should ingest a new gift wrap event", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("test-id-1", pubkey);

      const isNew = await inviteManager.ingestEvent(giftWrap);

      expect(isNew).toBe(true);

      // Check it's in received state
      const received = await inviteManager.getReceived();
      expect(received).toHaveLength(1);
      expect(received[0].id).toBe(giftWrap.id);
      expect(received[0]).toEqual(giftWrap);

      // Check it's marked as seen
      const seenIds = await getSeenIds(store);
      expect(seenIds).toContain(giftWrap.id);
    });

    it("should skip duplicate events", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("test-id-1", pubkey);

      // Ingest first time
      const isNew1 = await inviteManager.ingestEvent(giftWrap);
      expect(isNew1).toBe(true);

      // Ingest second time (duplicate)
      const isNew2 = await inviteManager.ingestEvent(giftWrap);
      expect(isNew2).toBe(false);

      // Should only have one received event
      const received = await inviteManager.getReceived();
      expect(received).toHaveLength(1);
    });

    it("should throw on non-gift-wrap events", async () => {
      const invalidEvent = {
        id: "test",
        pubkey: "test-pubkey",
        created_at: Math.floor(Date.now() / 1000),
        kind: 1, // Regular note, not gift wrap
        tags: [],
        content: "test",
        sig: "test",
      } as NostrEvent;

      await expect(inviteManager.ingestEvent(invalidEvent)).rejects.toThrow(
        "Expected kind 1059 gift wrap",
      );
    });
  });

  describe("ingestEvents", () => {
    it("should ingest multiple events in batch", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap1 = createMockGiftWrap("test-id-1", pubkey);
      const giftWrap2 = createMockGiftWrap("test-id-2", pubkey);

      const newCount = await inviteManager.ingestEvents([giftWrap1, giftWrap2]);

      expect(newCount).toBe(2);

      const received = await inviteManager.getReceived();
      expect(received).toHaveLength(2);
    });

    it("should handle invalid events gracefully", async () => {
      const pubkey = await account.signer.getPublicKey();
      const validGiftWrap = createMockGiftWrap("test-id-1", pubkey);

      const invalidEvent = {
        id: "invalid",
        kind: 1,
        pubkey: "test",
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: "invalid",
        sig: "sig",
      } as NostrEvent;

      let errorEmitted = false;
      inviteManager.on("error", (err, eventId) => {
        errorEmitted = true;
        expect(eventId).toBe("invalid");
      });

      const newCount = await inviteManager.ingestEvents([
        validGiftWrap,
        invalidEvent,
      ]);

      expect(newCount).toBe(1); // Only valid event counted
      expect(errorEmitted).toBe(true);
    });

    describe("batched seen-set persistence (cold-start drain)", () => {
      /**
       * Wraps MemoryBackend and records every `setItem` call, so a test can
       * assert both the *count* of writes to a given key and their relative
       * *order* against writes to other keys — the two things that matter
       * for O(n) batching + crash-safe ordering.
       */
      class CountingBackend<T> implements GenericKeyValueStore<T> {
        private inner = new MemoryBackend<T>();
        public writeLog: string[] = [];

        async getItem(key: string): Promise<T | null> {
          return this.inner.getItem(key);
        }

        async setItem(key: string, value: T): Promise<T> {
          this.writeLog.push(key);
          return this.inner.setItem(key, value);
        }

        async removeItem(key: string): Promise<void> {
          return this.inner.removeItem(key);
        }

        async clear(): Promise<void> {
          return this.inner.clear();
        }

        async keys(): Promise<string[]> {
          return this.inner.keys();
        }

        seenWriteCount(): number {
          return this.writeLog.filter((k) => k === "__seen").length;
        }
      }

      it("persists the seen-set exactly once for a batch of N new events, not once per event", async () => {
        const pubkey = await account.signer.getPublicKey();
        const countingStore = new CountingBackend<StoredInviteEntry>();
        const manager = new InviteManager({
          signer: account.signer,
          store: countingStore,
        });

        const N = 25;
        const events = Array.from({ length: N }, (_, i) =>
          createMockGiftWrap(`batch-id-${i}`, pubkey),
        );

        const newCount = await manager.ingestEvents(events);

        expect(newCount).toBe(N);
        // O(n) received writes, but exactly ONE seen-set persist — not N.
        expect(countingStore.seenWriteCount()).toBe(1);

        const seenIds = await getSeenIds(countingStore);
        expect(seenIds).toHaveLength(N);
      });

      it("writes every received:<id> before the single batch-end seen persist (crash-safe ordering)", async () => {
        const pubkey = await account.signer.getPublicKey();
        const countingStore = new CountingBackend<StoredInviteEntry>();
        const manager = new InviteManager({
          signer: account.signer,
          store: countingStore,
        });

        const N = 10;
        const events = Array.from({ length: N }, (_, i) =>
          createMockGiftWrap(`order-id-${i}`, pubkey),
        );

        await manager.ingestEvents(events);

        const seenIndex = countingStore.writeLog.indexOf("__seen");
        expect(seenIndex).toBe(N); // after all N `received:` writes
        expect(seenIndex).toBeGreaterThan(-1);

        const receivedWrites = countingStore.writeLog.filter((k) =>
          k.startsWith("received:"),
        );
        expect(receivedWrites).toHaveLength(N);

        // Every received:<id> write must appear before the (single) seen
        // write — a crash before the seen flush leaves ids
        // received-but-not-seen (safe/re-drivable), never the reverse.
        for (const key of receivedWrites) {
          expect(countingStore.writeLog.indexOf(key)).toBeLessThan(seenIndex);
        }
      });

      it("produces the same seen-set contents as ingesting the same events one-by-one via ingestEvent", async () => {
        const pubkey = await account.signer.getPublicKey();
        const events = Array.from({ length: 8 }, (_, i) =>
          createMockGiftWrap(`parity-id-${i}`, pubkey),
        );

        const batchStore = new MemoryBackend<StoredInviteEntry>();
        const batchManager = new InviteManager({
          signer: account.signer,
          store: batchStore,
        });
        await batchManager.ingestEvents(events);

        const singleStore = new MemoryBackend<StoredInviteEntry>();
        const singleManager = new InviteManager({
          signer: account.signer,
          store: singleStore,
        });
        for (const event of events) {
          await singleManager.ingestEvent(event);
        }

        const batchSeen = (await getSeenIds(batchStore)).sort();
        const singleSeen = (await getSeenIds(singleStore)).sort();
        expect(batchSeen).toEqual(singleSeen);

        const batchReceived = (await batchManager.getReceived())
          .map((e) => e.id)
          .sort();
        const singleReceived = (await singleManager.getReceived())
          .map((e) => e.id)
          .sort();
        expect(batchReceived).toEqual(singleReceived);
      });

      it("does not re-ingest (or re-count) already-seen wraps after a reload, preserving dedup across the batch flush", async () => {
        const pubkey = await account.signer.getPublicKey();
        const countingStore = new CountingBackend<StoredInviteEntry>();
        const events = Array.from({ length: 5 }, (_, i) =>
          createMockGiftWrap(`reload-id-${i}`, pubkey),
        );

        const firstManager = new InviteManager({
          signer: account.signer,
          store: countingStore,
        });
        const firstCount = await firstManager.ingestEvents(events);
        expect(firstCount).toBe(5);

        // Simulate a reload: fresh InviteManager instance (no in-memory
        // seenCache) reading from the same persisted store.
        const reloadedManager = new InviteManager({
          signer: account.signer,
          store: countingStore,
        });
        const secondCount = await reloadedManager.ingestEvents(events);

        // All 5 wraps are already seen — nothing new, and no seen-set
        // rewrite should occur for an all-duplicate batch.
        expect(secondCount).toBe(0);
        expect(countingStore.seenWriteCount()).toBe(1); // unchanged from first batch

        const received = await reloadedManager.getReceived();
        expect(received).toHaveLength(5); // unchanged — no duplicate storage
      });
    });
  });

  describe("decryptGiftWraps", () => {
    it("should emit error on decrypt failure", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("test-id-1", pubkey);

      await inviteManager.ingestEvent(giftWrap);

      let errorEmitted = false;
      inviteManager.on("error", (err, eventId) => {
        errorEmitted = true;
        expect(eventId).toBe("test-id-1");
      });

      const unread = await inviteManager.decryptGiftWraps();

      // Since we can't properly decrypt without full infrastructure, this will fail
      expect(unread).toHaveLength(0);
      expect(errorEmitted).toBe(true);

      // Should be removed from received even on failure
      const received = await inviteManager.getReceived();
      expect(received).toHaveLength(0);
    });

    it("should still strip the wrap from received on decrypt failure when shouldRemoveOnFailure is omitted (default preserves today's behavior)", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("default-strip-id", pubkey);

      // `inviteManager` (from beforeEach) is constructed with no
      // `shouldRemoveOnFailure` option at all — this exercises AC-FORK-1.
      await inviteManager.ingestEvent(giftWrap);

      const result = await inviteManager.decryptGiftWrap(giftWrap.id);
      expect(result).toBeNull();

      const received = await inviteManager.getReceived();
      expect(received.find((r) => r.id === giftWrap.id)).toBeUndefined();
    });

    it("should NOT strip the wrap from received when shouldRemoveOnFailure returns false, and it remains retrievable afterward", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("retryable-id", pubkey);

      // AC-FORK-2: a supplied predicate returning false must prevent the strip.
      const retainingManager = new InviteManager({
        signer: account.signer,
        store,
        shouldRemoveOnFailure: () => false,
      });

      await retainingManager.ingestEvent(giftWrap);

      const result = await retainingManager.decryptGiftWrap(giftWrap.id);
      expect(result).toBeNull();

      // Still present via getReceived() ...
      const received = await retainingManager.getReceived();
      expect(received.find((r) => r.id === giftWrap.id)).toEqual(giftWrap);

      // ... and a subsequent decryptGiftWrap(id) call can still find and
      // re-attempt it (it wasn't lost after the first failed attempt).
      const retryResult = await retainingManager.decryptGiftWrap(giftWrap.id);
      expect(retryResult).toBeNull();
      const receivedAfterRetry = await retainingManager.getReceived();
      expect(receivedAfterRetry.find((r) => r.id === giftWrap.id)).toEqual(
        giftWrap,
      );
    });

    it("should pass the caught error and the giftwrap to shouldRemoveOnFailure", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("predicate-args-id", pubkey);

      let capturedError: unknown;
      let capturedGiftwrap: unknown;
      const spyManager = new InviteManager({
        signer: account.signer,
        store,
        shouldRemoveOnFailure: (error, giftwrap) => {
          capturedError = error;
          capturedGiftwrap = giftwrap;
          return true;
        },
      });

      await spyManager.ingestEvent(giftWrap);
      await spyManager.decryptGiftWrap(giftWrap.id);

      expect(capturedError).toBeInstanceOf(Error);
      expect(capturedGiftwrap).toEqual(giftWrap);
    });

    it("should fall back to stripping (fail safe) when shouldRemoveOnFailure itself throws", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("predicate-throws-id", pubkey);

      const throwingManager = new InviteManager({
        signer: account.signer,
        store,
        shouldRemoveOnFailure: () => {
          throw new Error("predicate boom");
        },
      });

      await throwingManager.ingestEvent(giftWrap);

      const result = await throwingManager.decryptGiftWrap(giftWrap.id);
      expect(result).toBeNull();

      const received = await throwingManager.getReceived();
      expect(received.find((r) => r.id === giftWrap.id)).toBeUndefined();
    });
  });

  describe("getUnread", () => {
    it("should return empty array when no unread invites", async () => {
      const unread = await inviteManager.getUnread();
      expect(unread).toHaveLength(0);
    });
  });

  describe("getReceived", () => {
    it("should return all received invites", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap1 = createMockGiftWrap("test-id-1", pubkey);
      const giftWrap2 = createMockGiftWrap("test-id-2", pubkey);

      await inviteManager.ingestEvents([giftWrap1, giftWrap2]);

      const received = await inviteManager.getReceived();
      expect(received).toHaveLength(2);
    });
  });

  describe("markAsRead", () => {
    it("should remove invite from unread", async () => {
      // Manually add an unread invite to test markAsRead
      const unread: UnreadInvite = createMockWelcomeRumor("rumor-1", "sender");
      const id = "test-id-1";

      await store.setItem(`unread:${id}`, { type: "unread", rumor: unread });

      const unreadBefore = await inviteManager.getUnread();
      expect(unreadBefore).toHaveLength(1);

      await inviteManager.markAsRead(id);

      const unreadAfter = await inviteManager.getUnread();
      expect(unreadAfter).toHaveLength(0);
    });

    it("should emit read event", async () => {
      const unread: UnreadInvite = createMockWelcomeRumor("rumor-1", "sender");

      await store.setItem(`unread:${unread.id}`, {
        type: "unread",
        rumor: unread,
      });

      let eventEmitted = false;
      let emittedId = "";
      inviteManager.on("read", (inviteId) => {
        eventEmitted = true;
        emittedId = inviteId;
      });

      await inviteManager.markAsRead(unread.id);

      expect(eventEmitted).toBe(true);
      expect(emittedId).toBe("rumor-1");
    });
  });

  describe("watchUnread", () => {
    it("should yield initial unread invites", async () => {
      // Manually add an unread invite
      const unread: UnreadInvite = createMockWelcomeRumor("rumor-1", "sender");

      await store.setItem(`unread:${unread.id}`, {
        type: "unread",
        rumor: unread,
      });

      const generator = inviteManager.watchUnread();
      const { value } = await generator.next();

      expect(value).toHaveLength(1);
      expect(value![0]).toEqual(unread);
    });

    it("should yield when invite is marked as read", async () => {
      // Add an unread invite
      const unread: UnreadInvite = createMockWelcomeRumor("rumor-1", "sender");

      await store.setItem(`unread:${unread.id}`, {
        type: "unread",
        rumor: unread,
      });

      const generator = inviteManager.watchUnread();

      // Get initial state (1 invite)
      const initial = await generator.next();
      expect(initial.value).toHaveLength(1);

      // Mark as read in background
      setTimeout(async () => {
        await inviteManager.markAsRead(unread.id);
      }, 10);

      // Should yield when invite is marked as read
      const updated = await generator.next();
      expect(updated.value).toHaveLength(0);
    });
  });

  describe("watchReceived", () => {
    it("should yield initial received invites", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("test-id-1", pubkey);

      await inviteManager.ingestEvent(giftWrap);

      const generator = inviteManager.watchReceived();
      const { value } = await generator.next();

      expect(value).toHaveLength(1);
      expect(value[0].id).toBe(giftWrap.id);
    });

    it("should yield when new gift wrap is received", async () => {
      const pubkey = await account.signer.getPublicKey();
      const generator = inviteManager.watchReceived();

      // Get initial (empty) state
      const initial = await generator.next();
      expect(initial.value).toHaveLength(0);

      // Add gift wrap in background
      setTimeout(async () => {
        const giftWrap = createMockGiftWrap("test-id-1", pubkey);
        await inviteManager.ingestEvent(giftWrap);
      }, 10);

      // Should yield when new gift wrap is received
      const updated = await generator.next();
      expect(updated.value).toHaveLength(1);
    });

    it("should yield when received invite is processed", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("test-id-1", pubkey);

      await inviteManager.ingestEvent(giftWrap);

      const generator = inviteManager.watchReceived();

      // Get initial state (1 gift wrap)
      const initial = await generator.next();
      expect(initial.value).toHaveLength(1);

      // Process received in background (will fail to decrypt but still remove)
      setTimeout(async () => {
        await inviteManager.decryptGiftWraps();
      }, 10);

      // Should yield when gift wrap is processed (removed)
      const updated = await generator.next();
      expect(updated.value).toHaveLength(0);
    });
  });

  describe("events", () => {
    it("should emit received when gift wrap is ingested", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("test-id-1", pubkey);

      let eventEmitted = false;
      let emittedInvite: any = null;

      inviteManager.on("received", (invite) => {
        eventEmitted = true;
        emittedInvite = invite;
      });

      await inviteManager.ingestEvent(giftWrap);

      expect(eventEmitted).toBe(true);
      expect(emittedInvite.id).toBe(giftWrap.id);
    });

    it("should emit processed when gift wrap is decrypted", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("test-id-1", pubkey);

      await inviteManager.ingestEvent(giftWrap);

      let eventEmitted = false;
      let emittedId = "";

      inviteManager.on("processed", (inviteId) => {
        eventEmitted = true;
        emittedId = inviteId;
      });

      // This will fail to decrypt but should still emit processed
      await inviteManager.decryptGiftWraps();

      expect(eventEmitted).toBe(true);
      expect(emittedId).toBe(giftWrap.id);
    });
  });

  describe("clear", () => {
    it("should clear received and unread but not seen", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("test-id-1", pubkey);

      await inviteManager.ingestEvent(giftWrap);

      const receivedBefore = await inviteManager.getReceived();
      expect(receivedBefore).toHaveLength(1);

      await inviteManager.clear();

      const receivedAfter = await inviteManager.getReceived();
      const unreadAfter = await inviteManager.getUnread();

      expect(receivedAfter).toHaveLength(0);
      expect(unreadAfter).toHaveLength(0);

      // Seen index should NOT be cleared
      const seenIds = await getSeenIds(store);
      expect(seenIds).toContain(giftWrap.id);
    });
  });

  describe("clearSeen", () => {
    it("should clear the seen index", async () => {
      const pubkey = await account.signer.getPublicKey();
      const giftWrap = createMockGiftWrap("test-id-1", pubkey);

      await inviteManager.ingestEvent(giftWrap);

      const seenBefore = await getSeenIds(store);
      expect(seenBefore).toContain(giftWrap.id);

      await inviteManager.clearSeen();

      const seenAfter = await getSeenIds(store);
      expect(seenAfter).toHaveLength(0);
    });
  });
});
