import { PrivateKeyAccount } from "applesauce-accounts/accounts";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  KeyPackageManager,
  MissingRelayError,
  MissingSlotIdentifierError,
  StoredKeyPackage,
} from "../key-package-manager.js";
import {
  getKeyPackageIdentifier,
  getKeyPackageRelays,
} from "../../core/key-package-event.js";
import {
  ADDRESSABLE_KEY_PACKAGE_KIND,
  KEY_PACKAGE_KIND,
} from "../../core/protocol.js";
import { MockNetwork } from "../../__tests__/helpers/mock-network.js";
import { InMemoryKeyValueStore } from "../../extra/in-memory-key-value-store";
import { generateKeyPackage } from "../../core/key-package.js";
import { createCredential } from "../../core/credential.js";
import { defaultCryptoProvider, getCiphersuiteImpl } from "ts-mls";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_CLIENT_ID = "test-client-desktop";

function makeManager(
  network: MockNetwork,
  account: PrivateKeyAccount<any>,
  clientId?: string,
) {
  const manager = new KeyPackageManager({
    store: new InMemoryKeyValueStore(),
    signer: account.signer,
    network,
    clientId,
  });
  // `store` is the manager itself — KeyPackageStore was merged into KeyPackageManager
  return { manager, store: manager };
}

/** Returns the published NostrEvent[] for a ref, or [] if none */
async function getPublished(
  manager: KeyPackageManager,
  ref: Uint8Array | string,
) {
  return (await manager.get(ref))?.published ?? [];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("KeyPackageManager", () => {
  let account: PrivateKeyAccount<any>;
  let network: MockNetwork;

  beforeEach(() => {
    account = PrivateKeyAccount.generateNew();
    network = new MockNetwork(["wss://relay.test"]);
  });

  // -------------------------------------------------------------------------
  // create()
  // -------------------------------------------------------------------------

  describe("create()", () => {
    it("throws MissingRelayError if no relays are provided", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      await expect(
        manager.create({ relays: [], identifier: TEST_CLIENT_ID }),
      ).rejects.toThrow(MissingRelayError);
    });

    it("throws MissingSlotIdentifierError if no d and no clientId", async () => {
      const { manager } = makeManager(network, account); // no clientId
      await expect(
        manager.create({ relays: ["wss://relay.test"] }),
      ).rejects.toThrow(MissingSlotIdentifierError);
    });

    it("uses manager clientId when no d is passed in options", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      expect(pkg.identifier).toBe(TEST_CLIENT_ID);
    });

    it("uses explicit d option, overriding clientId", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const explicitD = "explicit-slot-id";
      const pkg = await manager.create({
        relays: ["wss://relay.test"],
        identifier: explicitD,
      });

      expect(pkg.identifier).toBe(explicitD);
    });

    it("stores the slot identifier under identifier, not d", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const stored = await manager.get(pkg.keyPackageRef);
      const storedRecord = stored as Record<string, unknown> | null;

      expect(stored?.identifier).toBe(TEST_CLIENT_ID);
      expect(storedRecord?.d).toBeUndefined();
    });

    it("stores private key material locally", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      expect(await manager.count()).toBe(1);
      expect(await manager.has(pkg.keyPackageRef)).toBe(true);
    });

    it("publishes a kind 30443 event to the network", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      await manager.create({ relays: ["wss://relay.test"] });

      const published = network.events.filter(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      );
      expect(published).toHaveLength(1);
    });

    it("does not publish any kind 443 events", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      await manager.create({ relays: ["wss://relay.test"] });

      const legacy = network.events.filter((e) => e.kind === KEY_PACKAGE_KIND);
      expect(legacy).toHaveLength(0);
    });

    it("published event includes the d tag", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      await manager.create({ relays: ["wss://relay.test"] });

      const event = network.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;
      expect(getKeyPackageIdentifier(event)).toBe(TEST_CLIENT_ID);
    });

    it("two create() calls with clientId produce events with the same d tag", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      await manager.create({ relays: ["wss://relay.test"] });
      await manager.create({ relays: ["wss://relay.test"] });

      const events = network.events.filter(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      );
      expect(events).toHaveLength(2);
      expect(getKeyPackageIdentifier(events[0])).toBe(TEST_CLIENT_ID);
      expect(getKeyPackageIdentifier(events[1])).toBe(TEST_CLIENT_ID);
    });

    it("records the published event on the stored entry", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const events = await getPublished(manager, pkg.keyPackageRef);
      expect(events).toHaveLength(1);

      const networkEvent = network.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      );
      expect(events[0].id).toBe(networkEvent?.id);
    });

    it("records relay URLs on the published event", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const events = await getPublished(manager, pkg.keyPackageRef);
      expect(getKeyPackageRelays(events[0])).toEqual(["wss://relay.test/"]);
    });

    it("emits added and published events", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      const added = vi.fn();
      const published = vi.fn();
      manager.on("added", added);
      manager.on("published", published);

      await manager.create({ relays: ["wss://relay.test"] });

      expect(added).toHaveBeenCalledOnce();
      expect(published).toHaveBeenCalledOnce();
    });

    it("deduplicates repeated addressable published events for the same ref via track()", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      // Simulate the same key package being observed again on another relay
      const originalEvent = network.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;
      await manager.track({ ...originalEvent, id: "b".repeat(64) });

      const events = await getPublished(manager, pkg.keyPackageRef);
      expect(events).toHaveLength(1);
    });
  });

  // -------------------------------------------------------------------------
  // rotate()
  // -------------------------------------------------------------------------

  describe("rotate()", () => {
    it("throws if the key package ref is not found in local private store", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const fakeRef = new Uint8Array(32).fill(0xab);
      await expect(manager.rotate(fakeRef)).rejects.toThrow(
        "Key package not found",
      );
    });

    it("throws if no relays can be determined for the new key package", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      // Add a key package to the private store without any published events
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await manager.add(kp);

      const listed = await manager.list();
      await expect(
        manager.rotate(listed[0].keyPackageRef, { relays: undefined }),
      ).rejects.toThrow("no relay URLs available");
    });

    it("reuses the same d slot from the stored entry", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const newPkg = await manager.rotate(pkg.keyPackageRef);

      // New package should still use the same slot identifier
      expect(newPkg.identifier).toBe(TEST_CLIENT_ID);
      const addrEvents = network.events.filter(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      );
      const newEvent = addrEvents[addrEvents.length - 1]!;
      expect(getKeyPackageIdentifier(newEvent)).toBe(TEST_CLIENT_ID);
    });

    it("generates a random d when old entry has no d (legacy 443 upgrade)", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      // Inject a stored entry without a d to simulate a legacy 443 package
      // Uses top-level imports for generateKeyPackage, createCredential, etc.
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      // add without d — simulates legacy entry
      await manager.add(kp);

      const listed = await manager.list();
      const newPkg = await manager.rotate(listed[0].keyPackageRef, {
        relays: ["wss://relay.test"],
      });

      // Should have some d, just not a specific one
      expect(newPkg.identifier).toBeDefined();
      expect(typeof newPkg.identifier).toBe("string");
      expect(newPkg.identifier!.length).toBeGreaterThan(0);
    });

    it("does NOT send a NIP-09 deletion for kind 30443 published events", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.rotate(pkg.keyPackageRef);

      // No kind 5 deletion should have been published
      const deleteEvents = network.events.filter((e) => e.kind === 5);
      expect(deleteEvents).toHaveLength(0);
    });

    it("sends NIP-09 deletion only for kind 443 published events on the entry", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      // Inject a stored entry with a legacy kind 443 published event
      // Uses top-level imports for generateKeyPackage, createCredential, etc.
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });

      const fakeRelayUrl = "wss://relay.test/";
      const fakeLegacyEvent = {
        kind: KEY_PACKAGE_KIND,
        id: "legacy443event",
        pubkey,
        created_at: 1000,
        content: "",
        tags: [
          ["relays", fakeRelayUrl],
          ["i", "a".repeat(64)],
        ],
        sig: "sig",
      };
      await manager.add({ ...kp, published: [fakeLegacyEvent] });

      const listed = await manager.list();
      await manager.rotate(listed[0].keyPackageRef, {
        relays: ["wss://relay.test"],
      });

      // A kind 5 deletion should have been sent for the legacy event
      const deleteEvents = network.events.filter((e) => e.kind === 5);
      expect(deleteEvents).toHaveLength(1);
      const eTags = deleteEvents[0].tags.filter((t) => t[0] === "e");
      expect(eTags).toContainEqual(["e", "legacy443event"]);
    });

    it("creates and publishes a new kind 30443 event", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.rotate(pkg.keyPackageRef);

      const keyPackageEvents = network.events.filter(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      );
      // One from create(), one from rotate()
      expect(keyPackageEvents).toHaveLength(2);
    });

    it("deprecates the old entry after rotation (count drops, has() still true)", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      expect(await manager.count()).toBe(1);
      await manager.rotate(pkg.keyPackageRef);

      // count() only includes active (non-deprecated) entries, so new total is 1
      expect(await manager.count()).toBe(1);
      // has() returns true for deprecated entries — private key still accessible
      // for Welcome decryption during the grace window
      expect(await manager.has(pkg.keyPackageRef)).toBe(true);
    });

    it("deprecated old entry is excluded from list() after rotation", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.rotate(pkg.keyPackageRef);

      const listed = await manager.list();
      // Only the new (active) entry should appear
      expect(listed).toHaveLength(1);
      const listedRefs = listed.map((p) =>
        Buffer.from(p.keyPackageRef).toString("hex"),
      );
      expect(listedRefs).not.toContain(
        Buffer.from(pkg.keyPackageRef).toString("hex"),
      );
    });

    it("old published events remain accessible on deprecated entry after rotation", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.rotate(pkg.keyPackageRef);

      // The deprecated entry still holds the published events
      const remaining = await getPublished(manager, pkg.keyPackageRef);
      expect(remaining).toHaveLength(1);
    });

    it("reuses relays from the old key package if no relays option is passed", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({
        relays: ["wss://specific-relay.test"],
      });

      const newPkg = await manager.rotate(pkg.keyPackageRef);

      const events = await getPublished(manager, newPkg.keyPackageRef);
      expect(getKeyPackageRelays(events[0])).toContain(
        "wss://specific-relay.test/",
      );
    });

    it("skips relay deletion if the old key package was never published", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      // Add an unpublished key package directly to the private store
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await manager.add(kp);

      const listed = await manager.list();
      await manager.rotate(listed[0].keyPackageRef, {
        relays: ["wss://relay.test"],
      });

      const deleteEvents = network.events.filter((e) => e.kind === 5);
      expect(deleteEvents).toHaveLength(0);
    });

    it("returns a new key package with a different ref", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const old = await manager.create({ relays: ["wss://relay.test"] });
      const newPkg = await manager.rotate(old.keyPackageRef);

      expect(newPkg.keyPackageRef).toBeDefined();
      expect(
        Buffer.from(newPkg.keyPackageRef).equals(
          Buffer.from(old.keyPackageRef),
        ),
      ).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // remove()
  // -------------------------------------------------------------------------

  describe("remove()", () => {
    it("removes the key package from local private storage", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.remove(pkg.keyPackageRef);

      expect(await manager.has(pkg.keyPackageRef)).toBe(false);
      expect(await manager.count()).toBe(0);
    });

    it("does not publish anything to the network", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      const countBefore = network.events.length;

      await manager.remove(pkg.keyPackageRef);

      expect(network.events.length).toBe(countBefore);
    });

    it("emits removed", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const removed = vi.fn();
      manager.on("removed", removed);
      await manager.remove(pkg.keyPackageRef);

      expect(removed).toHaveBeenCalledOnce();
    });

    it("removes the entry including its published events", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.remove(pkg.keyPackageRef);

      expect(await getPublished(manager, pkg.keyPackageRef)).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // purge()
  // -------------------------------------------------------------------------

  describe("purge()", () => {
    it("publishes a kind 5 deletion for a single ref", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.purge(pkg.keyPackageRef);

      const deleteEvents = network.events.filter((e) => e.kind === 5);
      expect(deleteEvents).toHaveLength(1);
    });

    it("deletion event includes both e and a tags for kind 30443 published events", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.purge(pkg.keyPackageRef);

      const deleteEvent = network.events.find((e) => e.kind === 5)!;
      const eTags = deleteEvent.tags.filter((t) => t[0] === "e");
      const aTags = deleteEvent.tags.filter((t) => t[0] === "a");

      expect(eTags).toHaveLength(1);
      expect(aTags).toHaveLength(1);
      // a tag should be a 30443 coordinate
      expect(aTags[0][1]).toMatch(/^30443:/);
    });

    it("the deletion event references deduplicated event IDs for the ref", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      // Simulate a second observation of the same key package event
      const originalEvent = network.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;
      await manager.track({ ...originalEvent, id: "b".repeat(64) });

      await manager.purge(pkg.keyPackageRef);

      const deleteEvent = network.events.find((e) => e.kind === 5)!;
      const eTags = deleteEvent.tags.filter((t) => t[0] === "e");
      expect(eTags).toHaveLength(1);
    });

    it("removes local private key material", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.purge(pkg.keyPackageRef);

      expect(await manager.has(pkg.keyPackageRef)).toBe(false);
    });

    it("accepts an array of refs and publishes a single deletion covering all", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg1 = await manager.create({ relays: ["wss://relay.test"] });
      const pkg2 = await manager.create({
        relays: ["wss://relay2.test"],
        identifier: "second-slot",
      });

      await manager.purge([pkg1.keyPackageRef, pkg2.keyPackageRef]);

      const deleteEvents = network.events.filter((e) => e.kind === 5);
      expect(deleteEvents).toHaveLength(1);
      const eTags = deleteEvents[0].tags.filter((t) => t[0] === "e");
      expect(eTags).toHaveLength(2);
    });

    it("removes private keys for all refs in a bulk purge", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg1 = await manager.create({ relays: ["wss://relay.test"] });
      const pkg2 = await manager.create({
        relays: ["wss://relay2.test"],
        identifier: "second-slot",
      });

      await manager.purge([pkg1.keyPackageRef, pkg2.keyPackageRef]);

      expect(await manager.has(pkg1.keyPackageRef)).toBe(false);
      expect(await manager.has(pkg2.keyPackageRef)).toBe(false);
    });

    it("silently skips relay deletion for refs with no published events but still removes private key", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      // Add an unpublished key package directly to the private store
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await manager.add(kp);
      const listed = await manager.list();
      const unpublishedRef = listed[0].keyPackageRef;

      const eventCountBefore = network.events.length;
      await manager.purge(unpublishedRef);

      expect(network.events.length).toBe(eventCountBefore);
      expect(await manager.has(unpublishedRef)).toBe(false);
    });

    it("accepts a hex string ref", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      const refHex = Buffer.from(pkg.keyPackageRef).toString("hex");

      await manager.purge(refHex);

      const deleteEvents = network.events.filter((e) => e.kind === 5);
      expect(deleteEvents).toHaveLength(1);
      expect(await manager.has(refHex)).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // track()
  // -------------------------------------------------------------------------

  describe("track()", () => {
    it("returns false and ignores non-key-package events", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const result = await manager.track({
        id: "aa",
        kind: 1,
        pubkey: "bb",
        created_at: 0,
        content: "",
        tags: [],
        sig: "cc",
      });
      expect(result).toBe(false);
      expect(await manager.list()).toHaveLength(0);
    });

    it("returns false if the kind 30443 event has no `i` tag", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const result = await manager.track({
        id: "aa",
        kind: ADDRESSABLE_KEY_PACKAGE_KIND,
        pubkey: "bb",
        created_at: 0,
        content: "",
        tags: [["d", "someslot"]],
        sig: "cc",
      });
      expect(result).toBe(false);
      expect(await manager.list()).toHaveLength(0);
    });

    it("returns false if the kind 443 event has no `i` tag", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const result = await manager.track({
        id: "aa",
        kind: KEY_PACKAGE_KIND,
        pubkey: "bb",
        created_at: 0,
        content: "",
        tags: [],
        sig: "cc",
      });
      expect(result).toBe(false);
    });

    it("returns false if the event body cannot be decoded as a KeyPackage", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const result = await manager.track({
        id: "b".repeat(64),
        kind: ADDRESSABLE_KEY_PACKAGE_KIND,
        pubkey: "c".repeat(64),
        created_at: 1000,
        content: "",
        tags: [
          ["i", "a".repeat(64)],
          ["d", "someslot"],
        ],
        sig: "d".repeat(128),
      });
      expect(result).toBe(false);
    });

    it("returns true and records a real kind 30443 published event", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      const realEvent = network.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;

      const result = await manager.track({ ...realEvent, id: "e".repeat(64) });

      expect(result).toBe(true);
      const events = await getPublished(manager, pkg.keyPackageRef);
      expect(events).toHaveLength(1);
    });

    it("replaces an older addressable published event with a newer one", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      const realEvent = network.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;

      const newerEvent = {
        ...realEvent,
        id: "e".repeat(64),
        created_at: realEvent.created_at + 1,
      };
      await manager.track(newerEvent);

      const events = await getPublished(manager, pkg.keyPackageRef);
      expect(events).toHaveLength(1);
      expect(events[0].id).toBe(newerEvent.id);
    });

    it("stores the d tag when tracking a kind 30443 event", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      await manager.create({ relays: ["wss://relay.test"] });
      const realEvent = network.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;

      // Track with a different id (as if observed from another relay)
      const tracked = { ...realEvent, id: "e".repeat(64) };
      await manager.track(tracked);

      // d tag from the event should be on the stored entry
      const iTag = realEvent.tags.find((t) => t[0] === "i")!;
      const stored = await manager.get(iTag[1]);
      expect(stored?.identifier).toBe(TEST_CLIENT_ID);
    });

    it("accepts a legacy kind 443 event and records it", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      // Create a foreign key package from another account to get a real event,
      // then simulate it as kind 443 by patching the kind
      const otherNetwork = new MockNetwork(["wss://relay.test"]);
      const otherAccount = PrivateKeyAccount.generateNew();
      const { manager: otherManager } = makeManager(
        otherNetwork,
        otherAccount,
        "other-client",
      );
      await otherManager.create({ relays: ["wss://relay.test"] });

      const foreignAddressableEvent = otherNetwork.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;

      // Simulate the same package as a legacy kind 443 event
      const legacyEvent = {
        ...foreignAddressableEvent,
        kind: KEY_PACKAGE_KIND,
        id: "f".repeat(64),
        tags: foreignAddressableEvent.tags.filter((t) => t[0] !== "d"),
      };

      const result = await manager.track(legacyEvent);
      expect(result).toBe(true);
    });

    it("records relay URLs from the event's relays tag", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({
        relays: ["wss://relay1.test", "wss://relay2.test"],
      });
      const realEvent = network.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;

      await manager.track({ ...realEvent, id: "e".repeat(64) });

      const events = await getPublished(manager, pkg.keyPackageRef);
      expect(getKeyPackageRelays(events[0])).toEqual([
        "wss://relay1.test/",
        "wss://relay2.test/",
      ]);
    });

    it("records a valid key package event from another device (no local private key)", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      const otherNetwork = new MockNetwork(["wss://relay.test"]);
      const otherAccount = PrivateKeyAccount.generateNew();
      const { manager: otherManager } = makeManager(
        otherNetwork,
        otherAccount,
        "other-device",
      );
      await otherManager.create({ relays: ["wss://relay.test"] });

      const foreignEvent = otherNetwork.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;

      const result = await manager.track(foreignEvent);

      expect(result).toBe(true);
      // Not in local private store
      expect(
        await manager.has(foreignEvent.tags.find((t) => t[0] === "i")![1]),
      ).toBe(false);
      // But tracked in the store
      const refHex = foreignEvent.tags.find((t) => t[0] === "i")![1];
      const stored = await manager.get(refHex);
      expect(stored?.published).toHaveLength(1);
    });

    it("emits published when a valid event is tracked", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      const realEvent = network.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;

      const publishedHandler = vi.fn();
      manager.on("published", publishedHandler);

      const newId = "b".repeat(64);
      await manager.track({ ...realEvent, id: newId });

      expect(publishedHandler).toHaveBeenCalledOnce();
      expect(publishedHandler).toHaveBeenCalledWith(
        Buffer.from(pkg.keyPackageRef).toString("hex"),
        newId,
        expect.any(Array),
      );
    });

    it("deduplicates multiple addressable events for the same ref", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      const realEvent = network.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;

      await manager.track({ ...realEvent, id: "b".repeat(64) });
      await manager.track({ ...realEvent, id: "e".repeat(64) });

      const events = await getPublished(manager, pkg.keyPackageRef);
      expect(events).toHaveLength(1);
    });

    it("keeps distinct legacy kind 443 published events", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      const otherNetwork = new MockNetwork(["wss://relay.test"]);
      const otherAccount = PrivateKeyAccount.generateNew();
      const { manager: otherManager } = makeManager(
        otherNetwork,
        otherAccount,
        "other-device",
      );
      await otherManager.create({ relays: ["wss://relay.test"] });

      const foreignEvent = otherNetwork.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;
      const legacyEvent = {
        ...foreignEvent,
        kind: KEY_PACKAGE_KIND,
        id: "f".repeat(64),
        tags: foreignEvent.tags.filter((t) => t[0] !== "d"),
      };

      await manager.track(legacyEvent);
      await manager.track({ ...legacyEvent, id: "e".repeat(64) });

      const refHex = foreignEvent.tags.find((t) => t[0] === "i")![1];
      const events = await getPublished(manager, refHex);
      expect(events).toHaveLength(2);
    });
  });

  // -------------------------------------------------------------------------
  // markUsed()
  // -------------------------------------------------------------------------

  describe("markUsed()", () => {
    it("sets used=true on the stored key package", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.markUsed(pkg.keyPackageRef);

      const stored = await manager.get(pkg.keyPackageRef);
      expect(stored?.used).toBe(true);
    });

    it("used flag is visible in list()", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      await manager.create({
        relays: ["wss://relay.test"],
        identifier: "second-slot",
      });

      await manager.markUsed(pkg.keyPackageRef);

      const all = await manager.list();
      expect(all.filter((p) => p.used)).toHaveLength(1);
      expect(all.filter((p) => !p.used)).toHaveLength(1);
    });

    it("emits updated", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const updated: StoredKeyPackage[] = [];
      manager.on("updated", (kp) => updated.push(kp));

      await manager.markUsed(pkg.keyPackageRef);

      expect(updated).toHaveLength(1);
      expect(updated[0].used).toBe(true);
    });

    it("does nothing when the ref does not exist", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      await expect(manager.markUsed("a".repeat(64))).resolves.toBeUndefined();
    });

    it("accepts Uint8Array ref", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.markUsed(pkg.keyPackageRef);

      const stored = await manager.get(pkg.keyPackageRef);
      expect(stored?.used).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // list()
  // -------------------------------------------------------------------------

  describe("list()", () => {
    it("returns all locally stored key packages enriched with published events", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      await manager.create({ relays: ["wss://relay.test"] });
      await manager.create({
        relays: ["wss://relay.test"],
        identifier: "second-slot",
      });

      expect(await manager.list()).toHaveLength(2);
    });

    it("returns the slot identifier under identifier, not d", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const [listed] = await manager.list();
      const listedRecord = listed as Record<string, unknown>;

      expect(listed.identifier).toBe(pkg.identifier);
      expect(listedRecord.d).toBeUndefined();
    });

    it("each entry includes published — filter for packages with published events", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      await manager.create({ relays: ["wss://relay.test"] });

      // One unpublished package (added directly to private store, no publish record)
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await manager.add(kp);

      const all = await manager.list();
      expect(all).toHaveLength(2);
      expect(all.filter((p) => (p.published?.length ?? 0) > 0)).toHaveLength(1);
    });

    it("tracked foreign packages (no private key) do not appear in list()", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      const otherNetwork = new MockNetwork(["wss://relay.test"]);
      const otherAccount = PrivateKeyAccount.generateNew();
      const { manager: otherManager } = makeManager(
        otherNetwork,
        otherAccount,
        "other-device",
      );
      await otherManager.create({ relays: ["wss://relay.test"] });
      const foreignEvent = otherNetwork.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;

      await manager.track(foreignEvent);

      expect(await manager.list()).toHaveLength(0);
      const refHex = foreignEvent.tags.find((t) => t[0] === "i")![1];
      const stored = await manager.get(refHex);
      expect(stored?.published).toHaveLength(1);
    });
  });

  // -------------------------------------------------------------------------
  // watchKeyPackages()
  // -------------------------------------------------------------------------

  describe("watchKeyPackages()", () => {
    it("yields initial snapshot immediately", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      await manager.create({ relays: ["wss://relay.test"] });

      const gen = manager.watchKeyPackages();
      const { value } = await gen.next();
      await gen.return(undefined);

      expect(value).toHaveLength(1);
      expect(value[0].published).toHaveLength(1);
    });

    it("initial snapshot includes published events merged from store", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const gen = manager.watchKeyPackages();
      const { value } = await gen.next();
      await gen.return(undefined);

      expect(value[0].keyPackageRef).toEqual(pkg.keyPackageRef);
      expect(value[0].published).toHaveLength(1);
      expect(getKeyPackageRelays(value[0].published![0])).toContain(
        "wss://relay.test/",
      );
    });

    it("yields updated snapshot after a key package is added", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const gen = manager.watchKeyPackages();

      const first = await gen.next();
      expect(first.value).toHaveLength(0);

      const created = manager.create({ relays: ["wss://relay.test"] });
      const second = await gen.next();
      await created;
      await gen.return(undefined);

      expect(second.value).toHaveLength(1);
    });

    it("yields a new array instance for each snapshot", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      const gen = manager.watchKeyPackages();

      const first = await gen.next();
      const update = manager.markUsed(pkg.keyPackageRef);
      const second = await gen.next();
      await update;
      await gen.return(undefined);

      expect(second.value).not.toBe(first.value);
    });

    it("yields a deduplicated snapshot after a publish is tracked", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      await manager.create({ relays: ["wss://relay.test"] });
      const realEvent = network.events.find(
        (e) => e.kind === ADDRESSABLE_KEY_PACKAGE_KIND,
      )!;

      const gen = manager.watchKeyPackages();
      await gen.next();

      const tracking = manager.track({ ...realEvent, id: "b".repeat(64) });
      const { value } = await gen.next();
      await tracking;
      await gen.return(undefined);

      expect(value[0].published).toHaveLength(1);
    });

    it("yields updated snapshot after a key package is removed", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const gen = manager.watchKeyPackages();
      await gen.next();

      const removal = manager.remove(pkg.keyPackageRef);
      const { value } = await gen.next();
      await removal;
      await gen.return(undefined);

      expect(value).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // fetchKeyPackagesForUser()
  // -------------------------------------------------------------------------

  describe("fetchKeyPackagesForUser()", () => {
    it("queries network with both kind 443 and kind 30443 filters", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const requestSpy = vi.spyOn(network, "request");
      const targetPubkey = await account.signer.getPublicKey();

      await manager.fetchKeyPackagesForUser(targetPubkey, ["wss://relay.test"]);

      expect(requestSpy).toHaveBeenCalledOnce();
      const [relays, filters] = requestSpy.mock.calls[0];
      expect(relays).toEqual(["wss://relay.test"]);
      const filterArray = Array.isArray(filters) ? filters : [filters];
      expect(filterArray).toHaveLength(2);
      expect(filterArray.some((f) => f.kinds?.includes(KEY_PACKAGE_KIND))).toBe(
        true,
      );
      expect(
        filterArray.some((f) =>
          f.kinds?.includes(ADDRESSABLE_KEY_PACKAGE_KIND),
        ),
      ).toBe(true);
    });

    it("returns all events found on the relays", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      const targetPubkey = await account.signer.getPublicKey();

      const events = await manager.fetchKeyPackagesForUser(targetPubkey, [
        "wss://relay.test",
      ]);

      expect(events.length).toBeGreaterThan(0);
      expect(events.every((e) => e.pubkey === targetPubkey)).toBe(true);
    });

    it("tracks all returned events into the publish record", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      const targetPubkey = await account.signer.getPublicKey();

      // trackSpy counts calls to track()
      const trackSpy = vi.spyOn(manager, "track");

      const events = await manager.fetchKeyPackagesForUser(targetPubkey, [
        "wss://relay.test",
      ]);

      expect(trackSpy).toHaveBeenCalledTimes(events.length);
    });

    it("returns an empty array when no matching events exist on the relays", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const strangerPubkey =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

      const events = await manager.fetchKeyPackagesForUser(strangerPubkey, [
        "wss://relay.test",
      ]);

      expect(events).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // KeyPackageStore > grace window (markDeprecated / removeExpired)
  // -------------------------------------------------------------------------

  describe("KeyPackageStore > grace window", () => {
    it("markDeprecated() sets the deprecatedAt timestamp on the entry", async () => {
      const { store } = makeManager(network, account, TEST_CLIENT_ID);
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await store.add(kp);

      const listed = await store.list();
      const ref = listed[0].keyPackageRef;
      const timestamp = 1_000_000;

      await store.markDeprecated(ref, timestamp);

      const stored = await store.getKeyPackage(ref);
      expect(stored?.deprecatedAt).toBe(timestamp);
    });

    it("removeExpired() removes entries older than maxAgeSec", async () => {
      const { store } = makeManager(network, account, TEST_CLIENT_ID);
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await store.add(kp);

      const listed = await store.list();
      const ref = listed[0].keyPackageRef;

      // Timestamp far in the past — grace window has expired
      const expiredTimestamp = Math.floor(Date.now() / 1000) - 90000;
      await store.markDeprecated(ref, expiredTimestamp);

      const removed = await store.removeExpired(86400);

      expect(removed).toBe(1);
      expect(await store.getKeyPackage(ref)).toBeNull();
    });

    it("removeExpired() does NOT remove entries within the grace window", async () => {
      const { store } = makeManager(network, account, TEST_CLIENT_ID);
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await store.add(kp);

      const listed = await store.list();
      const ref = listed[0].keyPackageRef;

      // Timestamp just now — still within the grace window
      const recentTimestamp = Math.floor(Date.now() / 1000);
      await store.markDeprecated(ref, recentTimestamp);

      const removed = await store.removeExpired(86400);

      expect(removed).toBe(0);
      expect(await store.getKeyPackage(ref)).not.toBeNull();
    });

    it("list() excludes deprecated entries", async () => {
      const { store } = makeManager(network, account, TEST_CLIENT_ID);
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();

      const kp1 = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      const kp2 = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await store.add(kp1);
      await store.add(kp2);

      const listed = await store.list();
      expect(listed).toHaveLength(2);

      // Deprecate the first one
      await store.markDeprecated(
        listed[0].keyPackageRef,
        Math.floor(Date.now() / 1000),
      );

      const afterDeprecation = await store.list();
      expect(afterDeprecation).toHaveLength(1);
      const remainingRef = Buffer.from(
        afterDeprecation[0].keyPackageRef,
      ).toString("hex");
      expect(remainingRef).toBe(
        Buffer.from(listed[1].keyPackageRef).toString("hex"),
      );
    });

    it("getPrivateKey() still returns private keys for deprecated entries", async () => {
      const { store } = makeManager(network, account, TEST_CLIENT_ID);
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await store.add(kp);

      const listed = await store.list();
      const ref = listed[0].keyPackageRef;

      await store.markDeprecated(ref, Math.floor(Date.now() / 1000));

      const privateKey = await store.getPrivateKey(ref);
      expect(privateKey).not.toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // KeyPackageManager > cleanupDeprecated()
  // -------------------------------------------------------------------------

  describe("cleanupDeprecated()", () => {
    it("rotate() marks old entry as deprecated instead of removing it", async () => {
      const { manager, store } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.rotate(pkg.keyPackageRef);

      // The old entry still exists in the store with deprecatedAt set
      const stored = await store.getKeyPackage(pkg.keyPackageRef);
      expect(stored).not.toBeNull();
      expect(stored?.deprecatedAt).toBeDefined();
      expect(typeof stored?.deprecatedAt).toBe("number");
    });

    it("cleanupDeprecated() returns count of removed entries", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      // Rotate creates a deprecated entry with the current timestamp
      await manager.rotate(pkg.keyPackageRef);

      // No entries are expired yet (grace window is 24 hours)
      const countWithinWindow = await manager.cleanupDeprecated(86400);
      expect(countWithinWindow).toBe(0);

      // Passing maxAgeSec=0 expires entries deprecated at or before "now"
      const countExpired = await manager.cleanupDeprecated(0);
      expect(countExpired).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // KeyPackageManager > listForWelcomeDecrypt()
  // -------------------------------------------------------------------------

  describe("listForWelcomeDecrypt()", () => {
    it("includes both active and deprecated entries, active first", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      // Create two key packages, both initially active.
      const kp1 = await manager.create({
        relays: ["wss://relay.test"],
        identifier: "slot-a",
      });
      const kp2 = await manager.create({
        relays: ["wss://relay.test"],
        identifier: "slot-b",
      });

      // Deprecate kp1.
      await manager.markDeprecated(
        kp1.keyPackageRef,
        Math.floor(Date.now() / 1000),
      );

      const result = await manager.listForWelcomeDecrypt();

      expect(result).toHaveLength(2);
      // Active entry (kp2) comes first
      expect(Buffer.from(result[0].keyPackageRef).toString("hex")).toBe(
        Buffer.from(kp2.keyPackageRef).toString("hex"),
      );
      expect(result[0].deprecatedAt).toBeUndefined();
      // Deprecated entry (kp1) comes after
      expect(Buffer.from(result[1].keyPackageRef).toString("hex")).toBe(
        Buffer.from(kp1.keyPackageRef).toString("hex"),
      );
      expect(result[1].deprecatedAt).toBeDefined();
    });

    it("returns only active entries when none are deprecated", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      await manager.create({
        relays: ["wss://relay.test"],
        identifier: "slot-a",
      });

      const result = await manager.listForWelcomeDecrypt();
      expect(result).toHaveLength(1);
      expect(result[0].deprecatedAt).toBeUndefined();
    });

    it("returns deprecated entries even when no active entries remain", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      const kp = await manager.create({
        relays: ["wss://relay.test"],
        identifier: "slot-a",
      });
      await manager.markDeprecated(
        kp.keyPackageRef,
        Math.floor(Date.now() / 1000),
      );

      // list() drops the deprecated entry — regression guard on AC-GRACE-3.
      const active = await manager.list();
      expect(active).toHaveLength(0);

      // listForWelcomeDecrypt still surfaces it.
      const result = await manager.listForWelcomeDecrypt();
      expect(result).toHaveLength(1);
      expect(result[0].deprecatedAt).toBeDefined();
    });

    it("excludes entries that have been cleaned up via cleanupDeprecated()", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      const kp = await manager.create({
        relays: ["wss://relay.test"],
        identifier: "slot-a",
      });
      await manager.markDeprecated(
        kp.keyPackageRef,
        Math.floor(Date.now() / 1000),
      );

      // Expire and remove immediately.
      await manager.cleanupDeprecated(0);

      const result = await manager.listForWelcomeDecrypt();
      expect(result).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // KeyPackageManager > list() regression on deprecation semantics
  // -------------------------------------------------------------------------

  describe("list() — deprecation regression guard (AC-GRACE-3)", () => {
    it("excludes deprecated entries", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      const kp = await manager.create({
        relays: ["wss://relay.test"],
        identifier: "slot-a",
      });
      await manager.markDeprecated(
        kp.keyPackageRef,
        Math.floor(Date.now() / 1000),
      );

      const result = await manager.list();
      expect(result).toHaveLength(0);
    });

    it("count() excludes deprecated entries", async () => {
      const { manager } = makeManager(network, account, TEST_CLIENT_ID);

      const kp = await manager.create({
        relays: ["wss://relay.test"],
        identifier: "slot-a",
      });
      expect(await manager.count()).toBe(1);

      await manager.markDeprecated(
        kp.keyPackageRef,
        Math.floor(Date.now() / 1000),
      );
      expect(await manager.count()).toBe(0);
    });
  });
});
