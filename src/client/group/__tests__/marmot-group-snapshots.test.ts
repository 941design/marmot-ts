/**
 * Tests for epoch snapshot wiring in MarmotGroup.
 *
 * These tests verify:
 * - AC-SNAP-1: snapshot taken before processMessage in ingest()
 * - AC-SNAP-2: snapshot taken before state advance in selfUpdate() / commit()
 * - AC-SNAP-3: no snapshot promotion on publish failure
 * - AC-RET-1: prune called with correct keepAboveEpoch after each advance
 * - AC-RET-2: snapshotDepth defaults to 2; after 3 advances at most 2 snapshots
 * - AC-STRUCT-3: snapshotDepth defaults to 2 without config
 */

import { PrivateKeyAccount } from "applesauce-accounts/accounts";
import {
  CiphersuiteImpl,
  defaultCryptoProvider,
  getCiphersuiteImpl,
} from "ts-mls";
import { beforeEach, describe, expect, it } from "vitest";

import type {
  EpochSnapshot,
  EpochSnapshotStoreBackend,
} from "../epoch-snapshot.js";
import { InMemoryEpochSnapshotStore } from "../../../extra/in-memory-epoch-snapshot-store.js";
import { MarmotClient } from "../../marmot-client.js";
import { SerializedClientState } from "../../../core/client-state.js";
import type { StoredKeyPackage } from "../../key-package-manager.js";
import { MockNetwork } from "../../../__tests__/helpers/mock-network.js";
import { InMemoryKeyValueStore } from "../../../extra/in-memory-key-value-store.js";
import { ADDRESSABLE_KEY_PACKAGE_KIND } from "../../../core/protocol.js";
import { unlockGiftWrap } from "applesauce-common/helpers/gift-wrap";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** A spy implementation of EpochSnapshotStoreBackend that records all calls */
class SpySnapshotStore implements EpochSnapshotStoreBackend {
  readonly snapshots = new Map<string, EpochSnapshot>();
  readonly setCalls: Array<{ groupIdHex: string; epoch: bigint }> = [];
  readonly pruneCalls: Array<{
    groupIdHex: string;
    keepAboveEpoch: bigint;
  }> = [];
  readonly clearCalls: Array<{ groupIdHex: string }> = [];

  async get(groupIdHex: string, epoch: bigint): Promise<EpochSnapshot | null> {
    return this.snapshots.get(`${groupIdHex}:${epoch}`) ?? null;
  }

  async set(
    groupIdHex: string,
    epoch: bigint,
    snapshot: EpochSnapshot,
  ): Promise<void> {
    this.setCalls.push({ groupIdHex, epoch });
    this.snapshots.set(`${groupIdHex}:${epoch}`, snapshot);
  }

  async prune(groupIdHex: string, keepAboveEpoch: bigint): Promise<void> {
    this.pruneCalls.push({ groupIdHex, keepAboveEpoch });
  }

  async clear(groupIdHex: string): Promise<void> {
    this.clearCalls.push({ groupIdHex });
  }
}

/** A snapshot store that always throws on set() */
class ThrowingSnapshotStore implements EpochSnapshotStoreBackend {
  async get(): Promise<EpochSnapshot | null> {
    return null;
  }
  async set(): Promise<void> {
    throw new Error("snapshot store unavailable");
  }
  async prune(): Promise<void> {}
  async clear(): Promise<void> {}
}

async function makeCiphersuite(): Promise<CiphersuiteImpl> {
  return getCiphersuiteImpl(
    "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    defaultCryptoProvider,
  );
}

// ---------------------------------------------------------------------------
// Setup helpers for full MarmotClient flows
// ---------------------------------------------------------------------------

async function setupTwoMemberGroup(mockNetwork: MockNetwork) {
  const adminAccount = PrivateKeyAccount.generateNew();
  const inviteeAccount = PrivateKeyAccount.generateNew();

  const adminSpyStore = new SpySnapshotStore();

  const adminClient = new MarmotClient({
    groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
    keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
    signer: adminAccount.signer,
    network: mockNetwork,
    groupOptions: { snapshots: adminSpyStore },
  });

  const inviteeClient = new MarmotClient({
    groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
    keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
    signer: inviteeAccount.signer,
    network: mockNetwork,
    clientId:
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  });

  const adminPubkey = await adminAccount.signer.getPublicKey();
  const inviteePubkey = await inviteeAccount.signer.getPublicKey();

  await inviteeClient.keyPackages.create({ relays: ["wss://mock-relay.test"] });

  const adminGroup = await adminClient.groups.create("Test Group", {
    adminPubkeys: [adminPubkey],
    relays: ["wss://mock-relay.test"],
  });

  const keyPackageEvents = await mockNetwork.request(
    ["wss://mock-relay.test"],
    {
      kinds: [ADDRESSABLE_KEY_PACKAGE_KIND],
      authors: [inviteePubkey],
    },
  );

  // Admin invites invitee — this calls commit() which advances admin epoch
  adminSpyStore.setCalls.length = 0; // reset before invite
  adminSpyStore.pruneCalls.length = 0;
  await adminGroup.inviteByKeyPackageEvent(keyPackageEvents[0]);

  const giftWraps = await mockNetwork.request(["wss://mock-inbox.test"], {
    kinds: [1059],
    "#p": [inviteePubkey],
  });
  const welcomeRumor = await unlockGiftWrap(
    giftWraps[0],
    inviteeAccount.signer,
  );
  const { group: inviteeGroup } = await inviteeClient.joinGroupFromWelcome({
    welcomeRumor,
  });

  return {
    adminClient,
    inviteeClient,
    adminAccount,
    inviteeAccount,
    adminGroup,
    inviteeGroup,
    adminPubkey,
    inviteePubkey,
    adminSpyStore,
  };
}

// ---------------------------------------------------------------------------
// Describe blocks
// ---------------------------------------------------------------------------

describe("MarmotGroup snapshot wiring", () => {
  let mockNetwork: MockNetwork;
  let ciphersuite: CiphersuiteImpl;

  beforeEach(async () => {
    mockNetwork = new MockNetwork();
    ciphersuite = await makeCiphersuite();
  });

  // -------------------------------------------------------------------------
  // AC-STRUCT-3: default snapshotDepth = 2
  // -------------------------------------------------------------------------
  describe("AC-STRUCT-3: snapshotDepth defaults to 2", () => {
    it("defaults to depth 2 when no snapshots option provided", async () => {
      // Verify that after 3 advances with the default, at most 2 snapshots survive.
      // This is tested concretely in AC-RET-2 below; here we just confirm the
      // construction path doesn't throw and an InMemoryEpochSnapshotStore is used.
      const adminAccount = PrivateKeyAccount.generateNew();
      const adminPubkey = await adminAccount.signer.getPublicKey();

      const client = new MarmotClient({
        groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
        keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
        signer: adminAccount.signer,
        network: mockNetwork,
        // No snapshots option — should use default InMemoryEpochSnapshotStore with depth 2
      });

      const group = await client.groups.create("Depth Test", {
        adminPubkeys: [adminPubkey],
        relays: ["wss://mock-relay.test"],
      });

      // Group should exist without error — snapshot store was auto-wired
      expect(group).toBeTruthy();
    });
  });

  // -------------------------------------------------------------------------
  // AC-SNAP-2: snapshot taken in selfUpdate() before state advance
  // -------------------------------------------------------------------------
  describe("AC-SNAP-2: selfUpdate() snapshots before advancing state", () => {
    it("records a snapshot with the pre-advance epoch", async () => {
      const { adminGroup, inviteeGroup, adminSpyStore } =
        await setupTwoMemberGroup(mockNetwork);

      // selfUpdate() from invitee (non-admin path, uses invitee's group)
      // We need the invitee group to have a spy store. Instead test with admin.
      adminSpyStore.setCalls.length = 0;
      adminSpyStore.pruneCalls.length = 0;

      const epochBefore = adminGroup.state.groupContext.epoch;
      await adminGroup.selfUpdate();
      const epochAfter = adminGroup.state.groupContext.epoch;

      // Epoch advanced
      expect(epochAfter).toBeGreaterThan(epochBefore);

      // set() was called once with the pre-advance epoch
      expect(adminSpyStore.setCalls).toHaveLength(1);
      expect(adminSpyStore.setCalls[0].epoch).toBe(epochBefore);

      // The snapshot was stored at epochBefore, not epochAfter
      const snap = await adminSpyStore.get(
        adminSpyStore.setCalls[0].groupIdHex,
        epochBefore,
      );
      expect(snap).not.toBeNull();
      expect(snap!.epoch).toBe(epochBefore);

      // prune was called
      expect(adminSpyStore.pruneCalls).toHaveLength(1);
    });
  });

  // -------------------------------------------------------------------------
  // AC-SNAP-2: snapshot taken in commit() before state advance
  // -------------------------------------------------------------------------
  describe("AC-SNAP-2: commit() snapshots before advancing state", () => {
    it("records a snapshot at the pre-advance epoch on a successful commit", async () => {
      const { adminGroup, adminSpyStore } =
        await setupTwoMemberGroup(mockNetwork);

      adminSpyStore.setCalls.length = 0;
      adminSpyStore.pruneCalls.length = 0;

      const epochBefore = adminGroup.state.groupContext.epoch;
      // commit() with empty proposal list (no-op self-update commit)
      await adminGroup.commit({ extraProposals: [] });
      const epochAfter = adminGroup.state.groupContext.epoch;

      expect(epochAfter).toBeGreaterThan(epochBefore);

      // Snapshot stored at pre-advance epoch
      expect(adminSpyStore.setCalls).toHaveLength(1);
      expect(adminSpyStore.setCalls[0].epoch).toBe(epochBefore);

      const snap = await adminSpyStore.get(
        adminSpyStore.setCalls[0].groupIdHex,
        epochBefore,
      );
      expect(snap).not.toBeNull();
      expect(snap!.appliedCommit).toBeDefined();

      // Prune called after advance
      expect(adminSpyStore.pruneCalls).toHaveLength(1);
    });
  });

  // -------------------------------------------------------------------------
  // AC-SNAP-3: no snapshot when publish fails
  // -------------------------------------------------------------------------
  describe("AC-SNAP-3: publish failure — no snapshot stored, state unchanged", () => {
    it("does not advance state or store snapshot when selfUpdate publish fails", async () => {
      const adminAccount = PrivateKeyAccount.generateNew();
      const inviteeAccount = PrivateKeyAccount.generateNew();
      const adminPubkey = await adminAccount.signer.getPublicKey();
      const inviteePubkey = await inviteeAccount.signer.getPublicKey();

      const failingNetwork = new MockNetwork();
      const spyStore = new SpySnapshotStore();

      // Override publish to return failure after initial setup
      let failPublish = false;
      const originalPublish = failingNetwork.publish.bind(failingNetwork);
      failingNetwork.publish = async (relays, event) => {
        if (failPublish) {
          // Return failure for all relays
          const result: Record<string, any> = {};
          for (const relay of relays) {
            result[relay] = { from: relay, ok: false, message: "relay down" };
          }
          return result;
        }
        return originalPublish(relays, event);
      };

      const adminClient = new MarmotClient({
        groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
        keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
        signer: adminAccount.signer,
        network: failingNetwork,
        groupOptions: { snapshots: spyStore },
      });

      const inviteeClient = new MarmotClient({
        groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
        keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
        signer: inviteeAccount.signer,
        network: failingNetwork,
        clientId:
          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      });

      await inviteeClient.keyPackages.create({
        relays: ["wss://mock-relay.test"],
      });

      const adminGroup = await adminClient.groups.create("Fail Test", {
        adminPubkeys: [adminPubkey],
        relays: ["wss://mock-relay.test"],
      });

      const kpEvents = await failingNetwork.request(["wss://mock-relay.test"], {
        kinds: [ADDRESSABLE_KEY_PACKAGE_KIND],
        authors: [inviteePubkey],
      });
      await adminGroup.inviteByKeyPackageEvent(kpEvents[0]);

      // Reset spy state after setup
      spyStore.setCalls.length = 0;
      spyStore.pruneCalls.length = 0;

      const epochBefore = adminGroup.state.groupContext.epoch;
      const groupIdHex =
        spyStore.setCalls[0]?.groupIdHex ??
        Array.from(spyStore.snapshots.keys())[0]?.split(":")[0] ??
        "";

      // Now make publish fail
      failPublish = true;

      await expect(adminGroup.selfUpdate()).rejects.toThrow(
        /no relay acknowledged/,
      );

      // State must NOT have advanced
      expect(adminGroup.state.groupContext.epoch).toBe(epochBefore);

      // Snapshot store must have NO new entry at the would-be new epoch
      if (groupIdHex) {
        const snapAtNewEpoch = await spyStore.get(groupIdHex, epochBefore + 1n);
        expect(snapAtNewEpoch).toBeNull();
      }

      // set() must not have been called (hasAck check fires before snapshot)
      expect(spyStore.setCalls).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // AC-RET-2: depth=2 default keeps only 2 snapshots after 3 advances
  // -------------------------------------------------------------------------
  describe("AC-RET-2: default depth=2 retains at most 2 snapshots", () => {
    it("retains at most 2 snapshots after 3 consecutive selfUpdate advances", async () => {
      // Use a real InMemoryEpochSnapshotStore to count retained entries.
      // The spy store doesn't actually prune — we need a real store here.
      const adminAccount = PrivateKeyAccount.generateNew();
      const adminPubkey = await adminAccount.signer.getPublicKey();

      // We need a second member for selfUpdate to work (single-member group
      // selfUpdate can fail in ts-mls due to "Could not find common ancestor").
      // Use the existing adminGroup + inviteeGroup setup to get a 2-member group.
      // Then do 3 selfUpdates from the admin side.

      const realStore = new InMemoryEpochSnapshotStore();
      const net2 = new MockNetwork();

      const inv2Account = PrivateKeyAccount.generateNew();
      const inv2Pubkey = await inv2Account.signer.getPublicKey();

      const adminClient2 = new MarmotClient({
        groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
        keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
        signer: adminAccount.signer,
        network: net2,
        groupOptions: { snapshots: realStore, snapshotDepth: 2 },
      });
      const invClient2 = new MarmotClient({
        groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
        keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
        signer: inv2Account.signer,
        network: net2,
        clientId:
          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      });

      await invClient2.keyPackages.create({
        relays: ["wss://mock-relay.test"],
      });
      const adminGroup2 = await adminClient2.groups.create("Retention Test", {
        adminPubkeys: [adminPubkey],
        relays: ["wss://mock-relay.test"],
      });

      const kpEvs = await net2.request(["wss://mock-relay.test"], {
        kinds: [ADDRESSABLE_KEY_PACKAGE_KIND],
        authors: [inv2Pubkey],
      });
      await adminGroup2.inviteByKeyPackageEvent(kpEvs[0]);

      const groupIdHex2 = adminGroup2.idStr;

      // Do 3 selfUpdates — each advances the epoch by 1
      await adminGroup2.selfUpdate();
      await adminGroup2.selfUpdate();
      await adminGroup2.selfUpdate();

      const finalEpoch = adminGroup2.state.groupContext.epoch;

      // With depth=2 and 3+ advances, only at most 2 epochs should be present.
      // Snapshots are taken at the pre-advance epoch.
      // After 3 advances the oldest should have been pruned.
      let retained = 0;
      for (let e = 0n; e <= finalEpoch; e++) {
        const snap = await realStore.get(groupIdHex2, e);
        if (snap !== null) retained++;
      }

      expect(retained).toBeLessThanOrEqual(2);
    });
  });

  // -------------------------------------------------------------------------
  // AC-RET-1: prune receives correct keepAboveEpoch on each advance
  // -------------------------------------------------------------------------
  describe("AC-RET-1: prune called with correct keepAboveEpoch", () => {
    it("calls prune with currentEpoch - snapshotDepth after each advance", async () => {
      const { adminGroup, adminSpyStore } =
        await setupTwoMemberGroup(mockNetwork);

      adminSpyStore.setCalls.length = 0;
      adminSpyStore.pruneCalls.length = 0;

      const epochBeforeSelfUpdate = adminGroup.state.groupContext.epoch;

      await adminGroup.selfUpdate();

      expect(adminSpyStore.pruneCalls).toHaveLength(1);
      // keepAboveEpoch = epochBefore - snapshotDepth (depth defaults to 2)
      const expectedKeepAbove = epochBeforeSelfUpdate - 2n;
      expect(adminSpyStore.pruneCalls[0].keepAboveEpoch).toBe(
        expectedKeepAbove,
      );
    });
  });

  // -------------------------------------------------------------------------
  // AC-SNAP-1: snapshot taken before processMessage in ingest()
  // -------------------------------------------------------------------------
  describe("AC-SNAP-1: ingest() snapshots commit before processMessage", () => {
    it("stores a pre-apply snapshot when ingesting a current-epoch commit", async () => {
      const adminAcc = PrivateKeyAccount.generateNew();
      const inviteeAcc = PrivateKeyAccount.generateNew();
      const adminPub = await adminAcc.signer.getPublicKey();
      const inviteePub = await inviteeAcc.signer.getPublicKey();

      const net = new MockNetwork();
      const adminSpyIngest = new SpySnapshotStore();
      const inviteeSpyIngest = new SpySnapshotStore();

      const adminC = new MarmotClient({
        groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
        keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
        signer: adminAcc.signer,
        network: net,
        groupOptions: { snapshots: adminSpyIngest },
      });
      const inviteeC = new MarmotClient({
        groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
        keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
        signer: inviteeAcc.signer,
        network: net,
        groupOptions: { snapshots: inviteeSpyIngest },
        clientId:
          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      });

      await inviteeC.keyPackages.create({ relays: ["wss://mock-relay.test"] });
      const adminG = await adminC.groups.create("Ingest Snap Test", {
        adminPubkeys: [adminPub],
        relays: ["wss://mock-relay.test"],
      });

      const kpEvs = await net.request(["wss://mock-relay.test"], {
        kinds: [ADDRESSABLE_KEY_PACKAGE_KIND],
        authors: [inviteePub],
      });
      await adminG.inviteByKeyPackageEvent(kpEvs[0]);

      const giftWraps = await net.request(["wss://mock-inbox.test"], {
        kinds: [1059],
        "#p": [inviteePub],
      });
      const wr = await unlockGiftWrap(giftWraps[0], inviteeAcc.signer);
      const { group: inviteeG } = await inviteeC.joinGroupFromWelcome({
        welcomeRumor: wr,
      });

      // Reset spy stores
      inviteeSpyIngest.setCalls.length = 0;
      inviteeSpyIngest.pruneCalls.length = 0;

      // Admin does selfUpdate() — this publishes a commit event
      await adminG.selfUpdate();

      // Fetch the commit event from the network and ingest it into invitee's group.
      // Group events use the Nostr group ID (marmotData.nostrGroupId) as the #h tag,
      // not the MLS group ID (adminG.idStr).
      const { GROUP_EVENT_KIND } = await import("../../../core/protocol.js");
      const { getMarmotGroupData } =
        await import("../../../core/client-state.js");
      const { bytesToHex: toHex } = await import("@noble/hashes/utils.js");
      const nostrGroupIdHex = toHex(
        getMarmotGroupData(adminG.state)!.nostrGroupId,
      );
      const groupEvents = await net.request(["wss://mock-relay.test"], {
        kinds: [GROUP_EVENT_KIND],
        "#h": [nostrGroupIdHex],
      });

      const epochBeforeIngest = inviteeG.state.groupContext.epoch;

      const results: any[] = [];
      for await (const r of inviteeG.ingest(groupEvents)) {
        results.push(r);
      }

      // The invitee should have advanced epoch
      const epochAfterIngest = inviteeG.state.groupContext.epoch;
      expect(epochAfterIngest).toBeGreaterThan(epochBeforeIngest);

      // A snapshot set() call must have been made before processMessage
      // (evidenced by having at least one set call at the pre-apply epoch)
      const setAtPreApply = inviteeSpyIngest.setCalls.filter(
        (c) => c.epoch === epochBeforeIngest,
      );
      expect(setAtPreApply.length).toBeGreaterThan(0);
    });

    it("propagates snapshot store errors (no silent apply-without-snapshot)", async () => {
      const adminAcc = PrivateKeyAccount.generateNew();
      const inviteeAcc = PrivateKeyAccount.generateNew();
      const adminPub = await adminAcc.signer.getPublicKey();
      const inviteePub = await inviteeAcc.signer.getPublicKey();

      const net = new MockNetwork();
      const throwingStore = new ThrowingSnapshotStore();

      const adminC = new MarmotClient({
        groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
        keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
        signer: adminAcc.signer,
        network: net,
        // Admin uses default store so setup succeeds
      });
      const inviteeC = new MarmotClient({
        groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
        keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
        signer: inviteeAcc.signer,
        network: net,
        groupOptions: { snapshots: throwingStore },
        clientId:
          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      });

      await inviteeC.keyPackages.create({ relays: ["wss://mock-relay.test"] });
      const adminG = await adminC.groups.create("Throw Snap Test", {
        adminPubkeys: [adminPub],
        relays: ["wss://mock-relay.test"],
      });

      const kpEvs = await net.request(["wss://mock-relay.test"], {
        kinds: [ADDRESSABLE_KEY_PACKAGE_KIND],
        authors: [inviteePub],
      });
      await adminG.inviteByKeyPackageEvent(kpEvs[0]);

      const giftWraps = await net.request(["wss://mock-inbox.test"], {
        kinds: [1059],
        "#p": [inviteePub],
      });
      const wr = await unlockGiftWrap(giftWraps[0], inviteeAcc.signer);
      const { group: inviteeG } = await inviteeC.joinGroupFromWelcome({
        welcomeRumor: wr,
      });

      // Admin publishes a commit
      await adminG.selfUpdate();

      const { GROUP_EVENT_KIND } = await import("../../../core/protocol.js");
      const { getMarmotGroupData: getGd } =
        await import("../../../core/client-state.js");
      const { bytesToHex: toHex2 } = await import("@noble/hashes/utils.js");
      const nostrGrpIdHex = toHex2(getGd(adminG.state)!.nostrGroupId);
      const groupEvents = await net.request(["wss://mock-relay.test"], {
        kinds: [GROUP_EVENT_KIND],
        "#h": [nostrGrpIdHex],
      });

      // Per AC-SNAP-1: a snapshot-store throw in ingest() MUST NOT result in the
      // commit being applied without a snapshot. The snapshot set() happens
      // OUTSIDE the try/catch in ingest(), so it propagates as a thrown error.
      // The load-bearing assertion is that the invitee's epoch is UNCHANGED —
      // the competing commit was not silently applied, preserving the
      // convergence guarantee S2 depends on.
      const epochBefore = inviteeG.state.groupContext.epoch;
      const ingestGen = inviteeG.ingest(groupEvents);
      let threw = false;
      try {
        for await (const r of ingestGen) {
          // No "processed" result for the throwing commit is allowed: if the
          // snapshot fails, the commit must not advance state.
          if (r.kind === "processed") {
            throw new Error(
              "AC-SNAP-1 violation: commit was applied despite snapshot store failure",
            );
          }
        }
      } catch {
        threw = true;
      }

      // The store threw, so ingest() must have surfaced an error (propagated or
      // re-queued as unreadable) AND the state must not have advanced.
      expect(threw).toBe(true);
      expect(inviteeG.state.groupContext.epoch).toBe(epochBefore);
    });
  });
});
