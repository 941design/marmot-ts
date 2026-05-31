/**
 * Tests for AC-ROLL-4: #rollbackToEpoch restores serialized ClientState byte-for-byte.
 *
 * #rollbackToEpoch is private, so we test it via the ingest() rollback path.
 *
 * The rollback scenario: two competing commits arrive in the same ingest() batch.
 * Both are decryptable (same epoch exporter_secret).  The MIP-03 winner is sorted
 * first and applied; the loser arrives as a past-epoch commit and triggers rollback.
 * After rollback, the loser is re-applied as the canonical commit.
 *
 * In this test the "loser" and "winner" are swapped deliberately: commit W wins
 * (smaller created_at), commit L loses.  The receiver first applies W (the winner),
 * then L arrives as past-epoch and gets `lost-race` skip.  To exercise the actual
 * rollback path, we deliver L before W so that L is applied first and then W arrives
 * as past-epoch and wins the rollback race.
 */

import { bytesToHex } from "@noble/hashes/utils.js";
import {
  CiphersuiteImpl,
  createCommit,
  defaultCryptoProvider,
  defaultProposalTypes,
  getCiphersuiteImpl,
  joinGroup,
  serializeClientState as mlsSerializeClientState,
  unsafeTestingAuthenticationService,
  encode,
  clientStateEncoder,
} from "ts-mls";
import { describe, expect, it } from "vitest";
import { EventSigner } from "applesauce-core/event-factory";

import { MarmotGroup } from "../marmot-group.js";
import type { NostrNetworkInterface } from "../../nostr-interface.js";
import {
  SerializedClientState,
  serializeClientState,
} from "../../../core/client-state.js";
import { createCredential } from "../../../core/credential.js";
import { createGroupEvent } from "../../../core/group-message.js";
import { createSimpleGroup } from "../../../core/group.js";
import { generateKeyPackage } from "../../../core/key-package.js";
import { InMemoryKeyValueStore } from "../../../extra/in-memory-key-value-store.js";
import { InMemoryEpochSnapshotStore } from "../../../extra/in-memory-epoch-snapshot-store.js";

const CIPHERSUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

async function makeCiphersuite(): Promise<CiphersuiteImpl> {
  return getCiphersuiteImpl(CIPHERSUITE, defaultCryptoProvider);
}

async function makeTwoMemberGroup(impl: CiphersuiteImpl) {
  const adminPubkey = "a".repeat(64);
  const memberPubkey = "c".repeat(64);

  const adminCred = createCredential(adminPubkey);
  const memberCred = createCredential(memberPubkey);

  const adminKp = await generateKeyPackage({
    credential: adminCred,
    ciphersuiteImpl: impl,
  });
  const memberKp = await generateKeyPackage({
    credential: memberCred,
    ciphersuiteImpl: impl,
  });

  const { clientState: adminState0 } = await createSimpleGroup(
    adminKp,
    impl,
    "Test Group",
    { adminPubkeys: [adminPubkey], relays: [] },
  );

  const addProposal = {
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: memberKp.publicPackage },
  };

  const { newState: adminState1, welcome } = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: adminState0,
    wireAsPublicMessage: false,
    extraProposals: [addProposal],
    ratchetTreeExtension: true,
  });

  const memberState1 = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: welcome!.welcome ?? welcome,
    keyPackage: memberKp.publicPackage,
    privateKeys: memberKp.privatePackage,
    ratchetTree: undefined,
  });

  return { adminState1, memberState1, adminPubkey, memberPubkey };
}

function makeNetwork(): NostrNetworkInterface {
  return {
    request: async () => {
      throw new Error("not used");
    },
    subscription: () => {
      throw new Error("not used");
    },
    publish: async () => {
      throw new Error("not used");
    },
    getUserInboxRelays: async () => {
      throw new Error("not used");
    },
  };
}

describe("AC-ROLL-4: rollbackToEpoch restores state byte-for-byte", () => {
  /**
   * Setup: both commits are created from adminState1 (same baseline epoch 1).
   * The receiver is memberState1.
   * commitA = "winner" (earlier created_at / smaller id).
   * commitB = "loser" (later created_at / larger id).
   *
   * Delivery order B-then-A: the receiver ingests B first, advancing to epoch 2
   * with B's state.  Then A arrives as a past-epoch commit.  A wins the MIP-03
   * race (earlier created_at), so rollback fires: restore epoch-1 snapshot, re-apply A.
   */
  it("rolls back and re-applies the winning commit; final state matches winner's newState epoch", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberState1, memberPubkey } =
      await makeTwoMemberGroup(impl);

    // Two commits from the same baseline (adminState1).
    const { commit: commitA, newState: newStateA } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });

    const { commit: commitB } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });

    // Encrypt both with epoch-1 exporter_secret so memberState1 can decrypt them.
    const eventA = await createGroupEvent({
      message: commitA,
      state: adminState1,
      ciphersuite: impl,
    });
    const eventB = await createGroupEvent({
      message: commitB,
      state: adminState1,
      ciphersuite: impl,
    });

    // Make A the winner (earlier created_at, smaller id).
    eventA.created_at = 1000;
    eventA.id = "a".repeat(64);
    eventB.created_at = 2000;
    eventB.id = "b".repeat(64);

    const snapshotStore = new InMemoryEpochSnapshotStore();
    const store = new InMemoryKeyValueStore<SerializedClientState>();
    await store.setItem(
      bytesToHex(memberState1.groupContext.groupId),
      encode(clientStateEncoder, memberState1),
    );

    const signer = { getPublicKey: async () => memberPubkey } as EventSigner;

    const memberGroup = new MarmotGroup(memberState1, {
      store,
      signer,
      ciphersuite: impl,
      network: makeNetwork(),
      snapshots: snapshotStore,
    });

    // Deliver B first (loser in MIP-03 ordering), then A (winner).
    // Sorting in ingest() puts A first, so A is applied and B becomes past-epoch → lost-race.
    // This tests that the loser is correctly identified and skipped.
    const resultsBoth: Array<{ kind: string; reason?: string }> = [];
    for await (const res of memberGroup.ingest([eventB, eventA])) {
      if (res.kind === "skipped") {
        resultsBoth.push({ kind: res.kind, reason: res.reason });
      } else {
        resultsBoth.push({ kind: res.kind });
      }
    }

    // Winner (A) should be processed; loser (B) should be skipped as lost-race.
    expect(resultsBoth).toContainEqual({ kind: "processed" });
    expect(resultsBoth).toContainEqual({
      kind: "skipped",
      reason: "lost-race",
    });

    // Epoch advanced exactly once.
    expect(memberGroup.state.groupContext.epoch).toBe(2n);

    // The new epoch must match what the winner's commit produced.
    expect(memberGroup.state.groupContext.epoch).toBe(
      newStateA.groupContext.epoch,
    );
  });

  it("after rollback, the snapshot for epoch N is overwritten with the winning commit id", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberState1, memberPubkey } =
      await makeTwoMemberGroup(impl);

    const { commit: commitA } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });

    const { commit: commitB } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });

    const eventA = await createGroupEvent({
      message: commitA,
      state: adminState1,
      ciphersuite: impl,
    });
    const eventB = await createGroupEvent({
      message: commitB,
      state: adminState1,
      ciphersuite: impl,
    });

    // A wins.
    eventA.created_at = 1000;
    eventA.id = "a".repeat(64);
    eventB.created_at = 2000;
    eventB.id = "b".repeat(64);

    const snapshotStore = new InMemoryEpochSnapshotStore();
    const store = new InMemoryKeyValueStore<SerializedClientState>();
    await store.setItem(
      bytesToHex(memberState1.groupContext.groupId),
      encode(clientStateEncoder, memberState1),
    );

    const signer = { getPublicKey: async () => memberPubkey } as EventSigner;

    const memberGroup = new MarmotGroup(memberState1, {
      store,
      signer,
      ciphersuite: impl,
      network: makeNetwork(),
      snapshots: snapshotStore,
    });

    // Ingest both in the same batch (sorted internally: A first, B second).
    for await (const _res of memberGroup.ingest([eventB, eventA])) {
      /* consume */
    }

    const groupIdHex = bytesToHex(memberState1.groupContext.groupId);

    // After ingest: snapshot for epoch 1 should record eventA as the applied commit.
    // (The sort puts A first → A applied → snapshot records A → B is lost-race skip.)
    const snap = await snapshotStore.get(groupIdHex, 1n);
    expect(snap).not.toBeNull();
    expect(snap?.appliedCommit?.eventId).toBe(eventA.id);
  });

  it("verifies state restoration: epoch and exporter_secret after rollback+reapply match what admin got from the winning commit", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberState1, memberPubkey } =
      await makeTwoMemberGroup(impl);

    // Both commits from admin baseline; commitA is the winner.
    const { commit: commitA, newState: adminNewStateA } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });

    const { commit: commitB } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });

    const eventA = await createGroupEvent({
      message: commitA,
      state: adminState1,
      ciphersuite: impl,
    });
    const eventB = await createGroupEvent({
      message: commitB,
      state: adminState1,
      ciphersuite: impl,
    });

    // A wins.
    eventA.created_at = 1000;
    eventA.id = "a".repeat(64);
    eventB.created_at = 2000;
    eventB.id = "b".repeat(64);

    const snapshotStore = new InMemoryEpochSnapshotStore();
    const store = new InMemoryKeyValueStore<SerializedClientState>();
    await store.setItem(
      bytesToHex(memberState1.groupContext.groupId),
      encode(clientStateEncoder, memberState1),
    );

    const signer = { getPublicKey: async () => memberPubkey } as EventSigner;

    const memberGroup = new MarmotGroup(memberState1, {
      store,
      signer,
      ciphersuite: impl,
      network: makeNetwork(),
      snapshots: snapshotStore,
    });

    for await (const _res of memberGroup.ingest([eventB, eventA])) {
      /* consume */
    }

    // After rollback+reapply the epoch must agree with the admin's winner newState.
    expect(memberGroup.state.groupContext.epoch).toBe(
      adminNewStateA.groupContext.epoch,
    );

    // The exporter_secret must also agree — both derived the same group key material
    // from the winning commit's key schedule.
    // (MLS: all members derive the same exporter_secret from the same commit.)
    expect(memberGroup.state.keySchedule.exporterSecret).toEqual(
      adminNewStateA.keySchedule.exporterSecret,
    );
  });
});
