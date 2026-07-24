/**
 * Tests for Story S4: Bounded past-epoch decryption window.
 *
 * AC-PAST-1: A member that has advanced to a later epoch CAN still decrypt
 * application messages encrypted under a past epoch (within pastEpochDepth),
 * WITHOUT triggering a rollback event.
 *
 * AC-PAST-2: A member more than pastEpochDepth epochs ahead MUST NOT decrypt
 * messages from outside the window — they are yielded as unreadable (deferred),
 * not silently dropped, and do NOT cause a rollback.
 */

import { bytesToHex } from "@noble/hashes/utils.js";
import {
  CiphersuiteImpl,
  createApplicationMessage,
  createCommit,
  defaultCryptoProvider,
  defaultProposalTypes,
  encode,
  clientStateEncoder,
  getCiphersuiteImpl,
  getCredentialFromLeafIndex,
  joinGroup,
  type ClientState,
  unsafeTestingAuthenticationService,
} from "ts-mls";
import { describe, expect, it } from "vitest";
import type { EventSigner } from "applesauce-core/event-factory";
import type { NostrEvent } from "applesauce-core/helpers/event";
import type { Rumor } from "applesauce-common/helpers/gift-wrap";

import { MarmotGroup } from "../marmot-group.js";
import type { NostrNetworkInterface } from "../../nostr-interface.js";
import type { SerializedClientState } from "../../../core/client-state.js";
import {
  createCredential,
  getCredentialPubkey,
} from "../../../core/credential.js";
import {
  createGroupEvent,
  serializeApplicationRumor,
} from "../../../core/group-message.js";
import { createSimpleGroup } from "../../../core/group.js";
import { generateKeyPackage } from "../../../core/key-package.js";
import { InMemoryKeyValueStore } from "../../../extra/in-memory-key-value-store.js";
import { InMemoryEpochSnapshotStore } from "../../../extra/in-memory-epoch-snapshot-store.js";
import { marmotAuthService } from "../../../core/auth-service.js";

const CIPHERSUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

async function makeCiphersuite(): Promise<CiphersuiteImpl> {
  return getCiphersuiteImpl(CIPHERSUITE, defaultCryptoProvider);
}

/**
 * Build an authentic application-message payload: a serialized rumor whose
 * `pubkey` matches the sending state's own MLS leaf credential, so it passes the
 * receiver's sender-authentication enforcement. Application messages carrying raw
 * (non-rumor) bytes are now dropped as `undeserializable`, so decrypt/rollback
 * fixtures must send real rumors.
 */
function authenticAppData(state: ClientState, content: string): Uint8Array {
  const pubkey = getCredentialPubkey(
    getCredentialFromLeafIndex(state.ratchetTree, state.privatePath.leafIndex),
  );
  return serializeApplicationRumor({
    id: "e".repeat(64),
    pubkey,
    kind: 9,
    content,
    tags: [],
    created_at: 0,
  } as Rumor);
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

/**
 * Creates a two-member group at epoch 1.
 * Returns both members' states and their public keys.
 */
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

/**
 * Builds a MarmotGroup for the member and processes N sequential self-update
 * commits from the admin, advancing both admin and member through N epochs.
 *
 * Returns:
 * - memberGroup at epoch (1 + N)
 * - the admin state sequence (indexed 0 = epoch 1, N = epoch 1+N)
 * - the commit events produced at each epoch transition
 */
async function buildGroupAtEpoch(
  adminState1: ClientState,
  memberState1: ClientState,
  memberPubkey: string,
  impl: CiphersuiteImpl,
  advanceCount: number,
  pastEpochDepth: number,
): Promise<{
  memberGroup: MarmotGroup;
  adminStates: ClientState[];
  commitEvents: NostrEvent[];
}> {
  const store = new InMemoryKeyValueStore<SerializedClientState>();
  await store.setItem(
    bytesToHex(memberState1.groupContext.groupId),
    encode(clientStateEncoder, memberState1),
  );
  const signer = {
    getPublicKey: async () => memberPubkey,
  } as EventSigner;

  const memberGroup = new MarmotGroup(memberState1, {
    store,
    signer,
    ciphersuite: impl,
    network: makeNetwork(),
    snapshots: new InMemoryEpochSnapshotStore(),
    pastEpochDepth,
  });

  const adminStates: ClientState[] = [adminState1];
  const commitEvents: NostrEvent[] = [];

  let currentAdminState = adminState1;

  for (let i = 0; i < advanceCount; i++) {
    const { newState: nextAdminState, commit } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: currentAdminState,
      extraProposals: [],
    });

    // Encrypt the commit event with the CURRENT epoch's exporter_secret.
    const ev = await createGroupEvent({
      message: commit,
      state: currentAdminState,
      ciphersuite: impl,
    });
    ev.created_at = 1000 + i;
    ev.id = String(i).repeat(64);

    // Member processes the commit.
    for await (const _res of memberGroup.ingest([ev])) {
      // consume results
    }

    commitEvents.push(ev);
    currentAdminState = nextAdminState;
    adminStates.push(currentAdminState);
  }

  return { memberGroup, adminStates, commitEvents };
}

// ---------------------------------------------------------------------------
// AC-PAST-1: member one epoch behind decrypts a recent app message, no rollback
// ---------------------------------------------------------------------------

describe("AC-PAST-1: past-epoch application message decrypts without rollback", () => {
  it("decrypts an application message encrypted under epoch N when the member is at epoch N+1", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberState1, memberPubkey } =
      await makeTwoMemberGroup(impl);

    // Step 1: Build the group — member advances from epoch 1 to epoch 2.
    const { memberGroup } = await buildGroupAtEpoch(
      adminState1,
      memberState1,
      memberPubkey,
      impl,
      1, // advance 1 epoch
      5, // pastEpochDepth
    );

    expect(memberGroup.state.groupContext.epoch).toBe(2n);

    // Step 2: Admin creates an application message at epoch 1 (before the advance).
    // This message is encrypted with the epoch-1 exporter_secret.
    const appData = authenticAppData(adminState1, "hello from epoch 1");
    const { message: appMessage } = await createApplicationMessage({
      context: {
        cipherSuite: impl,
        authService: marmotAuthService,
        externalPsks: {},
      },
      state: adminState1, // epoch 1 state
      message: appData,
    });

    const appEvent = await createGroupEvent({
      message: appMessage,
      state: adminState1, // encrypted with epoch-1 exporter_secret
      ciphersuite: impl,
    });

    let rollbackFired = false;
    memberGroup.on("rollback", () => {
      rollbackFired = true;
    });

    // Step 3: Member receives the epoch-1 application message while at epoch 2.
    const step2Results: Array<{ kind: string }> = [];
    for await (const res of memberGroup.ingest([appEvent])) {
      step2Results.push({ kind: res.kind });
    }

    // (a) The message MUST be successfully decrypted (kind: "processed").
    expect(step2Results).toContainEqual({ kind: "processed" });
    // (b) No rollback triggered.
    expect(rollbackFired).toBe(false);
    // (c) No unreadable result.
    expect(step2Results.every((r) => r.kind !== "unreadable")).toBe(true);
    // (d) Epoch unchanged.
    expect(memberGroup.state.groupContext.epoch).toBe(2n);
  });

  it("decrypts an application message encrypted under epoch N when member is at N+3 (within depth=5)", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberState1, memberPubkey } =
      await makeTwoMemberGroup(impl);

    // Advance member through 3 commits (epoch 1 → 4).
    const { memberGroup } = await buildGroupAtEpoch(
      adminState1,
      memberState1,
      memberPubkey,
      impl,
      3,
      5,
    );
    expect(memberGroup.state.groupContext.epoch).toBe(4n);

    // Application message created at epoch 1 (3 epochs behind current = 4).
    const appData = authenticAppData(adminState1, "hello from epoch 1");
    const { message: appMessage } = await createApplicationMessage({
      context: {
        cipherSuite: impl,
        authService: marmotAuthService,
        externalPsks: {},
      },
      state: adminState1,
      message: appData,
    });
    const appEvent = await createGroupEvent({
      message: appMessage,
      state: adminState1,
      ciphersuite: impl,
    });

    let rollbackFired = false;
    memberGroup.on("rollback", () => {
      rollbackFired = true;
    });

    const results: Array<{ kind: string }> = [];
    for await (const res of memberGroup.ingest([appEvent])) {
      results.push({ kind: res.kind });
    }

    // (a) Successfully decrypted — 3 epochs behind is within depth=5 window.
    expect(results).toContainEqual({ kind: "processed" });
    // (b, c) No rollback.
    expect(rollbackFired).toBe(false);
    expect(memberGroup.state.groupContext.epoch).toBe(4n);
  });

  it("defaults pastEpochDepth to 5 when not provided in options (construction succeeds)", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberState1, memberPubkey } =
      await makeTwoMemberGroup(impl);

    // Construct MarmotGroup without pastEpochDepth — should not throw.
    const store = new InMemoryKeyValueStore<SerializedClientState>();
    await store.setItem(
      bytesToHex(memberState1.groupContext.groupId),
      encode(clientStateEncoder, memberState1),
    );
    const memberGroup = new MarmotGroup(memberState1, {
      store,
      signer: { getPublicKey: async () => memberPubkey } as EventSigner,
      ciphersuite: impl,
      network: makeNetwork(),
    });

    // Group should be constructed and at the initial epoch.
    expect(memberGroup).toBeDefined();
    expect(memberGroup.state.groupContext.epoch).toBe(1n);

    // Advance once and confirm past-epoch decryption still works (depth defaults to 5).
    const { newState: _unused, commit } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });
    const commitEv = await createGroupEvent({
      message: commit,
      state: adminState1,
      ciphersuite: impl,
    });
    commitEv.created_at = 1000;
    commitEv.id = "0".repeat(64);

    for await (const _res of memberGroup.ingest([commitEv])) {
      // consume
    }
    expect(memberGroup.state.groupContext.epoch).toBe(2n);

    // App message from epoch 1 should be in the default window of 5.
    const { message: appMessage } = await createApplicationMessage({
      context: {
        cipherSuite: impl,
        authService: marmotAuthService,
        externalPsks: {},
      },
      state: adminState1,
      message: authenticAppData(adminState1, "default depth test"),
    });
    const appEv = await createGroupEvent({
      message: appMessage,
      state: adminState1,
      ciphersuite: impl,
    });

    const appResults: string[] = [];
    for await (const res of memberGroup.ingest([appEv])) {
      appResults.push(res.kind);
    }
    // The message should be decrypted (depth=5 default retains epoch 1).
    expect(appResults).toContain("processed");
  });
});

// ---------------------------------------------------------------------------
// AC-PAST-2: beyond-window boundary → unreadable, not dropped, no rollback
// ---------------------------------------------------------------------------

describe("AC-PAST-2: beyond-window messages are unreadable, not dropped or rolled back", () => {
  it("yields unreadable (not silently drops) for a message beyond pastEpochDepth=1", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberState1, memberPubkey } =
      await makeTwoMemberGroup(impl);

    // pastEpochDepth = 1: only the most recent past epoch key is retained.
    // Advance member 2 epochs (1→2→3). Epoch-1's key will be evicted after epoch 2→3.
    const { memberGroup } = await buildGroupAtEpoch(
      adminState1,
      memberState1,
      memberPubkey,
      impl,
      2, // advance 2 epochs
      1, // pastEpochDepth = 1
    );
    expect(memberGroup.state.groupContext.epoch).toBe(3n);

    // Application message from epoch 1 — should be OUTSIDE the window (depth=1 retains epoch-2 only).
    const { message: appMessage } = await createApplicationMessage({
      context: {
        cipherSuite: impl,
        authService: marmotAuthService,
        externalPsks: {},
      },
      state: adminState1,
      message: new TextEncoder().encode("outside window"),
    });
    const appEvent = await createGroupEvent({
      message: appMessage,
      state: adminState1,
      ciphersuite: impl,
    });

    let rollbackFired = false;
    memberGroup.on("rollback", () => {
      rollbackFired = true;
    });

    const results: Array<{ kind: string; errors?: unknown[] }> = [];
    for await (const res of memberGroup.ingest([appEvent])) {
      if (res.kind === "unreadable") {
        results.push({ kind: res.kind, errors: res.errors });
      } else {
        results.push({ kind: res.kind });
      }
    }

    // The message MUST be yielded as unreadable (not silently dropped).
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].kind).toBe("unreadable");

    // MUST NOT trigger a rollback.
    expect(rollbackFired).toBe(false);

    // Epoch MUST remain unchanged.
    expect(memberGroup.state.groupContext.epoch).toBe(3n);
  });
});

// ---------------------------------------------------------------------------
// VQ-S4-003 / VQ-S4-008: exporter_secret ring stays bounded (forward secrecy)
// ---------------------------------------------------------------------------

describe("VQ-S4-003 / VQ-S4-008: past-epoch key ring stays bounded", () => {
  it("retains at most pastEpochDepth=2 entries after 5 advances", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberState1, memberPubkey } =
      await makeTwoMemberGroup(impl);

    // Advance through 5 epochs with depth=2 (epochs 1→6).
    const { memberGroup, adminStates } = await buildGroupAtEpoch(
      adminState1,
      memberState1,
      memberPubkey,
      impl,
      5, // 5 advances → epoch 6
      2, // pastEpochDepth = 2 → retains epochs 4 and 5 after advancing to 6
    );
    expect(memberGroup.state.groupContext.epoch).toBe(6n);

    // App message from epoch 4 — within window (depth=2, current=6: retained epochs 4 and 5).
    const { message: appMsg4 } = await createApplicationMessage({
      context: {
        cipherSuite: impl,
        authService: marmotAuthService,
        externalPsks: {},
      },
      state: adminStates[3], // epoch 4 (adminStates[0]=epoch1, adminStates[3]=epoch4)
      message: authenticAppData(adminStates[3], "from epoch 4"),
    });
    const appEvent4 = await createGroupEvent({
      message: appMsg4,
      state: adminStates[3],
      ciphersuite: impl,
    });

    // App message from epoch 1 — outside window.
    const { message: appMsg1 } = await createApplicationMessage({
      context: {
        cipherSuite: impl,
        authService: marmotAuthService,
        externalPsks: {},
      },
      state: adminState1,
      message: new TextEncoder().encode("from epoch 1"),
    });
    const appEvent1 = await createGroupEvent({
      message: appMsg1,
      state: adminState1,
      ciphersuite: impl,
    });

    // Epoch 4 is in the window → must decrypt successfully.
    const res4: string[] = [];
    for await (const res of memberGroup.ingest([appEvent4])) {
      res4.push(res.kind);
    }
    expect(res4).toContain("processed");

    // Epoch 1 is outside the window (depth=2 keeps only 4 and 5) → must be unreadable.
    const res1: string[] = [];
    for await (const res of memberGroup.ingest([appEvent1])) {
      res1.push(res.kind);
    }
    expect(res1).toContain("unreadable");
  });
});
