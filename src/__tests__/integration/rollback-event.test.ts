/**
 * Integration tests for Story S3: Post-rollback message invalidation and rollback event.
 *
 * AC-STRUCT-4 — MarmotGroupEvents includes `rollback: (info: RollbackInfo) => void`
 * AC-EVT-1    — Exactly one `rollback` event fires on a MIP-03 fork resolution
 * AC-EVT-2    — No `rollback` event fires during single-committer (no race) ingest
 * AC-MSG-1    — invalidatedMessages carries IDs of app messages decrypted under the losing epoch
 * AC-MSG-2    — Events unreadable under loser's keys are retried and succeed under the winner's
 *
 * Implementation note for AC-EVT-1 / AC-MSG-1:
 *
 *   A multi-batch rollback (loser applied in batch 1, winner delivered in batch 2) requires
 *   the winner's Nostr event to be NIP-44-decryptable after the member has advanced to the
 *   loser's epoch.  The real protocol solves this via S4 (past-epoch decryption window).
 *
 *   The tests below simulate the scenario by NIP-44-wrapping the winner's MLS commit bytes
 *   with the loser's epoch-2 exporter secret.  This lets the member (at epoch 2) decrypt the
 *   outer NIP-44 envelope; the inner MLS message is still a valid epoch-1 commit.  The
 *   rollback path then fires normally: commitEpoch=1 < currentEpoch=2, snapshot has loser,
 *   winner beats loser → rollback to epoch 1, re-apply winner.  This is the correct unit
 *   scope for S3; full multi-batch end-to-end coverage lands in S4.
 */
import { EventSigner } from "applesauce-core";
import {
  CiphersuiteImpl,
  createApplicationMessage,
  createCommit,
  createProposal,
  defaultCryptoProvider,
  encode,
  clientStateEncoder,
  getCiphersuiteImpl,
  joinGroup,
  unsafeTestingAuthenticationService,
  defaultProposalTypes,
} from "ts-mls";
import { describe, expect, it, vi } from "vitest";
import { bytesToHex } from "@noble/hashes/utils.js";

import {
  MarmotGroup,
  type RollbackInfo,
} from "../../client/group/marmot-group.js";
import type { NostrNetworkInterface } from "../../client/nostr-interface.js";
import {
  deserializeClientState,
  type SerializedClientState,
} from "../../core/client-state.js";
import { createCredential } from "../../core/credential.js";
import { createGroupEvent } from "../../core/group-message.js";
import { createSimpleGroup } from "../../core/group.js";
import { generateKeyPackage } from "../../core/key-package.js";
import { InMemoryKeyValueStore } from "../../extra/in-memory-key-value-store.js";
import { InMemoryEpochSnapshotStore } from "../../extra/in-memory-epoch-snapshot-store.js";
import { MockNetwork } from "../helpers/mock-network.js";

// ---------------------------------------------------------------------------
// Shared test utilities
// ---------------------------------------------------------------------------

function makeNullNetwork(): NostrNetworkInterface {
  return {
    request: async () => {
      throw new Error("not used in this test");
    },
    subscription: () => {
      throw new Error("not used in this test");
    },
    publish: async () => {
      throw new Error("not used in this test");
    },
    getUserInboxRelays: async () => {
      throw new Error("not used in this test");
    },
  };
}

function makeMarmotGroup(
  state: Parameters<typeof MarmotGroup>[0],
  pubkey: string,
  impl: CiphersuiteImpl,
  snapshotStore: InMemoryEpochSnapshotStore,
  network: NostrNetworkInterface = makeNullNetwork(),
): MarmotGroup {
  const store = new InMemoryKeyValueStore<SerializedClientState>();
  store.setItem(
    bytesToHex(state.groupContext.groupId),
    encode(clientStateEncoder, state),
  );
  return new MarmotGroup(state, {
    store,
    signer: { getPublicKey: async () => pubkey } as EventSigner,
    ciphersuite: impl,
    network,
    snapshots: snapshotStore,
  });
}

/**
 * Build a two-member group (admin leaf 0 + member leaf 1) at epoch 1.
 * Returns both member states and the ciphersuite. Pass `relays` when the test
 * needs a member to publish (e.g. sendApplicationRumor) through a MockNetwork.
 */
async function buildTwoMemberGroup(
  impl: CiphersuiteImpl,
  relays: string[] = [],
) {
  const adminPubkey = "a".repeat(64);
  const memberPubkey = "c".repeat(64);

  const adminKp = await generateKeyPackage({
    credential: createCredential(adminPubkey),
    ciphersuiteImpl: impl,
  });
  const memberKp = await generateKeyPackage({
    credential: createCredential(memberPubkey),
    ciphersuiteImpl: impl,
  });

  const { clientState: adminState0 } = await createSimpleGroup(
    adminKp,
    impl,
    "RollbackTest",
    { adminPubkeys: [adminPubkey], relays },
  );

  const { newState: adminState1, welcome } = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: adminState0,
    wireAsPublicMessage: false,
    extraProposals: [
      {
        proposalType: defaultProposalTypes.add,
        add: { keyPackage: memberKp.publicPackage },
      },
    ],
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

  return { adminState1, memberState1, adminPubkey, memberPubkey, impl };
}

// ---------------------------------------------------------------------------
// AC-STRUCT-4: TypeScript compilation check — group.on("rollback", ...) compiles
// ---------------------------------------------------------------------------
describe("AC-STRUCT-4: rollback event type registration", () => {
  it('group.on("rollback", handler) compiles with the correct RollbackInfo signature', async () => {
    const impl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const { memberState1, memberPubkey } = await buildTwoMemberGroup(impl);
    const group = makeMarmotGroup(
      memberState1,
      memberPubkey,
      impl,
      new InMemoryEpochSnapshotStore(),
    );

    // Must compile: 'rollback' is a valid key in MarmotGroupEvents.
    const spy = vi.fn<[RollbackInfo], void>();
    group.on("rollback", spy);

    // No events fired yet.
    expect(spy).not.toHaveBeenCalled();
    group.off("rollback", spy);
  });
});

// ---------------------------------------------------------------------------
// AC-EVT-2: No rollback event fires in single-committer path
// ---------------------------------------------------------------------------
describe("AC-EVT-2: no rollback event in single-committer path", () => {
  it("single commit advances epoch without any rollback event", async () => {
    const impl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const { adminState1, memberState1, memberPubkey } =
      await buildTwoMemberGroup(impl);

    const { commit } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });

    const commitEvent = await createGroupEvent({
      message: commit,
      state: adminState1,
      ciphersuite: impl,
    });
    commitEvent.created_at = 1000;
    commitEvent.id = "a".repeat(64);

    const memberGroup = makeMarmotGroup(
      memberState1,
      memberPubkey,
      impl,
      new InMemoryEpochSnapshotStore(),
    );

    const rollbackSpy = vi.fn<[RollbackInfo], void>();
    memberGroup.on("rollback", rollbackSpy);

    for await (const _r of memberGroup.ingest([commitEvent])) {
      /* consume */
    }

    // Single-committer: no rollback event.
    expect(rollbackSpy).not.toHaveBeenCalled();
    expect(memberGroup.state.groupContext.epoch).toBe(2n);
  });
});

// ---------------------------------------------------------------------------
// AC-EVT-1 + AC-MSG-1: Real rollback event with invalidated message IDs.
//
// Setup:
//   1. Member starts at epoch 1.
//   2. Member ingests the LOSER commit (from adminState1, bad MIP-03 score) in a
//      single-event batch. This advances the member to epoch 2 (loser branch) and
//      records the snapshot with loseEvent as appliedCommit.
//   3. Member ingests an app message encrypted with the loser's epoch-2 keys. The
//      group decrypts it and #messagesByEpoch[2] = [appEvent.id].
//   4. The WINNER commit (from adminState1, better MIP-03 score) arrives. Its inner
//      MLS bytes are a valid epoch-1 commit, but its NIP-44 outer envelope is wrapped
//      with the LOSER's epoch-2 exporter secret (so the member at epoch 2 can decrypt
//      it). The member ingests [winEvent]:
//        - NIP-44 decryption succeeds (loser-epoch-2 keys).
//        - commitEpoch = 1 < currentEpoch = 2 → check snapshot.
//        - snapshot.appliedCommit = loseEvent (recorded in step 2).
//        - isBetterCandidate(winEvent, loseEvent)? winEvent.created_at < loseEvent → YES.
//        - Rollback fires: group rolls back to epoch 1, re-applies winEvent.
//        - rollback event emitted with targetEpoch=1, newHeadCommitEventId=winEvent.id,
//          invalidatedMessages=[appEvent.id].
// ---------------------------------------------------------------------------
describe("AC-EVT-1 + AC-MSG-1: rollback event emitted with correct payload", () => {
  it("emits exactly one rollback event with targetEpoch, winnerEventId, and invalidatedMessages", async () => {
    const impl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const { adminState1, memberState1, memberPubkey } =
      await buildTwoMemberGroup(impl);

    // -----------------------------------------------------------------------
    // Create loser commit: higher created_at, larger id → loses MIP-03 race.
    // -----------------------------------------------------------------------
    const { commit: loseCommit, newState: loserEpoch2State } =
      await createCommit({
        context: {
          cipherSuite: impl,
          authService: unsafeTestingAuthenticationService,
        },
        state: adminState1,
        extraProposals: [],
      });

    const loseEvent = await createGroupEvent({
      message: loseCommit,
      state: adminState1, // epoch-1 NIP-44 envelope
      ciphersuite: impl,
    });
    loseEvent.created_at = 2000; // loses: higher created_at
    loseEvent.id = "f".repeat(64); // loses: larger id

    // -----------------------------------------------------------------------
    // Create winner commit: lower created_at, smaller id → wins MIP-03 race.
    // -----------------------------------------------------------------------
    const { commit: winCommit } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });

    // Wrap the winner's MLS bytes with the LOSER's epoch-2 exporter secret.
    // This lets the member (at epoch 2) decrypt the NIP-44 outer envelope.
    // The inner MLS commit message is still a valid epoch-1 commit.
    const winEvent = await createGroupEvent({
      message: winCommit,
      state: loserEpoch2State, // loser epoch-2 NIP-44 wrap for test decryptability
      ciphersuite: impl,
    });
    winEvent.created_at = 500; // wins: lower created_at
    winEvent.id = "1".repeat(64); // wins: smaller id

    // -----------------------------------------------------------------------
    // Step 2: member ingests the loser commit → advances to losing epoch 2.
    // -----------------------------------------------------------------------
    const snapshotStore = new InMemoryEpochSnapshotStore();
    const memberGroup = makeMarmotGroup(
      memberState1,
      memberPubkey,
      impl,
      snapshotStore,
    );

    for await (const _r of memberGroup.ingest([loseEvent])) {
      /* consume */
    }
    expect(memberGroup.state.groupContext.epoch).toBe(2n);
    // Snapshot must record the loser at epoch 1.
    const snap1 = await snapshotStore.get(
      bytesToHex(memberState1.groupContext.groupId),
      1n,
    );
    expect(snap1?.appliedCommit?.eventId).toBe(loseEvent.id);

    // -----------------------------------------------------------------------
    // Step 3: ingest an app message encrypted under loser's epoch-2 keys.
    //         This populates #messagesByEpoch[2n].
    // -----------------------------------------------------------------------
    const { message: loserAppMsg } = await createApplicationMessage({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
        externalPsks: {},
      },
      state: loserEpoch2State, // loser epoch-2 keys
      message: new TextEncoder().encode("message under loser epoch"),
    });
    const loserAppEvent = await createGroupEvent({
      message: loserAppMsg,
      state: loserEpoch2State,
      ciphersuite: impl,
    });
    loserAppEvent.id = "loserapp".padEnd(64, "0").slice(0, 64);

    const decryptedUnderLoser: string[] = [];
    for await (const r of memberGroup.ingest([loserAppEvent])) {
      if (r.kind === "processed" && r.result.kind === "applicationMessage") {
        decryptedUnderLoser.push(r.event.id);
      }
    }
    expect(decryptedUnderLoser).toContain(loserAppEvent.id);

    // -----------------------------------------------------------------------
    // Step 4: ingest the winner commit (NIP-44 wrapped with loser epoch-2 keys).
    //         Rollback fires: epoch 2 → epoch 1 → apply winner → emit rollback.
    // -----------------------------------------------------------------------
    const rollbackPayloads: RollbackInfo[] = [];
    memberGroup.on("rollback", (info) => rollbackPayloads.push(info));

    for await (const _r of memberGroup.ingest([winEvent])) {
      /* consume */
    }

    // AC-EVT-1: exactly one rollback event.
    expect(rollbackPayloads).toHaveLength(1);

    const info = rollbackPayloads[0];
    // targetEpoch = epoch we rolled back TO (the snapshot's epoch = 1n).
    expect(info.targetEpoch).toBe(1n);
    // newHeadCommitEventId = the winning commit's event id.
    expect(info.newHeadCommitEventId).toBe(winEvent.id);
    // groupId matches the group.
    expect(bytesToHex(info.groupId)).toBe(
      bytesToHex(memberState1.groupContext.groupId),
    );

    // AC-MSG-1: invalidatedMessages contains the app message decrypted under loser epoch 2.
    expect(info.invalidatedMessages).toContain(loserAppEvent.id);

    // After rollback + winner apply, epoch should be at the winner's new epoch.
    expect(memberGroup.state.groupContext.epoch).toBe(2n);
  });
});

// ---------------------------------------------------------------------------
// AC-MSG-2: App messages encrypted under winner's epoch are retried after
//           the winner commit is applied and appear as successfully decrypted.
// ---------------------------------------------------------------------------
describe("AC-MSG-2: winner-epoch app messages retried and decrypted", () => {
  it("app message encrypted under winner epoch-2 keys succeeds via unreadable retry after commit", async () => {
    const impl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const { adminState1, memberState1, memberPubkey } =
      await buildTwoMemberGroup(impl);

    const { commit: winCommit, newState: winnerEpoch2State } =
      await createCommit({
        context: {
          cipherSuite: impl,
          authService: unsafeTestingAuthenticationService,
        },
        state: adminState1,
        extraProposals: [],
      });

    const winEvent = await createGroupEvent({
      message: winCommit,
      state: adminState1,
      ciphersuite: impl,
    });
    winEvent.created_at = 500;
    winEvent.id = "a".repeat(64);

    // App message encrypted under winner's epoch-2 keys — unreadable at epoch 1.
    const plaintext = new TextEncoder().encode("hello from winner epoch");
    const { message: appMsg } = await createApplicationMessage({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
        externalPsks: {},
      },
      state: winnerEpoch2State,
      message: plaintext,
    });
    const appEvent = await createGroupEvent({
      message: appMsg,
      state: winnerEpoch2State,
      ciphersuite: impl,
    });
    appEvent.id = "winnerappmsg".padEnd(64, "0").slice(0, 64);

    const memberGroup = makeMarmotGroup(
      memberState1,
      memberPubkey,
      impl,
      new InMemoryEpochSnapshotStore(),
    );

    // Deliver winner commit + winner app message in one batch.
    // - winEvent: epoch-1 NIP-44 → decryptable at epoch 1 → applied → epoch 2.
    // - appEvent: epoch-2 NIP-44 → fails at epoch 1 → unreadable.
    // After winEvent is applied (epoch 1→2), retry path re-attempts appEvent
    // with epoch-2 keys → succeeds.
    const decryptedIds: string[] = [];
    for await (const r of memberGroup.ingest([winEvent, appEvent])) {
      if (r.kind === "processed" && r.result.kind === "applicationMessage") {
        decryptedIds.push(r.event.id);
      }
    }

    // AC-MSG-2: app message appears as successfully decrypted.
    expect(decryptedIds).toContain(appEvent.id);
    expect(memberGroup.state.groupContext.epoch).toBe(2n);
  });
});

// ---------------------------------------------------------------------------
// Regression guard: a competing commit that wins the MIP-03 *metadata* race
// (attacker-controllable outer created_at / id) but FAILS MLS validation must
// NOT regress state. Rollback must only commit after the winner validates;
// otherwise a hostile "better-looking" commit could force the victim back to
// an earlier epoch and discard its valid branch.
// ---------------------------------------------------------------------------
describe("rollback regression guard: invalid better-candidate does not regress state", () => {
  it("keeps current state and fires no rollback when the better-metadata commit fails validation", async () => {
    const impl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const { adminState1, memberState1, memberPubkey } =
      await buildTwoMemberGroup(impl);

    // Member applies the loser commit → advances to epoch 2, snapshot records
    // the loser at epoch 1.
    const { commit: loseCommit } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });
    const loseEvent = await createGroupEvent({
      message: loseCommit,
      state: adminState1,
      ciphersuite: impl,
    });
    loseEvent.created_at = 2000; // loses
    loseEvent.id = "f".repeat(64); // loses

    const memberGroup = makeMarmotGroup(
      memberState1,
      memberPubkey,
      impl,
      new InMemoryEpochSnapshotStore(),
    );

    // We need the loser-epoch-2 exporter secret to NIP-44-wrap the hostile
    // event so the member (at epoch 2) can decrypt its outer envelope. Re-derive
    // it by applying the loser commit to the admin's epoch-1 state.
    const { newState: loserEpoch2State } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });

    for await (const _r of memberGroup.ingest([loseEvent])) {
      /* consume */
    }
    expect(memberGroup.state.groupContext.epoch).toBe(2n);

    const epochBefore = memberGroup.state.groupContext.epoch;
    const exporterBefore = memberGroup.state.keySchedule.exporterSecret.slice();

    // Build a FOREIGN commit from a wholly separate group. Its inner MLS bytes
    // are a valid epoch-1 commit for *that* group, so processMessage against our
    // group's epoch-1 snapshot will fail (wrong group context / signature).
    const foreign = await buildTwoMemberGroup(impl);
    const { commit: foreignCommit } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: foreign.adminState1,
      extraProposals: [],
    });
    // Wrap the foreign commit with OUR loser epoch-2 exporter secret so the
    // member decrypts the NIP-44 envelope and reaches the rollback decision.
    const hostileEvent = await createGroupEvent({
      message: foreignCommit,
      state: loserEpoch2State,
      ciphersuite: impl,
    });
    hostileEvent.created_at = 400; // wins on metadata
    hostileEvent.id = "0".repeat(64); // wins on metadata

    const rollbackPayloads: RollbackInfo[] = [];
    memberGroup.on("rollback", (info) => rollbackPayloads.push(info));

    for await (const _r of memberGroup.ingest([hostileEvent])) {
      /* consume */
    }

    // No rollback event — the hostile commit never validated.
    expect(rollbackPayloads).toHaveLength(0);
    // State is unchanged: same epoch and same exporter_secret (loser branch).
    expect(memberGroup.state.groupContext.epoch).toBe(epochBefore);
    expect(memberGroup.state.keySchedule.exporterSecret).toEqual(
      exporterBefore,
    );
  });
});

// ---------------------------------------------------------------------------
// Genuine cross-batch rollback (S2 + S4 together): the winning commit arrives
// in a LATER batch, after the member already advanced to the loser epoch, and
// is decryptable ONLY through the retained past-epoch exporter secret. This is
// the real delayed-delivery fork scenario — not the same-batch shortcut the
// AC-EVT-1 test uses (which re-wraps the winner with the loser key).
// ---------------------------------------------------------------------------
describe("cross-batch rollback via past-epoch window (S2 + S4)", () => {
  it("decrypts a later-arriving winner through the retained epoch-1 key and rolls back to converge", async () => {
    const impl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const { adminState1, memberState1, memberPubkey } =
      await buildTwoMemberGroup(impl);

    // Two competing epoch-1 commits from the same admin baseline, each wrapped
    // with its OWN epoch-1 envelope (no test shortcut re-wrapping).
    const { commit: loseCommit } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });
    const loseEvent = await createGroupEvent({
      message: loseCommit,
      state: adminState1,
      ciphersuite: impl,
    });
    loseEvent.created_at = 2000; // loses
    loseEvent.id = "f".repeat(64); // loses

    const { commit: winCommit, newState: winnerState } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });
    const winEvent = await createGroupEvent({
      message: winCommit,
      state: adminState1, // ORIGINAL epoch-1 envelope — not re-wrapped
      ciphersuite: impl,
    });
    winEvent.created_at = 500; // wins
    winEvent.id = "1".repeat(64); // wins

    const memberGroup = makeMarmotGroup(
      memberState1,
      memberPubkey,
      impl,
      new InMemoryEpochSnapshotStore(),
    );

    // Batch 1: member applies the loser → epoch 2, retains the epoch-1 exporter
    // secret in the past-epoch ring, snapshot records the loser at epoch 1.
    for await (const _r of memberGroup.ingest([loseEvent])) {
      /* consume */
    }
    expect(memberGroup.state.groupContext.epoch).toBe(2n);

    const rollbackPayloads: RollbackInfo[] = [];
    memberGroup.on("rollback", (info) => rollbackPayloads.push(info));

    // Batch 2 (later): the winner arrives with its original epoch-1 envelope.
    // At epoch 2 the current secret cannot decrypt it; Step 1b retries with the
    // retained epoch-1 key, recognises a commit, and routes it to the rollback
    // path, which converges the member onto the winner.
    for await (const _r of memberGroup.ingest([winEvent])) {
      /* consume */
    }

    // Rollback fired exactly once, converging to the winner.
    expect(rollbackPayloads).toHaveLength(1);
    expect(rollbackPayloads[0].newHeadCommitEventId).toBe(winEvent.id);
    expect(rollbackPayloads[0].targetEpoch).toBe(1n);
    // Member now holds the winner's state (same exporter_secret as the winner).
    expect(memberGroup.state.keySchedule.exporterSecret).toEqual(
      winnerState.keySchedule.exporterSecret,
    );
  });
});

// ---------------------------------------------------------------------------
// Replay guard over the MLS message (not outer content): a re-wrapped copy of
// the already-applied commit — different Nostr id / created_at / ciphertext
// (fresh NIP-44 nonce) but the SAME inner MLS commit — must be recognised as a
// replay and skipped, NOT trigger a spurious rollback even when its metadata
// "wins" the MIP-03 comparison.
// ---------------------------------------------------------------------------
describe("replay guard recognises a re-wrapped duplicate commit", () => {
  it("skips a re-wrapped applied commit with better metadata instead of rolling back", async () => {
    const impl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const { adminState1, memberState1, memberPubkey } =
      await buildTwoMemberGroup(impl);

    // A single epoch-1 commit the member will apply normally.
    const { commit } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });
    const appliedEvent = await createGroupEvent({
      message: commit,
      state: adminState1,
      ciphersuite: impl,
    });
    appliedEvent.created_at = 1000;
    appliedEvent.id = "5".repeat(64);

    const memberGroup = makeMarmotGroup(
      memberState1,
      memberPubkey,
      impl,
      new InMemoryEpochSnapshotStore(),
    );

    // Apply it → epoch 2, snapshot[1] records this commit, epoch-1 key retained.
    for await (const _r of memberGroup.ingest([appliedEvent])) {
      /* consume */
    }
    expect(memberGroup.state.groupContext.epoch).toBe(2n);
    const exporterAfter = memberGroup.state.keySchedule.exporterSecret.slice();

    // Re-wrap the SAME MLS commit with a fresh NIP-44 nonce, and give it
    // metadata that would WIN the MIP-03 race (earlier created_at, smaller id).
    const reWrapped = await createGroupEvent({
      message: commit,
      state: adminState1,
      ciphersuite: impl,
    });
    reWrapped.created_at = 100; // would "win" on created_at
    reWrapped.id = "0".repeat(64); // would "win" on id
    expect(reWrapped.content).not.toBe(appliedEvent.content); // fresh nonce

    const rollbackPayloads: RollbackInfo[] = [];
    memberGroup.on("rollback", (info) => rollbackPayloads.push(info));

    const reasons: string[] = [];
    for await (const r of memberGroup.ingest([reWrapped])) {
      if (r.kind === "skipped") reasons.push(r.reason);
    }

    // Recognised as a replay of the applied commit — no rollback, no state change.
    expect(reasons).toContain("self-echo-commit");
    expect(rollbackPayloads).toHaveLength(0);
    expect(memberGroup.state.groupContext.epoch).toBe(2n);
    expect(memberGroup.state.keySchedule.exporterSecret).toEqual(exporterAfter);
  });
});

// ---------------------------------------------------------------------------
// AC-MSG-1 (local messages): a message the member SENT on the losing branch
// must also appear in invalidatedMessages after a rollback. sendApplicationRumor
// tracks the sent event under its epoch so the rollback collector sees it.
// ---------------------------------------------------------------------------
describe("rollback invalidates locally-sent messages too", () => {
  it("includes a message sent on the loser branch in RollbackInfo.invalidatedMessages", async () => {
    const impl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const relay = "wss://mock-relay.test";
    const { adminState1, memberState1, memberPubkey } =
      await buildTwoMemberGroup(impl, [relay]);

    // Loser + winner, both epoch-1 commits with their own envelopes.
    const { commit: loseCommit } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });
    const loseEvent = await createGroupEvent({
      message: loseCommit,
      state: adminState1,
      ciphersuite: impl,
    });
    loseEvent.created_at = 2000;
    loseEvent.id = "f".repeat(64);

    const { commit: winCommit } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });
    const winEvent = await createGroupEvent({
      message: winCommit,
      state: adminState1,
      ciphersuite: impl,
    });
    winEvent.created_at = 500;
    winEvent.id = "1".repeat(64);

    const memberGroup = makeMarmotGroup(
      memberState1,
      memberPubkey,
      impl,
      new InMemoryEpochSnapshotStore(),
      new MockNetwork(),
    );

    // Batch 1: apply the loser → epoch 2.
    for await (const _r of memberGroup.ingest([loseEvent])) {
      /* consume */
    }
    expect(memberGroup.state.groupContext.epoch).toBe(2n);

    // Member sends its own chat message on the loser branch (epoch 2).
    await memberGroup.sendChatMessage("hello from the loser branch");
    // Capture the sent event id from the published kind-445 event.
    const published = (memberGroup.network as MockNetwork).events;
    const sentLocalId = published[published.length - 1].id;

    const rollbackPayloads: RollbackInfo[] = [];
    memberGroup.on("rollback", (info) => rollbackPayloads.push(info));

    // Batch 2: winner arrives (decrypted via the retained epoch-1 key) → rollback.
    for await (const _r of memberGroup.ingest([winEvent])) {
      /* consume */
    }

    expect(rollbackPayloads).toHaveLength(1);
    // The locally-sent message on the discarded branch is invalidated.
    expect(rollbackPayloads[0].invalidatedMessages).toContain(sentLocalId);
  });
});

// ---------------------------------------------------------------------------
// Finding-2 convergence: a proposal for an epoch the member has already passed
// is merged into that epoch's snapshot, so a later rollback whose winning
// commit references the proposal can resolve it. This test exercises the merge
// mechanism: after ingesting a past-epoch proposal, the epoch-1 snapshot's
// serialized state changes and gains an unapplied proposal.
// ---------------------------------------------------------------------------
describe("past-epoch proposal merges into the matching snapshot", () => {
  it("updates the epoch-1 snapshot with a proposal that arrives after the member advanced", async () => {
    const impl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const { adminState1, memberState1, memberPubkey } =
      await buildTwoMemberGroup(impl);

    // A commit the member applies to advance to epoch 2 (retains the epoch-1
    // key and records the epoch-1 snapshot).
    const { commit } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });
    const commitEvent = await createGroupEvent({
      message: commit,
      state: adminState1,
      ciphersuite: impl,
    });
    commitEvent.created_at = 1000;
    commitEvent.id = "5".repeat(64);

    const snapshots = new InMemoryEpochSnapshotStore();
    const memberGroup = makeMarmotGroup(
      memberState1,
      memberPubkey,
      impl,
      snapshots,
    );
    const groupIdHex = bytesToHex(memberState1.groupContext.groupId);

    for await (const _r of memberGroup.ingest([commitEvent])) {
      /* consume */
    }
    expect(memberGroup.state.groupContext.epoch).toBe(2n);

    const snapBefore = await snapshots.get(groupIdHex, 1n);
    expect(snapBefore).not.toBeNull();
    const stateBefore = snapBefore!.state.slice();

    // An epoch-1 add proposal published by the admin, delivered to the member
    // only now (after it advanced to epoch 2).
    const newMemberKp = await generateKeyPackage({
      credential: createCredential("d".repeat(64)),
      ciphersuiteImpl: impl,
    });
    const { message: proposalMessage } = await createProposal({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      proposal: {
        proposalType: defaultProposalTypes.add,
        add: { keyPackage: newMemberKp.publicPackage },
      },
      wireAsPublicMessage: false,
    });
    const proposalEvent = await createGroupEvent({
      message: proposalMessage,
      state: adminState1, // epoch-1 envelope
      ciphersuite: impl,
    });
    proposalEvent.id = "deadbeef".padEnd(64, "0").slice(0, 64);

    for await (const _r of memberGroup.ingest([proposalEvent])) {
      /* consume */
    }

    // The epoch-1 snapshot now carries the proposal: bytes changed and the
    // deserialized snapshot has an unapplied proposal.
    const snapAfter = await snapshots.get(groupIdHex, 1n);
    expect(snapAfter).not.toBeNull();
    expect(snapAfter!.state).not.toEqual(stateBefore);
    const restored = deserializeClientState(snapAfter!.state);
    expect(Object.keys(restored.unappliedProposals).length).toBeGreaterThan(0);
    // Live state is untouched — the proposal was not applied to the current epoch.
    expect(memberGroup.state.groupContext.epoch).toBe(2n);
  });
});
