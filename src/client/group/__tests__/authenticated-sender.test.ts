/**
 * Tests for authenticated application-message sender enforcement.
 *
 * marmot-ts resolves the MLS-authenticated sender of every application message,
 * enforces that the rumor's claimed `pubkey` matches it, drops any message that
 * fails (no save / no yield-as-processed / no `applicationMessage` emit) while
 * surfacing the authenticated sender on the yielded result and a new
 * `authenticatedApplicationMessage` event.
 *
 * Coverage:
 *   AC-SENDER-1   honest send surfaces senderPubkey and is delivered
 *   AC-SENDER-2   spoof (A sends pubkey:B) is dropped + diagnostic fires
 *   AC-SENDER-3   undeserializable bytes are dropped + diagnostic fires
 *   AC-SURFACE-1  senderPubkey + senderLeafIndex on the yielded result
 *   AC-SURFACE-2  authenticatedApplicationMessage event payload; applicationMessage still fires
 *   AC-STATE-1    a dropped message still consumes the ratchet key (forward secrecy)
 *   AC-OBSERVABLE-1 a dropped message yields `rejected` (not silence) + fires the diagnostic
 *   AC-MULTI-1    each sender in a 3-member group resolves to its own leaf; survives an epoch advance
 *   AC-CASE-1     uppercase-hex rumor.pubkey is accepted (case-insensitive compare)
 *   AC-EPOCH-2    the spoof drop is exercised on the past-epoch branch specifically
 */

import { bytesToHex } from "@noble/hashes/utils.js";
import {
  CiphersuiteImpl,
  type ClientState,
  createApplicationMessage,
  createCommit,
  defaultCryptoProvider,
  defaultProposalTypes,
  getCiphersuiteImpl,
  joinGroup,
  unsafeTestingAuthenticationService,
} from "ts-mls";
import { describe, expect, it } from "vitest";
import type { EventSigner } from "applesauce-core/event-factory";
import type { NostrEvent } from "applesauce-core/helpers/event";
import type { Rumor } from "applesauce-common/helpers/gift-wrap";

import {
  MarmotGroup,
  type AuthenticatedApplicationMessage,
  type BaseGroupHistory,
  type IngestResult,
  type UnauthenticatedMessageInfo,
} from "../marmot-group.js";
import type { NostrNetworkInterface } from "../../nostr-interface.js";
import type { SerializedClientState } from "../../../core/client-state.js";
import { createCredential } from "../../../core/credential.js";
import {
  createGroupEvent,
  serializeApplicationRumor,
} from "../../../core/group-message.js";
import { createSimpleGroup } from "../../../core/group.js";
import { generateKeyPackage } from "../../../core/key-package.js";
import { InMemoryKeyValueStore } from "../../../extra/in-memory-key-value-store.js";
import { marmotAuthService } from "../../../core/auth-service.js";

const CIPHERSUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

async function makeCiphersuite(): Promise<CiphersuiteImpl> {
  return getCiphersuiteImpl(CIPHERSUITE, defaultCryptoProvider);
}

function makeNetwork(): NostrNetworkInterface {
  const nope = async () => {
    throw new Error("network not used in this test");
  };
  return {
    request: nope,
    subscription: () => {
      throw new Error("network not used in this test");
    },
    publish: nope,
    getUserInboxRelays: nope,
  };
}

/** Records every message handed to history so tests can assert save/no-save. */
class RecordingHistory implements BaseGroupHistory {
  readonly saved: Uint8Array[] = [];
  async saveMessage(message: Uint8Array): Promise<void> {
    this.saved.push(message);
  }
  async purgeMessages(): Promise<void> {
    this.saved.length = 0;
  }
}

/** Serialize a rumor with a chosen `pubkey` (the field enforcement checks). */
function rumorBytes(pubkey: string, content = "hi"): Uint8Array {
  return serializeApplicationRumor({
    id: "e".repeat(64),
    pubkey,
    kind: 9,
    content,
    tags: [],
    created_at: 0,
  } as Rumor);
}

const ADMIN_PUBKEY = "a".repeat(64);

/** Build an admin group at epoch 1 with `memberPubkeys` added in one commit. */
async function buildGroup(
  impl: CiphersuiteImpl,
  memberPubkeys: string[],
): Promise<{ adminState1: ClientState; memberStates: ClientState[] }> {
  const adminKp = await generateKeyPackage({
    credential: createCredential(ADMIN_PUBKEY),
    ciphersuiteImpl: impl,
  });
  const memberKps = [];
  for (const pk of memberPubkeys) {
    memberKps.push(
      await generateKeyPackage({
        credential: createCredential(pk),
        ciphersuiteImpl: impl,
      }),
    );
  }

  const { clientState: adminState0 } = await createSimpleGroup(
    adminKp,
    impl,
    "Test Group",
    { adminPubkeys: [ADMIN_PUBKEY], relays: [] },
  );

  const { newState: adminState1, welcome } = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: adminState0,
    wireAsPublicMessage: false,
    extraProposals: memberKps.map((kp) => ({
      proposalType: defaultProposalTypes.add,
      add: { keyPackage: kp.publicPackage },
    })),
    ratchetTreeExtension: true,
  });

  const memberStates: ClientState[] = [];
  for (const kp of memberKps) {
    memberStates.push(
      await joinGroup({
        context: {
          cipherSuite: impl,
          authService: unsafeTestingAuthenticationService,
        },
        welcome: welcome!.welcome ?? welcome,
        keyPackage: kp.publicPackage,
        privateKeys: kp.privatePackage,
        ratchetTree: adminState1.ratchetTree,
      }),
    );
  }
  return { adminState1, memberStates };
}

function makeReceiver(
  state: ClientState,
  pubkey: string,
  impl: CiphersuiteImpl,
  history?: RecordingHistory,
): MarmotGroup<RecordingHistory | undefined> {
  const store = new InMemoryKeyValueStore<SerializedClientState>();
  const signer = { getPublicKey: async () => pubkey } as EventSigner;
  return new MarmotGroup(state, {
    store,
    signer,
    ciphersuite: impl,
    network: makeNetwork(),
    history,
  });
}

/** Create an application-message Nostr event from `senderState` carrying `payload`. */
async function sendApp(
  senderState: ClientState,
  payload: Uint8Array,
  impl: CiphersuiteImpl,
): Promise<{ event: NostrEvent; newState: ClientState }> {
  const { message, newState } = await createApplicationMessage({
    context: {
      cipherSuite: impl,
      authService: marmotAuthService,
      externalPsks: {},
    },
    state: senderState,
    message: payload,
  });
  const event = await createGroupEvent({
    message,
    state: senderState,
    ciphersuite: impl,
  });
  return { event, newState };
}

async function ingestAll(
  group: MarmotGroup<RecordingHistory | undefined>,
  events: NostrEvent[],
): Promise<IngestResult[]> {
  const out: IngestResult[] = [];
  for await (const r of group.ingest(events)) out.push(r);
  return out;
}

/** Advance the admin (self-update commit) and drive the receiver through it. */
async function advance(
  adminState: ClientState,
  receiver: MarmotGroup<RecordingHistory | undefined>,
  impl: CiphersuiteImpl,
): Promise<ClientState> {
  const { newState, commit } = await createCommit({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    state: adminState,
    extraProposals: [],
  });
  const commitEvent = await createGroupEvent({
    message: commit,
    state: adminState,
    ciphersuite: impl,
  });
  await ingestAll(receiver, [commitEvent]);
  return newState;
}

const MEMBER_PUBKEY = "c".repeat(64);

describe("authenticated application-message sender", () => {
  it("AC-SENDER-1 / AC-SURFACE-1 / AC-SURFACE-2: honest send surfaces the sender and delivers", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberStates } = await buildGroup(impl, [
      MEMBER_PUBKEY,
    ]);
    const history = new RecordingHistory();
    const receiver = makeReceiver(
      memberStates[0],
      MEMBER_PUBKEY,
      impl,
      history,
    );

    const appEmits: Uint8Array[] = [];
    const authEmits: AuthenticatedApplicationMessage[] = [];
    receiver.on("applicationMessage", (m) => appEmits.push(m));
    receiver.on("authenticatedApplicationMessage", (m) => authEmits.push(m));

    const { event } = await sendApp(
      adminState1,
      rumorBytes(ADMIN_PUBKEY, "hello"),
      impl,
    );
    const results = await ingestAll(receiver, [event]);

    const processed = results.filter((r) => r.kind === "processed");
    expect(processed).toHaveLength(1);
    const only = processed[0];
    if (only.kind !== "processed" || only.result.kind !== "applicationMessage")
      throw new Error("expected a processed application message");
    // AC-SURFACE-1: authenticated sender surfaced on the yielded result.
    expect(only.senderPubkey).toBe(ADMIN_PUBKEY);
    expect(only.result.senderLeafIndex).toBe(0); // admin is leaf 0

    // Delivered: saved + both events fired.
    expect(history.saved).toHaveLength(1);
    expect(appEmits).toHaveLength(1);
    // AC-SURFACE-2: the authenticated event carries the full resolved payload.
    expect(authEmits).toHaveLength(1);
    expect(authEmits[0].senderPubkey).toBe(ADMIN_PUBKEY);
    expect(authEmits[0].senderLeafIndex).toBe(0);
    expect(authEmits[0].message).toEqual(only.result.message);
  });

  it("AC-SENDER-2 / AC-OBSERVABLE-1: a spoof is dropped and the diagnostic fires", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberStates } = await buildGroup(impl, [
      MEMBER_PUBKEY,
    ]);
    const history = new RecordingHistory();
    const receiver = makeReceiver(
      memberStates[0],
      MEMBER_PUBKEY,
      impl,
      history,
    );

    const appEmits: Uint8Array[] = [];
    const diagnostics: UnauthenticatedMessageInfo[] = [];
    receiver.on("applicationMessage", (m) => appEmits.push(m));
    receiver.on("unauthenticatedMessage", (i) => diagnostics.push(i));

    // Admin (senderPubkey A) claims to be the member (pubkey B).
    const { event } = await sendApp(
      adminState1,
      rumorBytes(MEMBER_PUBKEY, "I am the member"),
      impl,
    );
    const results = await ingestAll(receiver, [event]);

    // AC-OBSERVABLE-1: yields `rejected`, never a processed application message.
    expect(results.some((r) => r.kind === "processed")).toBe(false);
    const rejected = results.filter((r) => r.kind === "rejected");
    expect(rejected).toHaveLength(1);
    const rej = rejected[0];
    if (rej.kind !== "rejected" || rej.reason !== "unauthenticated-sender")
      throw new Error("expected an unauthenticated-sender rejection");
    expect(rej.senderPubkey).toBe(ADMIN_PUBKEY);
    expect(rej.claimedPubkey).toBe(MEMBER_PUBKEY);

    // Dropped: no save, no applicationMessage emit; diagnostic carries A and B.
    expect(history.saved).toHaveLength(0);
    expect(appEmits).toHaveLength(0);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      reason: "unauthenticated-sender",
      senderPubkey: ADMIN_PUBKEY,
      claimedPubkey: MEMBER_PUBKEY,
    });
  });

  it("AC-SENDER-3: undeserializable bytes are dropped with the diagnostic", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberStates } = await buildGroup(impl, [
      MEMBER_PUBKEY,
    ]);
    const history = new RecordingHistory();
    const receiver = makeReceiver(
      memberStates[0],
      MEMBER_PUBKEY,
      impl,
      history,
    );

    const diagnostics: UnauthenticatedMessageInfo[] = [];
    receiver.on("unauthenticatedMessage", (i) => diagnostics.push(i));

    const { event } = await sendApp(
      adminState1,
      new TextEncoder().encode("this is not a rumor"),
      impl,
    );
    const results = await ingestAll(receiver, [event]);

    expect(results.some((r) => r.kind === "processed")).toBe(false);
    const rej = results.find((r) => r.kind === "rejected");
    if (!rej || rej.kind !== "rejected" || rej.reason !== "undeserializable")
      throw new Error("expected an undeserializable rejection");
    expect(rej.senderPubkey).toBe(ADMIN_PUBKEY);
    expect(rej.claimedPubkey).toBeUndefined();
    expect(history.saved).toHaveLength(0);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0].reason).toBe("undeserializable");
  });

  it("AC-SENDER-3: a non-string (truthy) pubkey is dropped as undeserializable, not retried", async () => {
    // A member can craft a rumor whose JSON pubkey is a non-string truthy value
    // (number, array, object). This must classify as `undeserializable` and fire
    // the diagnostic — never silently burn the retry budget as `unreadable`.
    const impl = await makeCiphersuite();
    const { adminState1, memberStates } = await buildGroup(impl, [
      MEMBER_PUBKEY,
    ]);
    const history = new RecordingHistory();
    const receiver = makeReceiver(
      memberStates[0],
      MEMBER_PUBKEY,
      impl,
      history,
    );

    const diagnostics: UnauthenticatedMessageInfo[] = [];
    receiver.on("unauthenticatedMessage", (i) => diagnostics.push(i));

    const malformed = new TextEncoder().encode(
      JSON.stringify({
        id: "e".repeat(64),
        pubkey: 123, // non-string truthy pubkey
        kind: 9,
        content: "x",
        tags: [],
        created_at: 0,
      }),
    );
    const { event } = await sendApp(adminState1, malformed, impl);
    const results = await ingestAll(receiver, [event]);

    expect(results.some((r) => r.kind === "processed")).toBe(false);
    expect(results.some((r) => r.kind === "unreadable")).toBe(false);
    const rej = results.find((r) => r.kind === "rejected");
    if (!rej || rej.kind !== "rejected" || rej.reason !== "undeserializable")
      throw new Error("expected an undeserializable rejection");
    expect(rej.senderPubkey).toBe(ADMIN_PUBKEY);
    expect(history.saved).toHaveLength(0);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0].reason).toBe("undeserializable");
  });

  it("AC-CASE-1: an uppercase-hex claimed pubkey is accepted", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberStates } = await buildGroup(impl, [
      MEMBER_PUBKEY,
    ]);
    const receiver = makeReceiver(memberStates[0], MEMBER_PUBKEY, impl);

    const { event } = await sendApp(
      adminState1,
      rumorBytes(ADMIN_PUBKEY.toUpperCase(), "shouty but honest"),
      impl,
    );
    const results = await ingestAll(receiver, [event]);

    const processed = results.find((r) => r.kind === "processed");
    if (!processed || processed.kind !== "processed")
      throw new Error(
        "expected the case-differing honest message to be delivered",
      );
    expect(results.some((r) => r.kind === "rejected")).toBe(false);
  });

  it("AC-STATE-1: a dropped message still consumes the ratchet key (forward secrecy)", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberStates } = await buildGroup(impl, [
      MEMBER_PUBKEY,
    ]);
    const receiver = makeReceiver(memberStates[0], MEMBER_PUBKEY, impl);

    const { event } = await sendApp(
      adminState1,
      rumorBytes(MEMBER_PUBKEY, "spoof"),
      impl,
    );
    // First delivery: dropped, but MLS state is adopted and the key consumed.
    const first = await ingestAll(receiver, [event]);
    expect(first.some((r) => r.kind === "rejected")).toBe(true);

    // Re-delivering the same event must NOT decrypt again — the ratchet key is
    // gone. If state had not been adopted, the key would still be present and the
    // event would decrypt (and drop) a second time.
    const second = await ingestAll(receiver, [event]);
    expect(second.every((r) => r.kind !== "rejected")).toBe(true);
    expect(second.some((r) => r.kind === "unreadable")).toBe(true);
  });

  it("AC-MULTI-1: each sender resolves to its own leaf, and after an epoch advance too", async () => {
    const impl = await makeCiphersuite();
    const bob = "b".repeat(64);
    const carol = "c".repeat(64);
    // admin (leaf 0), bob (leaf 1), carol (leaf 2). Receiver = carol.
    const { adminState1, memberStates } = await buildGroup(impl, [bob, carol]);
    const bobState = memberStates[0];
    const carolState = memberStates[1];
    const receiver = makeReceiver(carolState, carol, impl);

    const fromAdmin = await sendApp(
      adminState1,
      rumorBytes(ADMIN_PUBKEY),
      impl,
    );
    const fromBob = await sendApp(bobState, rumorBytes(bob), impl);
    const results = await ingestAll(receiver, [fromAdmin.event, fromBob.event]);

    const byLeaf = new Map<number, string>();
    for (const r of results) {
      if (r.kind === "processed" && r.result.kind === "applicationMessage") {
        byLeaf.set(r.result.senderLeafIndex, r.senderPubkey);
      }
    }
    expect(byLeaf.get(0)).toBe(ADMIN_PUBKEY); // admin, leaf 0
    expect(byLeaf.get(1)).toBe(bob); // bob, leaf 1

    // Advance the epoch (admin self-update) and confirm resolution still holds.
    const adminState2 = await advance(adminState1, receiver, impl);
    const afterCommit = await sendApp(
      adminState2,
      rumorBytes(ADMIN_PUBKEY, "post-commit"),
      impl,
    );
    const results2 = await ingestAll(receiver, [afterCommit.event]);
    const processed2 = results2.find(
      (r) => r.kind === "processed" && r.result.kind === "applicationMessage",
    );
    if (
      !processed2 ||
      processed2.kind !== "processed" ||
      processed2.result.kind !== "applicationMessage"
    )
      throw new Error("expected a delivered post-commit message");
    expect(processed2.senderPubkey).toBe(ADMIN_PUBKEY);
    expect(processed2.result.senderLeafIndex).toBe(0);
  });

  it("AC-EPOCH-2: the spoof drop is exercised on the past-epoch branch", async () => {
    const impl = await makeCiphersuite();
    const { adminState1, memberStates } = await buildGroup(impl, [
      MEMBER_PUBKEY,
    ]);
    const receiver = makeReceiver(memberStates[0], MEMBER_PUBKEY, impl);

    const diagnostics: UnauthenticatedMessageInfo[] = [];
    receiver.on("unauthenticatedMessage", (i) => diagnostics.push(i));

    // Admin crafts a spoof at epoch 1 (claims to be the member), held for later.
    const spoof = await sendApp(
      adminState1,
      rumorBytes(MEMBER_PUBKEY, "past-epoch spoof"),
      impl,
    );

    // Advance the receiver to epoch 2 so the spoof is a past-epoch delivery.
    await advance(adminState1, receiver, impl);
    expect(receiver.state.groupContext.epoch).toBe(2n);

    const results = await ingestAll(receiver, [spoof.event]);

    // Decrypted via the past-epoch window, then dropped by enforcement.
    expect(results.some((r) => r.kind === "processed")).toBe(false);
    const rej = results.find((r) => r.kind === "rejected");
    if (
      !rej ||
      rej.kind !== "rejected" ||
      rej.reason !== "unauthenticated-sender"
    )
      throw new Error("expected a past-epoch unauthenticated-sender rejection");
    expect(rej.senderPubkey).toBe(ADMIN_PUBKEY);
    expect(rej.claimedPubkey).toBe(MEMBER_PUBKEY);
    expect(diagnostics).toHaveLength(1);
  });
});
