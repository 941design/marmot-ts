/**
 * AC-PROP-1: Property-based convergence test using fast-check.
 *
 * For K ≥ 2 members each committing a self-update at the same epoch,
 * delivers all commits in a random permutation and asserts every member
 * converges to the same epoch + exporter_secret + winning commit.
 *
 * NOTE: In MLS, a committer cannot apply their own commit via processMessage
 * (UpdatePath is encrypted to others). All K commits are therefore created
 * from the ADMIN's baseline state (same epoch), and a single non-committer
 * member (the observer) applies all of them. The observer must settle on the
 * MIP-03-minimum commit regardless of delivery order.
 *
 * We use numRuns = 20 to keep the suite fast while still covering many orderings.
 */

import { EventSigner } from "applesauce-core/event-factory";
import {
  CiphersuiteImpl,
  createCommit,
  defaultCryptoProvider,
  defaultProposalTypes,
  getCiphersuiteImpl,
  joinGroup,
  unsafeTestingAuthenticationService,
  encode,
  clientStateEncoder,
  type ClientState,
} from "ts-mls";
import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { bytesToHex } from "@noble/hashes/utils.js";

import { MarmotGroup } from "../../client/group/marmot-group.js";
import type { NostrNetworkInterface } from "../../client/nostr-interface.js";
import { SerializedClientState } from "../../core/client-state.js";
import { createCredential } from "../../core/credential.js";
import { createGroupEvent } from "../../core/group-message.js";
import { createSimpleGroup } from "../../core/group.js";
import { generateKeyPackage } from "../../core/key-package.js";
import { InMemoryKeyValueStore } from "../../extra/in-memory-key-value-store.js";
import { InMemoryEpochSnapshotStore } from "../../extra/in-memory-epoch-snapshot-store.js";
import { isBetterCandidate } from "../../core/group-message.js";
import type { NostrEvent } from "applesauce-core/helpers/event";

const CIPHERSUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

function makeNullNetwork(): NostrNetworkInterface {
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

/** Build a group with 1 admin + 1 observer (non-committer member). */
async function buildObserverGroup(impl: CiphersuiteImpl) {
  const adminPubkey = "a".repeat(64);
  const observerPubkey = "f".repeat(64);

  const adminCred = createCredential(adminPubkey);
  const observerCred = createCredential(observerPubkey);

  const adminKp = await generateKeyPackage({
    credential: adminCred,
    ciphersuiteImpl: impl,
  });
  const observerKp = await generateKeyPackage({
    credential: observerCred,
    ciphersuiteImpl: impl,
  });

  const { clientState: adminState0 } = await createSimpleGroup(
    adminKp,
    impl,
    "PropTest",
    { adminPubkeys: [adminPubkey], relays: [] },
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
        add: { keyPackage: observerKp.publicPackage },
      },
    ],
    ratchetTreeExtension: true,
  });

  const observerState1 = await joinGroup({
    context: {
      cipherSuite: impl,
      authService: unsafeTestingAuthenticationService,
    },
    welcome: welcome!.welcome ?? welcome,
    keyPackage: observerKp.publicPackage,
    privateKeys: observerKp.privatePackage,
    ratchetTree: undefined,
  });

  return { adminState1, observerState1, adminPubkey, observerPubkey };
}

/**
 * Create K concurrent commits from the same admin baseline.
 * Each commit gets a deterministic unique created_at and id derived from index.
 */
async function makeKCommits(
  adminState1: ClientState,
  impl: CiphersuiteImpl,
  k: number,
): Promise<Array<{ event: NostrEvent; newState: ClientState; index: number }>> {
  const results: Array<{
    event: NostrEvent;
    newState: ClientState;
    index: number;
  }> = [];

  for (let i = 0; i < k; i++) {
    const { commit, newState } = await createCommit({
      context: {
        cipherSuite: impl,
        authService: unsafeTestingAuthenticationService,
      },
      state: adminState1,
      extraProposals: [],
    });

    const event = await createGroupEvent({
      message: commit,
      state: adminState1,
      ciphersuite: impl,
    });

    // Assign deterministic but varied timestamps and ids so MIP-03 has a clear winner.
    // Index 0 has the earliest created_at → index 0's commit wins.
    event.created_at = 1000 + i * 100;
    event.id = String(i).padStart(64, "0");

    results.push({ event, newState, index: i });
  }

  return results;
}

function makeMarmotGroup(
  state: ClientState,
  pubkey: string,
  impl: CiphersuiteImpl,
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
    network: makeNullNetwork(),
    snapshots: new InMemoryEpochSnapshotStore(),
  });
}

/** Find the MIP-03 winner among a set of events. */
function mip03Winner(events: NostrEvent[]): NostrEvent {
  return events.reduce((best, candidate) => {
    return isBetterCandidate(
      { id: candidate.id, created_at: candidate.created_at },
      { eventId: best.id, createdAt: best.created_at },
    )
      ? candidate
      : best;
  });
}

describe("AC-PROP-1: convergence property — random delivery order", () => {
  it(
    "all delivery permutations of K commits converge to the MIP-03 minimum winner",
    { timeout: 30000 },
    async () => {
      const impl = await getCiphersuiteImpl(CIPHERSUITE, defaultCryptoProvider);
      const { adminState1, observerState1, observerPubkey } =
        await buildObserverGroup(impl);

      // K = 3 commits — enough to get non-trivial permutations without being too slow.
      const K = 3;
      const commits = await makeKCommits(adminState1, impl, K);
      const events = commits.map((c) => c.event);

      const expectedWinner = mip03Winner(events);
      // The winner is commit[0] (earliest created_at = 1000, id = "0".repeat(64)).
      expect(expectedWinner.id).toBe("0".repeat(64));

      // The winner's newState is what every member should converge to.
      const winnerNewState = commits.find(
        (c) => c.event.id === expectedWinner.id,
      )!.newState;

      await fc.assert(
        fc.asyncProperty(
          // Generate a random permutation of indices [0, K-1].
          fc.shuffledSubarray(
            Array.from({ length: K }, (_, i) => i),
            {
              minLength: K,
              maxLength: K,
            },
          ),
          async (permutation) => {
            const permutedEvents = permutation.map((i) => events[i]);

            // Create a fresh observer for each permutation.
            const observer = makeMarmotGroup(
              observerState1,
              observerPubkey,
              impl,
            );

            // Ingest all events in this permutation's order.
            for await (const _res of observer.ingest(permutedEvents)) {
              /* consume */
            }

            // All permutations must converge to the same winner.
            expect(observer.state.groupContext.epoch).toBe(
              winnerNewState.groupContext.epoch,
            );
            expect(observer.state.keySchedule.exporterSecret).toEqual(
              winnerNewState.keySchedule.exporterSecret,
            );
          },
        ),
        { numRuns: 20 },
      );
    },
  );
});
