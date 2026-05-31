import { describe, expect, it } from "vitest";
import fc from "fast-check";

// fast-check v4 removed `fc.hexaString`; build a hex-string arbitrary locally.
const hexString = (minLength: number, maxLength: number) =>
  fc
    .array(fc.constantFrom(..."0123456789abcdef".split("")), {
      minLength,
      maxLength,
    })
    .map((chars) => chars.join(""));
import { sha256 } from "@noble/hashes/sha2.js";
import {
  contentTypes,
  defaultCryptoProvider,
  getCiphersuiteImpl,
  wireformats,
} from "ts-mls";

import {
  deserializeApplicationData,
  isApplicationMessage,
  isBetterCandidate,
  isCommitMessage,
  isProposalMessage,
  isReplayOfApplied,
  serializeApplicationRumor,
  sortGroupCommits,
  decryptGroupMessageEvent,
  type GroupMessagePair,
} from "../group-message.js";
import { createCredential } from "../credential.js";
import { createSimpleGroup } from "../group.js";
import { generateKeyPackage } from "../key-package.js";

// ============================================================================
// Mutation-survivor closure for src/core/group-message.ts
//
// Buckets per base:property-based-testing AC-linkage:
//   - isBetterCandidate / sortGroupCommits ordering -> Bucket 1,
//     epic-concurrent-commit-fork-resolution:AC-ROLL-2
//   - isReplayOfApplied length guard -> Bucket 1,
//     epic-concurrent-commit-fork-resolution:AC-GUARD-1
//   - deserializeApplicationData round-trip + rejection -> Bucket 2 (no AC;
//     see spec-gap finding "group-message-rumor-serialization-roundtrip")
//   - is{Application,Commit,Proposal}Message discriminators -> Bucket 2 (no AC;
//     see spec-gap finding "group-message-wireformat-content-type-guards")
//   - decryptGroupMessageEvent 28-byte envelope minimum -> Bucket 2 (no AC;
//     see spec-gap finding "group-message-mip03-envelope-minimum-length")
// ============================================================================

// ----------------------------------------------------------------------------
// Bucket 2: application-rumor serialization is an inverse pair (Family B).
// User story: an application message a member serializes onto the wire is the
// exact same rumor every other member deserializes back — nothing is lost,
// reordered, or silently coerced in the round trip.
// (no AC; see BACKLOG finding group-message-rumor-serialization-roundtrip)
// ----------------------------------------------------------------------------
describe("application rumor serialization round-trip", () => {
  const rumorArb = fc.record({
    id: fc.string({ minLength: 1 }),
    pubkey: fc.string({ minLength: 1 }),
    // kind MUST include 0 — the validation guard checks `=== undefined`,
    // not falsiness, so kind:0 is a legitimate accepted value.
    kind: fc.integer({ min: 0, max: 65535 }),
    created_at: fc.integer({ min: 0 }),
    tags: fc.array(fc.array(fc.string())),
    content: fc.string(),
  });

  it("deserialize(serialize(rumor)) reproduces the rumor for arbitrary valid rumors", () => {
    fc.assert(
      fc.property(rumorArb, (rumor) => {
        const bytes = serializeApplicationRumor(rumor as never);
        const back = deserializeApplicationData(bytes);
        // JSON is the wire format; structural equality is the contract.
        expect(back).toEqual(JSON.parse(JSON.stringify(rumor)));
      }),
    );
  });

  it("accepts a rumor whose kind is 0 (kind:0 is not 'missing')", () => {
    const rumor = {
      id: "a".repeat(64),
      pubkey: "b".repeat(64),
      kind: 0,
      created_at: 1,
      tags: [] as string[][],
      content: "",
    };
    const back = deserializeApplicationData(
      serializeApplicationRumor(rumor as never),
    );
    expect(back.kind).toBe(0);
    expect(back.id).toBe(rumor.id);
  });

  it("rejects JSON null as not-an-object", () => {
    expect(() =>
      deserializeApplicationData(new TextEncoder().encode("null")),
    ).toThrow("not an object");
  });

  it("rejects a bare JSON number as not-an-object", () => {
    expect(() =>
      deserializeApplicationData(new TextEncoder().encode("42")),
    ).toThrow("not an object");
  });

  it("rejects a bare JSON string as not-an-object", () => {
    expect(() =>
      deserializeApplicationData(new TextEncoder().encode('"hello"')),
    ).toThrow("not an object");
  });

  it("rejects an object missing id", () => {
    const obj = JSON.stringify({ pubkey: "b".repeat(64), kind: 1 });
    expect(() =>
      deserializeApplicationData(new TextEncoder().encode(obj)),
    ).toThrow("missing required fields");
  });

  it("rejects an object missing pubkey", () => {
    const obj = JSON.stringify({ id: "a".repeat(64), kind: 1 });
    expect(() =>
      deserializeApplicationData(new TextEncoder().encode(obj)),
    ).toThrow("missing required fields");
  });

  it("rejects an object whose kind is omitted (undefined)", () => {
    const obj = JSON.stringify({ id: "a".repeat(64), pubkey: "b".repeat(64) });
    expect(() =>
      deserializeApplicationData(new TextEncoder().encode(obj)),
    ).toThrow("missing required fields");
  });
});

// ----------------------------------------------------------------------------
// Bucket 2: message-type discriminators (Family C output contract +
// mutual-exclusivity metamorphic property).
// User story: a decrypted group message is routed to exactly one handler —
// an application payload is never mistaken for a commit or proposal, and a
// non-private-message wireformat is none of the three.
// (no AC; see BACKLOG finding group-message-wireformat-content-type-guards)
// ----------------------------------------------------------------------------
describe("group message type discriminators", () => {
  function pairWith(
    wireformat: number,
    contentType: number | undefined,
  ): GroupMessagePair {
    return {
      event: {} as never,
      message: {
        wireformat,
        privateMessage: { contentType },
      },
    } as unknown as GroupMessagePair;
  }

  const privateContentTypes: Array<[string, number]> = [
    ["application", contentTypes.application],
    ["commit", contentTypes.commit],
    ["proposal", contentTypes.proposal],
  ];

  it("for a private message, exactly one of the three guards is true", () => {
    for (const [name, ct] of privateContentTypes) {
      const pair = pairWith(wireformats.mls_private_message, ct);
      const results = [
        isApplicationMessage(pair),
        isCommitMessage(pair),
        isProposalMessage(pair),
      ];
      expect(
        results.filter(Boolean).length,
        `exactly one guard true for ${name}`,
      ).toBe(1);
    }
  });

  it("each guard matches its own content type and rejects the other two", () => {
    expect(
      isApplicationMessage(
        pairWith(wireformats.mls_private_message, contentTypes.application),
      ),
    ).toBe(true);
    expect(
      isCommitMessage(
        pairWith(wireformats.mls_private_message, contentTypes.application),
      ),
    ).toBe(false);
    expect(
      isProposalMessage(
        pairWith(wireformats.mls_private_message, contentTypes.application),
      ),
    ).toBe(false);

    expect(
      isCommitMessage(
        pairWith(wireformats.mls_private_message, contentTypes.commit),
      ),
    ).toBe(true);
    expect(
      isProposalMessage(
        pairWith(wireformats.mls_private_message, contentTypes.proposal),
      ),
    ).toBe(true);
  });

  it("all three guards are false when the wireformat is not a private message, for every content type", () => {
    // Vary the content type as well as the wireformat: a public message
    // carrying a commit/proposal content type must STILL be rejected by every
    // guard. This is what makes the wireformat check load-bearing — without
    // it, a non-private message would be classified purely by content type.
    for (const [, ct] of privateContentTypes) {
      const pair = pairWith(wireformats.mls_public_message, ct);
      expect(isApplicationMessage(pair)).toBe(false);
      expect(isCommitMessage(pair)).toBe(false);
      expect(isProposalMessage(pair)).toBe(false);
    }
  });
});

// ----------------------------------------------------------------------------
// Bucket 1: MIP-03 commit ordering (Family B metamorphic — strict total order).
// epic-concurrent-commit-fork-resolution:AC-ROLL-2
// User story: when two commits race, every member deterministically picks the
// same winner — earliest created_at, then lexicographically smallest id — and
// a commit is never strictly "better than" itself.
// ----------------------------------------------------------------------------
describe("isBetterCandidate is a strict total order (AC-ROLL-2)", () => {
  const commitArb = fc.record({
    id: hexString(4, 16),
    created_at: fc.integer({ min: 0, max: 1000 }),
  });

  it("is irreflexive: an identical commit is never better than itself", () => {
    fc.assert(
      fc.property(commitArb, (c) => {
        expect(
          isBetterCandidate(
            { id: c.id, created_at: c.created_at },
            { eventId: c.id, createdAt: c.created_at },
          ),
        ).toBe(false);
      }),
    );
  });

  it("is asymmetric and total for distinct commits: exactly one direction wins", () => {
    fc.assert(
      fc.property(commitArb, commitArb, (a, b) => {
        fc.pre(a.id !== b.id || a.created_at !== b.created_at);
        const aBetter = isBetterCandidate(
          { id: a.id, created_at: a.created_at },
          { eventId: b.id, createdAt: b.created_at },
        );
        const bBetter = isBetterCandidate(
          { id: b.id, created_at: b.created_at },
          { eventId: a.id, createdAt: a.created_at },
        );
        // Distinct commits: precisely one is the winner.
        expect(aBetter !== bBetter).toBe(true);
      }),
    );
  });

  it("on a created_at tie the smaller id wins (id tiebreak is reachable)", () => {
    // Forces the equal-created_at-distinct-id branch that random pairs
    // under-sample; this is what discriminates `!==` from `<=` on the
    // created_at comparison.
    fc.assert(
      fc.property(
        hexString(4, 16),
        hexString(4, 16),
        fc.integer({ min: 0, max: 1000 }),
        (idA, idB, ts) => {
          fc.pre(idA !== idB);
          const aBetter = isBetterCandidate(
            { id: idA, created_at: ts },
            { eventId: idB, createdAt: ts },
          );
          // On an exact created_at tie, the winner is strictly the smaller id.
          expect(aBetter).toBe(idA < idB);
        },
      ),
    );
  });
});

// ----------------------------------------------------------------------------
// Bucket 1: sortGroupCommits realizes the MIP-03 ordering (Family C contract).
// epic-concurrent-commit-fork-resolution:AC-ROLL-2
// ----------------------------------------------------------------------------
describe("sortGroupCommits orders by MIP-03 key (AC-ROLL-2)", () => {
  function pair(id: string, created_at: number): GroupMessagePair {
    return {
      event: { id, created_at },
      message: {},
    } as unknown as GroupMessagePair;
  }

  const key = (p: GroupMessagePair) =>
    `${String(p.event.created_at).padStart(12, "0")}|${p.event.id}`;

  it("returns a non-decreasing permutation under the (created_at,id) key", () => {
    const commitsArb = fc.array(
      fc.record({
        id: hexString(4, 12),
        created_at: fc.integer({ min: 0, max: 50 }),
      }),
      { minLength: 0, maxLength: 8 },
    );
    fc.assert(
      fc.property(commitsArb, (raw) => {
        const input = raw.map((r) => pair(r.id, r.created_at));
        const sorted = sortGroupCommits([...input]);
        // Permutation: same multiset of keys.
        const keysIn = input.map(key).sort();
        const keysOut = sorted.map(key).sort();
        expect(keysOut).toEqual(keysIn);
        // Non-decreasing under the MIP-03 key.
        for (let i = 1; i < sorted.length; i++) {
          expect(key(sorted[i - 1]) <= key(sorted[i])).toBe(true);
        }
      }),
    );
  });

  it("reorders an explicitly out-of-order input (exercises the swap branch)", () => {
    // created_at descending on input -> must come back ascending.
    const input = [pair("ff", 3), pair("aa", 1), pair("bb", 2)];
    const sorted = sortGroupCommits([...input]);
    expect(sorted.map((p) => p.event.created_at)).toEqual([1, 2, 3]);
  });

  it("breaks created_at ties by lexicographically smallest id", () => {
    const input = [pair("cc", 5), pair("aa", 5), pair("bb", 5)];
    const sorted = sortGroupCommits([...input]);
    expect(sorted.map((p) => p.event.id)).toEqual(["aa", "bb", "cc"]);
  });
});

// ----------------------------------------------------------------------------
// Bucket 1: replay guard never spuriously matches across hash lengths.
// epic-concurrent-commit-fork-resolution:AC-GUARD-1
// User story: a commit is only treated as a self-echo replay when its id or
// its full content hash matches; a stored hash of a different length is never
// a false-positive replay (which would suppress a legitimate rollback).
// ----------------------------------------------------------------------------
describe("isReplayOfApplied length guard (AC-GUARD-1)", () => {
  it("returns false when the applied contentHash has a different length than sha256", () => {
    const candidate = {
      id: "b".repeat(64),
      contentHash: sha256(new TextEncoder().encode("content-A")),
    };
    // candidate hash is 32 bytes; a 16-byte applied hash forces the
    // length-mismatch branch, which must short-circuit to "not a replay".
    const shorterHash = new Uint8Array(16);
    expect(
      isReplayOfApplied(candidate, {
        eventId: "a".repeat(64),
        contentHash: shorterHash,
      }),
    ).toBe(false);

    // And a longer (33-byte) applied hash likewise cannot be a replay.
    const longerHash = new Uint8Array(33);
    expect(
      isReplayOfApplied(candidate, {
        eventId: "a".repeat(64),
        contentHash: longerHash,
      }),
    ).toBe(false);
  });

  it("still detects a genuine same-length content-hash replay", () => {
    const contentHash = sha256(new TextEncoder().encode("content-A"));
    const candidate = { id: "b".repeat(64), contentHash };
    expect(
      isReplayOfApplied(candidate, { eventId: "a".repeat(64), contentHash }),
    ).toBe(true);
  });
});

// ----------------------------------------------------------------------------
// Bucket 2: MIP-03 envelope minimum length (example test for an async crypto
// path). User story: a group-event payload too short to even hold the
// 12-byte nonce + 16-byte AEAD tag is rejected, not fed to the cipher.
// (no AC; see BACKLOG finding group-message-mip03-envelope-minimum-length)
// ----------------------------------------------------------------------------
describe("decryptGroupMessageEvent envelope minimum length", () => {
  async function createTestState(pubkey: string) {
    const ciphersuite = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const credential = createCredential(pubkey);
    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl: ciphersuite,
    });
    const { clientState } = await createSimpleGroup(
      keyPackage,
      ciphersuite,
      "Test Group",
      { adminPubkeys: [pubkey], relays: [] },
    );
    return { clientState, ciphersuite };
  }

  it("rejects a 27-byte payload (one byte under the 12+16 minimum)", async () => {
    const { clientState, ciphersuite } = await createTestState("a".repeat(64));
    const payload = new Uint8Array(27);
    const content = btoa(String.fromCharCode(...payload));
    const event = {
      id: "e".repeat(64),
      kind: 445,
      pubkey: "f".repeat(64),
      created_at: Math.floor(Date.now() / 1000),
      tags: [["h", "00".repeat(32)]],
      content,
      sig: "1".repeat(128),
    };
    await expect(
      decryptGroupMessageEvent(event, clientState, ciphersuite),
    ).rejects.toThrow("Failed to decrypt group message");
  });
});
