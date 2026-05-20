import { NostrEvent, unixNow } from "applesauce-core/helpers";
import { bytesToHex } from "@noble/ciphers/utils.js";
import {
  defaultCryptoProvider,
  encode,
  getCiphersuiteImpl,
  greaseValues,
  keyPackageEncoder,
  makeCustomExtension,
} from "ts-mls";
import { describe, expect, it } from "vitest";

import { createCredential } from "../credential.js";
import { generateKeyPackage } from "../key-package.js";
import {
  createDeleteKeyPackageEvent,
  createKeyPackageEvent,
  generateKeyPackageSlot,
  getKeyPackage,
  getKeyPackageIdentifier,
  keyPackageFilters,
  selectBestKeyPackage,
  softValidateKeyPackageEvent,
  validateKeyPackageEvent,
} from "../key-package-event.js";
import {
  ADDRESSABLE_KEY_PACKAGE_KIND,
  KEY_PACKAGE_KIND,
  LAST_RESORT_EXTENSION_TYPE,
} from "../protocol.js";

const mockPubkey =
  "02a1633cafe37eeebe2b39b4ec5f3d74c35e61fa7e7e6b7b8c5f7c4f3b2a1b2c3d";
const mockSig = "304502210...";
const mockD =
  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

describe("createDeleteKeyPackageEvent", () => {
  it("should create a valid kind 5 delete event with string event IDs", () => {
    const eventIds = ["abc123def456", "789ghi012jkl", "345mno678pqr"];

    const deleteEvent = createDeleteKeyPackageEvent({
      events: eventIds,
    });

    expect(deleteEvent.kind).toBe(5);
    expect(deleteEvent.content).toBe("");
    expect(deleteEvent.created_at).toBeGreaterThan(0);

    // Both k tags included when only string ids are provided (no kind info)
    const kTags = deleteEvent.tags.filter((t) => t[0] === "k");
    expect(kTags).toContainEqual(["k", "443"]);
    expect(kTags).toContainEqual(["k", "30443"]);

    // Check for e tags
    const eTags = deleteEvent.tags.filter((t) => t[0] === "e");
    expect(eTags).toHaveLength(3);
    expect(eTags).toEqual([
      ["e", "abc123def456"],
      ["e", "789ghi012jkl"],
      ["e", "345mno678pqr"],
    ]);
  });

  it("should create a valid kind 5 delete event with full kind 443 NostrEvent objects", () => {
    const keyPackageEvents: NostrEvent[] = [
      {
        kind: KEY_PACKAGE_KIND,
        id: "event1id",
        pubkey: mockPubkey,
        created_at: 1693876543,
        tags: [],
        content: "aabbccdd",
        sig: mockSig,
      },
      {
        kind: KEY_PACKAGE_KIND,
        id: "event2id",
        pubkey: mockPubkey,
        created_at: 1693876544,
        tags: [],
        content: "eeffgghh",
        sig: mockSig,
      },
    ];

    const deleteEvent = createDeleteKeyPackageEvent({
      events: keyPackageEvents,
    });

    expect(deleteEvent.kind).toBe(5);

    // Only kind 443 k tag (no 30443 events in input)
    const kTags = deleteEvent.tags.filter((t) => t[0] === "k");
    expect(kTags).toEqual([["k", "443"]]);

    // Check for e tags only (no a tags for kind 443)
    const eTags = deleteEvent.tags.filter((t) => t[0] === "e");
    expect(eTags).toHaveLength(2);
    expect(eTags).toEqual([
      ["e", "event1id"],
      ["e", "event2id"],
    ]);

    // No a tags for kind 443
    expect(deleteEvent.tags.filter((t) => t[0] === "a")).toHaveLength(0);
  });

  it("should create a valid kind 5 delete event with kind 30443 events, including a tags", () => {
    const addressableEvent: NostrEvent = {
      kind: ADDRESSABLE_KEY_PACKAGE_KIND,
      id: "addrEvent1",
      pubkey: mockPubkey,
      created_at: 1693876543,
      tags: [["d", mockD]],
      content: "aabbccdd",
      sig: mockSig,
    };

    const deleteEvent = createDeleteKeyPackageEvent({
      events: [addressableEvent],
    });

    expect(deleteEvent.kind).toBe(5);

    // Only kind 30443 k tag
    const kTags = deleteEvent.tags.filter((t) => t[0] === "k");
    expect(kTags).toEqual([["k", "30443"]]);

    // e tag present
    const eTags = deleteEvent.tags.filter((t) => t[0] === "e");
    expect(eTags).toEqual([["e", "addrEvent1"]]);

    // a tag present with correct coordinate
    const aTags = deleteEvent.tags.filter((t) => t[0] === "a");
    expect(aTags).toHaveLength(1);
    expect(aTags[0]).toEqual([
      "a",
      `${ADDRESSABLE_KEY_PACKAGE_KIND}:${mockPubkey}:${mockD}`,
    ]);
  });

  it("should handle mixed kind 443 and kind 30443 events", () => {
    const legacyEvent: NostrEvent = {
      kind: KEY_PACKAGE_KIND,
      id: "legacyId",
      pubkey: mockPubkey,
      created_at: 1693876543,
      tags: [],
      content: "aabbccdd",
      sig: mockSig,
    };
    const addressableEvent: NostrEvent = {
      kind: ADDRESSABLE_KEY_PACKAGE_KIND,
      id: "addrId",
      pubkey: mockPubkey,
      created_at: 1693876544,
      tags: [["d", mockD]],
      content: "eeffgghh",
      sig: mockSig,
    };

    const deleteEvent = createDeleteKeyPackageEvent({
      events: [legacyEvent, addressableEvent],
    });

    // Both k tags present
    const kTags = deleteEvent.tags.filter((t) => t[0] === "k");
    expect(kTags).toContainEqual(["k", "443"]);
    expect(kTags).toContainEqual(["k", "30443"]);

    // Both e tags present
    const eTags = deleteEvent.tags.filter((t) => t[0] === "e");
    expect(eTags).toContainEqual(["e", "legacyId"]);
    expect(eTags).toContainEqual(["e", "addrId"]);

    // a tag only for the addressable event
    const aTags = deleteEvent.tags.filter((t) => t[0] === "a");
    expect(aTags).toHaveLength(1);
    expect(aTags[0][1]).toBe(
      `${ADDRESSABLE_KEY_PACKAGE_KIND}:${mockPubkey}:${mockD}`,
    );
  });

  it("should throw an error when no events are provided", () => {
    expect(() => {
      createDeleteKeyPackageEvent({
        events: [],
      });
    }).toThrow("At least one event must be provided for deletion");
  });

  it("should throw an error when a full event is not kind 443 or 30443", () => {
    const wrongKindEvent: NostrEvent = {
      kind: 1,
      id: "wrongeventid",
      pubkey: mockPubkey,
      created_at: 1693876543,
      tags: [],
      content: "Hello world",
      sig: mockSig,
    };

    expect(() => {
      createDeleteKeyPackageEvent({
        events: [wrongKindEvent],
      });
    }).toThrow(
      `Event wrongeventid is not a key package event (kind 1 instead of ${KEY_PACKAGE_KIND} or ${ADDRESSABLE_KEY_PACKAGE_KIND})`,
    );
  });

  it("should handle mixed event IDs and full events", () => {
    const keyPackageEvent: NostrEvent = {
      kind: KEY_PACKAGE_KIND,
      id: "fulleventid",
      pubkey: mockPubkey,
      created_at: 1693876543,
      tags: [],
      content: "aabbccdd",
      sig: mockSig,
    };

    const deleteEvent = createDeleteKeyPackageEvent({
      events: ["stringeventid1", keyPackageEvent, "stringeventid2"],
    });

    expect(deleteEvent.kind).toBe(5);

    const eTags = deleteEvent.tags.filter((t) => t[0] === "e");
    expect(eTags).toHaveLength(3);
    expect(eTags).toEqual([
      ["e", "stringeventid1"],
      ["e", "fulleventid"],
      ["e", "stringeventid2"],
    ]);
  });

  it("should omit a tag for kind 30443 event with no d tag", () => {
    const addrEventNoD: NostrEvent = {
      kind: ADDRESSABLE_KEY_PACKAGE_KIND,
      id: "noDEvent",
      pubkey: mockPubkey,
      created_at: 1693876543,
      tags: [], // no d tag
      content: "aabbccdd",
      sig: mockSig,
    };

    const deleteEvent = createDeleteKeyPackageEvent({
      events: [addrEventNoD],
    });

    // e tag present
    expect(deleteEvent.tags.filter((t) => t[0] === "e")).toHaveLength(1);
    // No a tag since d is missing
    expect(deleteEvent.tags.filter((t) => t[0] === "a")).toHaveLength(0);
  });
});

describe("createKeyPackageEvent", () => {
  const validPubkey =
    "884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6";
  const testD =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

  it("should create a kind 30443 event (addressable)", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });

    const event = await createKeyPackageEvent({
      keyPackage: keyPackage.publicPackage,
      identifier: testD,
      relays: ["wss://relay.example.com"],
    });

    expect(event.kind).toBe(ADDRESSABLE_KEY_PACKAGE_KIND);
  });

  it("should include d tag with the provided slot identifier", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });

    const event = await createKeyPackageEvent({
      keyPackage: keyPackage.publicPackage,
      identifier: testD,
    });

    const dTag = event.tags.find((t) => t[0] === "d");
    expect(dTag).toEqual(["d", testD]);
  });

  it("should create event with base64 encoding and encoding tag", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );

    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });

    const event = await createKeyPackageEvent({
      keyPackage: keyPackage.publicPackage,
      identifier: testD,
      relays: ["wss://relay.example.com"],
    });

    // NIP-70 protected tag should be opt-in
    expect(event.tags.some((t) => t[0] === "-")).toBe(false);

    // Should have encoding tag
    const encodingTag = event.tags.find((t) => t[0] === "encoding");
    expect(encodingTag).toEqual(["encoding", "base64"]);

    // Content should be base64
    const hasBase64Chars =
      /[+/=]/.test(event.content) ||
      event.content.length % 2 !== 0 ||
      /[g-zG-Z]/.test(event.content);
    expect(hasBase64Chars).toBe(true);
  });

  it("should include NIP-70 protected tag when enabled", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );

    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });

    const event = await createKeyPackageEvent({
      keyPackage: keyPackage.publicPackage,
      identifier: testD,
      protected: true,
    });

    expect(event.tags.some((t) => t[0] === "-")).toBe(true);
  });

  it("should filter GREASE extensions from advertised extension tags", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );

    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
      extensions: [
        makeCustomExtension({
          extensionType: greaseValues[0],
          extensionData: new Uint8Array([1]),
        }),
      ],
    });

    const event = await createKeyPackageEvent({
      keyPackage: keyPackage.publicPackage,
      identifier: testD,
    });

    const extensionsTag = event.tags.find((tag) => tag[0] === "mls_extensions");
    expect(extensionsTag).toBeDefined();
    expect(extensionsTag).not.toContain(
      `0x${greaseValues[0].toString(16).padStart(4, "0")}`,
    );
  });

  it("should be able to decode base64-encoded key package event", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );

    const originalKeyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });

    const event = await createKeyPackageEvent({
      keyPackage: originalKeyPackage.publicPackage,
      identifier: testD,
      relays: ["wss://relay.example.com"],
    });

    // Mock the event as if it came from a relay
    const mockEvent: NostrEvent = {
      ...event,
      pubkey: "test-pubkey",
      id: "test-event-id",
      sig: "test-signature",
    };

    // Should be able to decode it
    const decodedKeyPackage = getKeyPackage(mockEvent);
    expect(decodedKeyPackage).toBeDefined();
    expect(decodedKeyPackage.leafNode.credential).toEqual(credential);
  });

  it("should still reject legacy hex-encoded events without encoding tag", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );

    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });

    // Create a legacy event (hex-encoded, no encoding tag)
    const encodedBytes = encode(keyPackageEncoder, keyPackage.publicPackage);
    const legacyEvent: NostrEvent = {
      kind: KEY_PACKAGE_KIND,
      pubkey: validPubkey,
      created_at: unixNow(),
      content: bytesToHex(encodedBytes),
      tags: [
        ["mls_protocol_version", "1.0"],
        ["mls_ciphersuite", "0x0001"],
        ["mls_extensions", "0x000a"],
        ["relays", "wss://relay.example.com"],
      ],
      id: "legacy-event-id",
      sig: "legacy-signature",
    };

    expect(() => getKeyPackage(legacyEvent)).toThrow(/encoding=base64 tag/i);
  });

  it("should reject hex-encoded events with explicit hex encoding tag", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );

    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });

    const encodedBytes = encode(keyPackageEncoder, keyPackage.publicPackage);
    const hexEvent: NostrEvent = {
      kind: KEY_PACKAGE_KIND,
      pubkey: validPubkey,
      created_at: unixNow(),
      content: bytesToHex(encodedBytes),
      tags: [
        ["mls_protocol_version", "1.0"],
        ["mls_ciphersuite", "0x0001"],
        ["mls_extensions", "0x000a"],
        ["relays", "wss://relay.example.com"],
        ["encoding", "hex"],
      ],
      id: "hex-event-id",
      sig: "hex-signature",
    };

    expect(() => getKeyPackage(hexEvent)).toThrow(/encoding=base64 tag/i);
  });
});

describe("generateKeyPackageSlot", () => {
  it("produces a 64-char lowercase hex string", () => {
    const slot = generateKeyPackageSlot();
    expect(slot).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces unique values across repeated calls", () => {
    const slots = new Set(Array.from({ length: 100 }, () => generateKeyPackageSlot()));
    expect(slots.size).toBe(100);
  });
});

describe("createKeyPackageEvent — MIP-00 slot validation", () => {
  const validPubkey =
    "884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6";

  async function makeKeyPackage() {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    return generateKeyPackage({ credential, ciphersuiteImpl });
  }

  it("emits mls_proposals tag with value 0x000a on kind 30443", async () => {
    const kp = await makeKeyPackage();
    const event = await createKeyPackageEvent({
      keyPackage: kp.publicPackage,
      identifier: generateKeyPackageSlot(),
    });
    const tag = event.tags.find((t) => t[0] === "mls_proposals");
    expect(tag).toEqual(["mls_proposals", "0x000a"]);
  });

  it("throws on non-64-hex identifier (free-form string)", async () => {
    const kp = await makeKeyPackage();
    await expect(
      createKeyPackageEvent({
        keyPackage: kp.publicPackage,
        identifier: "notestr-079251af-1234-5678-abcd-ef0123456789",
      }),
    ).rejects.toThrow(/generateKeyPackageSlot/);
  });

  it("throws on uppercase hex identifier", async () => {
    const kp = await makeKeyPackage();
    await expect(
      createKeyPackageEvent({
        keyPackage: kp.publicPackage,
        identifier: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
      }),
    ).rejects.toThrow(/generateKeyPackageSlot/);
  });

  it("throws on empty identifier with message naming generateKeyPackageSlot", async () => {
    const kp = await makeKeyPackage();
    await expect(
      createKeyPackageEvent({
        keyPackage: kp.publicPackage,
        identifier: "",
      }),
    ).rejects.toThrow(/generateKeyPackageSlot/);
  });
});

describe("getKeyPackageIdentifier", () => {
  it("should return the d tag value for a kind 30443 event", () => {
    const event: NostrEvent = {
      kind: ADDRESSABLE_KEY_PACKAGE_KIND,
      id: "testid",
      pubkey: mockPubkey,
      created_at: 0,
      content: "",
      tags: [["d", mockD]],
      sig: mockSig,
    };
    expect(getKeyPackageIdentifier(event)).toBe(mockD);
  });

  it("should return undefined for a kind 443 event (no d tag)", () => {
    const event: NostrEvent = {
      kind: KEY_PACKAGE_KIND,
      id: "testid",
      pubkey: mockPubkey,
      created_at: 0,
      content: "",
      tags: [],
      sig: mockSig,
    };
    expect(getKeyPackageIdentifier(event)).toBeUndefined();
  });

  it("should return undefined when event has no d tag at all", () => {
    const event: NostrEvent = {
      kind: ADDRESSABLE_KEY_PACKAGE_KIND,
      id: "testid",
      pubkey: mockPubkey,
      created_at: 0,
      content: "",
      tags: [["i", "somehex"]],
      sig: mockSig,
    };
    expect(getKeyPackageIdentifier(event)).toBeUndefined();
  });
});

describe("spec compliance (MIP-00)", () => {
  const validPubkey =
    "884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6";
  const testD =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

  it("should include an `i` tag with hex KeyPackageRef when publishing kind 30443", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );

    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });

    const event = await createKeyPackageEvent({
      keyPackage: keyPackage.publicPackage,
      identifier: testD,
    });

    const iTag = event.tags.find((t) => t[0] === "i");
    expect(iTag).toBeDefined();
    expect(iTag?.[1]).toMatch(/^[0-9a-f]+$/);
  });

  it("should reject decoding kind 443 events that are missing an encoding=base64 tag", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );

    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });

    const encodedBytes = encode(keyPackageEncoder, keyPackage.publicPackage);
    const missingEncodingEvent: NostrEvent = {
      kind: KEY_PACKAGE_KIND,
      pubkey: validPubkey,
      created_at: unixNow(),
      content: bytesToHex(encodedBytes),
      tags: [
        ["mls_protocol_version", "1.0"],
        ["mls_ciphersuite", "0x0001"],
        ["mls_extensions", "0x000a"],
      ],
      id: "missing-encoding-id",
      sig: "missing-encoding-sig",
    };

    expect(() => getKeyPackage(missingEncodingEvent)).toThrow(
      /encoding=base64 tag/i,
    );
  });

  it("should reject decoding kind 443 events with encoding=hex", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );

    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });

    const encodedBytes = encode(keyPackageEncoder, keyPackage.publicPackage);
    const hexEncodingEvent: NostrEvent = {
      kind: KEY_PACKAGE_KIND,
      pubkey: validPubkey,
      created_at: unixNow(),
      content: bytesToHex(encodedBytes),
      tags: [
        ["mls_protocol_version", "1.0"],
        ["mls_ciphersuite", "0x0001"],
        ["mls_extensions", "0x000a"],
        ["encoding", "hex"],
      ],
      id: "hex-encoding-id",
      sig: "hex-encoding-sig",
    };

    expect(() => getKeyPackage(hexEncodingEvent)).toThrow(
      /encoding=base64 tag/i,
    );
  });
});

describe("selectBestKeyPackage", () => {
  const validPubkey =
    "884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6";

  async function makeValidEvent(
    overrides: Partial<NostrEvent> & { lastResort?: boolean } = {},
  ): Promise<NostrEvent> {
    const { lastResort = false, ...eventOverrides } = overrides;
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
      isLastResort: lastResort,
    });
    const template = await createKeyPackageEvent({
      keyPackage: keyPackage.publicPackage,
      identifier: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    });
    return {
      ...template,
      pubkey: validPubkey,
      id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      sig: "sig",
      ...eventOverrides,
    };
  }

  it("returns null for an empty array", async () => {
    expect(selectBestKeyPackage([])).toBeNull();
  });

  it("returns null when all candidates have wrong kind", async () => {
    const wrongKind: NostrEvent = {
      kind: 1,
      id: "aaa",
      pubkey: validPubkey,
      created_at: 1000,
      tags: [],
      content: "",
      sig: "sig",
    };
    expect(selectBestKeyPackage([wrongKind])).toBeNull();
  });

  it("returns null when all candidates fail decoding", async () => {
    const badContent: NostrEvent = {
      kind: ADDRESSABLE_KEY_PACKAGE_KIND,
      id: "aaa",
      pubkey: validPubkey,
      created_at: 1000,
      tags: [["encoding", "base64"]],
      content: "bm90YXZhbGlka2V5cGFja2FnZQ==",
      sig: "sig",
    };
    expect(selectBestKeyPackage([badContent])).toBeNull();
  });

  it("selects a non-last_resort candidate over a last_resort candidate", async () => {
    const normal = await makeValidEvent({
      id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      created_at: 1000,
    });
    const lastResort = await makeValidEvent({
      lastResort: true,
      id: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      created_at: 2000,
    });

    const result = selectBestKeyPackage([lastResort, normal]);
    expect(result?.id).toBe(normal.id);
  });

  it("selects the newest created_at among same-priority candidates", async () => {
    const older = await makeValidEvent({
      id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      created_at: 1000,
    });
    const newer = await makeValidEvent({
      id: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      created_at: 2000,
    });

    const result = selectBestKeyPackage([older, newer]);
    expect(result?.id).toBe(newer.id);
  });

  it("tie-breaks by lexicographically smallest id when created_at is equal", async () => {
    const eventA = await makeValidEvent({
      id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      created_at: 1000,
    });
    const eventB = await makeValidEvent({
      id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      created_at: 1000,
    });

    const result = selectBestKeyPackage([eventB, eventA]);
    expect(result?.id).toBe(eventA.id);
  });

  it("handles mixed kind 443 and kind 30443 candidates", async () => {
    const kind443 = await makeValidEvent({
      kind: KEY_PACKAGE_KIND,
      id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      created_at: 1000,
    });
    const kind30443 = await makeValidEvent({
      id: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      created_at: 2000,
    });

    const result = selectBestKeyPackage([kind443, kind30443]);
    expect(result?.id).toBe(kind30443.id);
  });

  it("skips candidates that fail getKeyPackage() decoding and selects from the rest", async () => {
    const invalid: NostrEvent = {
      kind: ADDRESSABLE_KEY_PACKAGE_KIND,
      id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      pubkey: validPubkey,
      created_at: 9999,
      tags: [["encoding", "base64"]],
      content: "bm90YXZhbGlka2V5cGFja2FnZQ==",
      sig: "sig",
    };
    const valid = await makeValidEvent({
      id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      created_at: 1000,
    });

    const result = selectBestKeyPackage([invalid, valid]);
    expect(result?.id).toBe(valid.id);
  });
});

describe("keyPackageFilters", () => {
  const author1 =
    "884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6";
  const author2 =
    "02a1633cafe37eeebe2b39b4ec5f3d74c35e61fa7e7e6b7b8c5f7c4f3b2a1b2c3d";

  it("returns exactly two filters", () => {
    const filters = keyPackageFilters([author1]);
    expect(filters).toHaveLength(2);
  });

  it("first filter targets kind 443", () => {
    const [legacyFilter] = keyPackageFilters([author1]);
    expect(legacyFilter.kinds).toEqual([KEY_PACKAGE_KIND]);
  });

  it("second filter targets kind 30443", () => {
    const [, addressableFilter] = keyPackageFilters([author1]);
    expect(addressableFilter.kinds).toEqual([ADDRESSABLE_KEY_PACKAGE_KIND]);
  });

  it("both filters include the provided author", () => {
    const filters = keyPackageFilters([author1]);
    for (const filter of filters) {
      expect(filter.authors).toContain(author1);
    }
  });

  it("works with multiple authors — both filters carry all authors", () => {
    const filters = keyPackageFilters([author1, author2]);
    for (const filter of filters) {
      expect(filter.authors).toContain(author1);
      expect(filter.authors).toContain(author2);
    }
  });
});

describe("validateKeyPackageEvent", () => {
  const validPubkey =
    "884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6";
  const testD =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

  async function makeValidSignedEvent(): Promise<NostrEvent> {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });
    const template = await createKeyPackageEvent({
      keyPackage: keyPackage.publicPackage,
      identifier: testD,
      relays: ["wss://relay.example.com"],
    });
    return {
      ...template,
      pubkey: validPubkey,
      id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      sig: "sig",
    };
  }

  it("should accept a valid kind 30443 event", async () => {
    const event = await makeValidSignedEvent();
    const kp = await validateKeyPackageEvent(event);
    expect(kp).toBeDefined();
  });

  it("should reject wrong event kind", async () => {
    const event = await makeValidSignedEvent();
    event.kind = 1;
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Expected key package event/,
    );
  });

  it("should reject kind 30443 with missing d tag", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.filter((t) => t[0] !== "d");
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Missing required d tag/,
    );
  });

  it("should reject kind 30443 with empty d tag", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) => (t[0] === "d" ? ["d", ""] : t));
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /d tag value must not be empty/,
    );
  });

  it("should reject missing mls_protocol_version tag", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.filter((t) => t[0] !== "mls_protocol_version");
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Missing required tag: mls_protocol_version/,
    );
  });

  it("should reject unsupported protocol version", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "mls_protocol_version" ? ["mls_protocol_version", "2.0"] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Unsupported protocol version: 2.0/,
    );
  });

  it("should reject missing mls_ciphersuite tag", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.filter((t) => t[0] !== "mls_ciphersuite");
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Missing required tag: mls_ciphersuite/,
    );
  });

  it("should reject invalid ciphersuite format", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "mls_ciphersuite" ? ["mls_ciphersuite", "0001"] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Ciphersuite value must be 0x followed by 4 hex digits/,
    );
  });

  it("should reject unsupported ciphersuite value", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "mls_ciphersuite" ? ["mls_ciphersuite", "0x0002"] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Unsupported ciphersuite: 0x0002/,
    );
  });

  it("should reject missing mls_extensions tag", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.filter((t) => t[0] !== "mls_extensions");
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Missing required tag: mls_extensions/,
    );
  });

  it("should reject extensions with invalid hex format", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "mls_extensions" ? ["mls_extensions", "invalid"] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Extension value must be 0x followed by 4 hex digits/,
    );
  });

  it("should reject missing required extension (MarmotGroupData 0xf2ee)", async () => {
    const event = await makeValidSignedEvent();
    // Keep only LastResort, remove MarmotGroupData
    event.tags = event.tags.map((t) =>
      t[0] === "mls_extensions" ? ["mls_extensions", "0x000a"] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Missing required extension: 0xf2ee \(MarmotGroupData\)/,
    );
  });

  it("should reject missing relays tag", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.filter((t) => t[0] !== "relays");
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Missing required tag: relays/,
    );
  });

  it("should reject relays tag with no URLs", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "relays" ? ["relays"] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Relays tag must have at least one relay URL/,
    );
  });

  it("should reject invalid relay URL", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "relays" ? ["relays", "not-a-url"] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Invalid relay URL/,
    );
  });

  it("should reject missing i tag", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.filter((t) => t[0] !== "i");
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Missing required tag: i/,
    );
  });

  it("should reject non-hex i tag value", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "i" ? ["i", "not-hex!"] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /i tag must contain valid hex-encoded data/,
    );
  });

  it("should reject credential identity mismatch with event pubkey", async () => {
    const event = await makeValidSignedEvent();
    // Change pubkey to a different one
    event.pubkey =
      "0000000000000000000000000000000000000000000000000000000000000001";
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /does not match event pubkey/,
    );
  });

  it("should reject fabricated i tag that doesn't match content", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "i" ? ["i", "deadbeef".repeat(4)] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /KeyPackageRef in i tag does not match computed value/,
    );
  });

  it("should reject kind 30443 with non-64-hex d tag value", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "d" ? ["d", "notestr-079251af-short"] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /d tag must be exactly 64 lowercase hex characters/,
    );
  });

  it("should reject kind 30443 with missing mls_proposals tag", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.filter((t) => t[0] !== "mls_proposals");
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Missing required tag: mls_proposals/,
    );
  });

  it("should reject kind 30443 with wrong mls_proposals value", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "mls_proposals" ? ["mls_proposals", "0x000b"] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Invalid mls_proposals tag value/,
    );
  });

  it("should reject kind 30443 with extra mls_proposals entries", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "mls_proposals" ? ["mls_proposals", "0x000a", "0x0001"] : t,
    );
    await expect(validateKeyPackageEvent(event)).rejects.toThrow(
      /Invalid mls_proposals tag value/,
    );
  });

  it("round-trip: createKeyPackageEvent output passes validateKeyPackageEvent with zero violations", async () => {
    const event = await makeValidSignedEvent();
    const kp = await validateKeyPackageEvent(event);
    expect(kp).toBeDefined();
  });

  it("should accept legacy kind 443 event (no d tag required)", async () => {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });
    // Build a kind 443 event with all required tags
    const template = await createKeyPackageEvent({
      keyPackage: keyPackage.publicPackage,
      identifier: testD,
      relays: ["wss://relay.example.com"],
    });
    const event: NostrEvent = {
      ...template,
      kind: KEY_PACKAGE_KIND,
      pubkey: validPubkey,
      id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      sig: "sig",
    };
    const kp = await validateKeyPackageEvent(event);
    expect(kp).toBeDefined();
  });
});

describe("softValidateKeyPackageEvent", () => {
  const validPubkey =
    "884704bd421671e01c13f854d2ce23ce2a5bfe9562f4f297ad2bc921ba30c3a6";
  const testD =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

  async function makeValidSignedEvent(): Promise<NostrEvent> {
    const credential = createCredential(validPubkey);
    const ciphersuiteImpl = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );
    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl,
    });
    const template = await createKeyPackageEvent({
      keyPackage: keyPackage.publicPackage,
      identifier: testD,
      relays: ["wss://relay.example.com"],
    });
    return {
      ...template,
      pubkey: validPubkey,
      id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      sig: "sig",
    };
  }

  it("should return no violations for a valid event", async () => {
    const event = await makeValidSignedEvent();
    const result = await softValidateKeyPackageEvent(event);
    expect(result.keyPackage).toBeDefined();
    expect(result.violations).toHaveLength(0);
  });

  it("should return warning-level violations for missing tags without throwing", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.filter((t) => t[0] !== "relays");
    const result = await softValidateKeyPackageEvent(event);
    expect(result.keyPackage).toBeDefined();
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].severity).toBe("warning");
    expect(result.violations[0].check).toBe("relays_presence");
  });

  it("should collect multiple warnings at once", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.filter(
      (t) => t[0] !== "relays" && t[0] !== "mls_protocol_version",
    );
    const result = await softValidateKeyPackageEvent(event);
    expect(result.keyPackage).toBeDefined();
    expect(result.violations.length).toBeGreaterThanOrEqual(2);
    expect(result.violations.every((v) => v.severity === "warning")).toBe(true);
  });

  it("should return error severity for identity mismatch", async () => {
    const event = await makeValidSignedEvent();
    event.pubkey =
      "0000000000000000000000000000000000000000000000000000000000000001";
    const result = await softValidateKeyPackageEvent(event);
    expect(result.keyPackage).toBeDefined();
    const errors = result.violations.filter((v) => v.severity === "error");
    expect(errors.length).toBeGreaterThanOrEqual(1);
    expect(errors.some((v) => v.check === "identity_binding")).toBe(true);
  });

  it("should return error severity for fabricated i tag", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "i" ? ["i", "deadbeef".repeat(4)] : t,
    );
    const result = await softValidateKeyPackageEvent(event);
    expect(result.keyPackage).toBeDefined();
    const errors = result.violations.filter((v) => v.severity === "error");
    expect(errors.some((v) => v.check === "i_tag_mismatch")).toBe(true);
  });

  it("should return null keyPackage for wrong event kind (hard error)", async () => {
    const event = await makeValidSignedEvent();
    event.kind = 1;
    const result = await softValidateKeyPackageEvent(event);
    expect(result.keyPackage).toBeNull();
    expect(result.violations[0].severity).toBe("error");
    expect(result.violations[0].check).toBe("event_kind");
  });

  it("should report d_tag_shape warning for non-64-hex d tag on kind 30443", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "d" ? ["d", "notestr-shortslug"] : t,
    );
    const result = await softValidateKeyPackageEvent(event);
    expect(result.violations.some((v) => v.check === "d_tag_shape")).toBe(true);
    expect(
      result.violations.find((v) => v.check === "d_tag_shape")?.severity,
    ).toBe("warning");
  });

  it("should report mls_proposals_presence warning when tag absent on kind 30443", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.filter((t) => t[0] !== "mls_proposals");
    const result = await softValidateKeyPackageEvent(event);
    expect(
      result.violations.some((v) => v.check === "mls_proposals_presence"),
    ).toBe(true);
  });

  it("should report mls_proposals_value warning for wrong value on kind 30443", async () => {
    const event = await makeValidSignedEvent();
    event.tags = event.tags.map((t) =>
      t[0] === "mls_proposals" ? ["mls_proposals", "0x000b"] : t,
    );
    const result = await softValidateKeyPackageEvent(event);
    expect(
      result.violations.some((v) => v.check === "mls_proposals_value"),
    ).toBe(true);
  });

  it("should NOT report mls_proposals or d_tag_shape violations on kind 443 (back-compat)", async () => {
    const event = await makeValidSignedEvent();
    // Override to kind 443 with a non-hex d (kind 443 has no d tag requirement)
    event.kind = KEY_PACKAGE_KIND;
    event.tags = event.tags
      .filter((t) => t[0] !== "mls_proposals")
      .map((t) => (t[0] === "d" ? ["d", "free-form-value"] : t));
    const result = await softValidateKeyPackageEvent(event);
    expect(result.violations.some((v) => v.check === "mls_proposals_presence")).toBe(false);
    expect(result.violations.some((v) => v.check === "d_tag_shape")).toBe(false);
  });

  it("should return null keyPackage for decode failure (hard error)", async () => {
    const event: NostrEvent = {
      kind: ADDRESSABLE_KEY_PACKAGE_KIND,
      id: "aaa",
      pubkey: validPubkey,
      created_at: 1000,
      tags: [
        ["d", testD],
        ["encoding", "base64"],
        ["mls_protocol_version", "1.0"],
        ["mls_ciphersuite", "0x0001"],
        ["mls_extensions", "0x000a", "0xf2ee"],
        ["relays", "wss://relay.example.com"],
        ["i", "deadbeef"],
      ],
      content: "bm90YXZhbGlka2V5cGFja2FnZQ==",
      sig: "sig",
    };
    const result = await softValidateKeyPackageEvent(event);
    expect(result.keyPackage).toBeNull();
    expect(result.violations.some((v) => v.check === "content_decode")).toBe(
      true,
    );
  });

  it("should still decode keyPackage even with multiple warnings", async () => {
    const event = await makeValidSignedEvent();
    // Remove d tag and relays — both warnings, but content is still valid
    event.tags = event.tags.filter(
      (t) => t[0] !== "d" && t[0] !== "relays",
    );
    const result = await softValidateKeyPackageEvent(event);
    expect(result.keyPackage).toBeDefined();
    const warnings = result.violations.filter((v) => v.severity === "warning");
    expect(warnings.length).toBeGreaterThanOrEqual(2);
  });
});
