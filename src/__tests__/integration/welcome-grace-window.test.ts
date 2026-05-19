/**
 * Integration test for the KeyPackage rotation grace window in
 * `joinGroupFromWelcome`.
 *
 * Reproduces the race documented in
 * `specs/epic-welcome-grace-window/spec.md`: the inviter holds a relay
 * copy of an invitee's KeyPackage and builds a Welcome against it; the
 * invitee rotates locally before consuming the Welcome (which calls
 * `markDeprecated` on the original KP); `joinGroupFromWelcome` must still
 * succeed because the private material lives in IDB within the grace
 * window. After `cleanupDeprecated(0)` the private material is gone and
 * the existing "No matching KeyPackage" error returns.
 */

import { PrivateKeyAccount } from "applesauce-accounts/accounts";
import { unlockGiftWrap } from "applesauce-common/helpers/gift-wrap";
import { type NostrEvent } from "applesauce-core/helpers/event";
import {
  CiphersuiteImpl,
  defaultCryptoProvider,
  getCiphersuiteImpl,
} from "ts-mls";
import { beforeEach, describe, expect, it } from "vitest";
import type { StoredKeyPackage } from "../../client/key-package-manager.js";
import { MarmotClient } from "../../client/marmot-client.js";
import { SerializedClientState } from "../../core/client-state.js";
import {
  ADDRESSABLE_KEY_PACKAGE_KIND,
  WELCOME_EVENT_KIND,
} from "../../core/protocol.js";
import { InMemoryKeyValueStore } from "../../extra/in-memory-key-value-store";
import { MockNetwork } from "../helpers/mock-network.js";

describe("joinGroupFromWelcome — KeyPackage rotation grace window", () => {
  let adminAccount: PrivateKeyAccount<any>;
  let inviteeAccount: PrivateKeyAccount<any>;
  let _ciphersuite: CiphersuiteImpl;
  let mockNetwork: MockNetwork;
  let adminClient: MarmotClient;
  let inviteeClient: MarmotClient;

  beforeEach(async () => {
    adminAccount = PrivateKeyAccount.generateNew();
    inviteeAccount = PrivateKeyAccount.generateNew();

    _ciphersuite = await getCiphersuiteImpl(
      "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
      defaultCryptoProvider,
    );

    mockNetwork = new MockNetwork();

    adminClient = new MarmotClient({
      groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
      keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
      signer: adminAccount.signer,
      network: mockNetwork,
    });

    inviteeClient = new MarmotClient({
      groupStateStore: new InMemoryKeyValueStore<SerializedClientState>(),
      keyPackageStore: new InMemoryKeyValueStore<StoredKeyPackage>(),
      signer: inviteeAccount.signer,
      network: mockNetwork,
      clientId: "test-invitee-device",
    });
  });

  /**
   * Builds a Welcome rumor targeting the invitee's current published
   * KeyPackage, then rotates the invitee's KP locally (which calls
   * `markDeprecated`). The Welcome rumor now targets a deprecated KP.
   */
  async function setupRotatedKPScenario(): Promise<{
    welcomeRumor: Awaited<ReturnType<typeof unlockGiftWrap>>;
    originalKeyPackageRef: Uint8Array;
  }> {
    const adminPubkey = await adminAccount.signer.getPublicKey();
    const inviteePubkey = await inviteeAccount.signer.getPublicKey();

    // Invitee publishes a KeyPackage.
    const inviteePkg = await inviteeClient.keyPackages.create({
      relays: ["wss://mock-relay.test"],
    });
    const originalKeyPackageRef = inviteePkg.keyPackageRef;

    // Admin creates a group and invites the invitee while the original KP is
    // still active on the wire.
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
    expect(keyPackageEvents.length).toBe(1);
    await adminGroup.inviteByKeyPackageEvent(keyPackageEvents[0]);

    // Fetch the Welcome gift-wrap before any rotation happens.
    const giftWraps = await mockNetwork.request(["wss://mock-inbox.test"], {
      kinds: [1059],
      "#p": [inviteePubkey],
    });
    expect(giftWraps.length).toBe(1);

    const welcomeRumor = await unlockGiftWrap(
      giftWraps[0],
      inviteeAccount.signer,
    );
    expect(welcomeRumor.kind).toBe(WELCOME_EVENT_KIND);

    // Invitee rotates BEFORE consuming the Welcome — `rotate()` calls
    // `markDeprecated` on the original KP, so `list()` will no longer
    // surface it.
    await inviteeClient.keyPackages.rotate(originalKeyPackageRef, {
      relays: ["wss://mock-relay.test"],
    });

    // Confirm the rotation actually deprecated the original.
    const stored = await inviteeClient.keyPackages.get(originalKeyPackageRef);
    expect(stored?.deprecatedAt).toBeDefined();
    expect(
      (await inviteeClient.keyPackages.list()).some(
        (p) =>
          Buffer.from(p.keyPackageRef).toString("hex") ===
          Buffer.from(originalKeyPackageRef).toString("hex"),
      ),
    ).toBe(false);

    return { welcomeRumor, originalKeyPackageRef };
  }

  it("succeeds when the Welcome targets a deprecated-but-within-grace KP (AC-GRACE-1)", async () => {
    const { welcomeRumor } = await setupRotatedKPScenario();

    const { group } = await inviteeClient.joinGroupFromWelcome({
      welcomeRumor,
    });

    expect(group).toBeDefined();
    expect(group.state.groupContext.epoch).toBeGreaterThanOrEqual(1n);
  });

  it("still fails when the deprecated KP has been removed after rotation (AC-GRACE-2, rotation flow)", async () => {
    const { welcomeRumor } = await setupRotatedKPScenario();

    // Expire and remove the deprecated entry immediately. The rotation
    // replacement KP is still in the store but its keyPackageRef does NOT
    // match the welcome's secrets[] — it was generated fresh by rotate().
    const removed = await inviteeClient.keyPackages.cleanupDeprecated(0);
    expect(removed).toBe(1);

    // Two valid post-grace-window failure modes depending on whether the
    // rotation replacement is in the store (here: yes) — either way the
    // join must reject because the matching private material is gone.
    await expect(
      inviteeClient.joinGroupFromWelcome({ welcomeRumor }),
    ).rejects.toThrow(/No matching KeyPackage|Failed to join group/);
  });

  it("still fails with the literal 'No matching KeyPackage' error when the store is empty (AC-GRACE-2, bare removal)", async () => {
    const adminPubkey = await adminAccount.signer.getPublicKey();
    const inviteePubkey = await inviteeAccount.signer.getPublicKey();

    // Invitee publishes one KP — no rotation will run, so there is no
    // active replacement.
    const inviteePkg = await inviteeClient.keyPackages.create({
      relays: ["wss://mock-relay.test"],
    });
    const originalKeyPackageRef = inviteePkg.keyPackageRef;

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
    await adminGroup.inviteByKeyPackageEvent(keyPackageEvents[0]);

    const giftWraps = await mockNetwork.request(["wss://mock-inbox.test"], {
      kinds: [1059],
      "#p": [inviteePubkey],
    });
    const welcomeRumor = await unlockGiftWrap(
      giftWraps[0],
      inviteeAccount.signer,
    );

    // Deprecate directly (no rotation, no replacement KP), then expire.
    await inviteeClient.keyPackages.markDeprecated(
      originalKeyPackageRef,
      Math.floor(Date.now() / 1000),
    );
    const removed = await inviteeClient.keyPackages.cleanupDeprecated(0);
    expect(removed).toBe(1);

    await expect(
      inviteeClient.joinGroupFromWelcome({ welcomeRumor }),
    ).rejects.toThrow(/No matching KeyPackage/);
  });

  it("uses the deprecated KP as a fallback when only it matches the Welcome", async () => {
    // Setup: the invitee has a deprecated KP (matches the welcome) plus a
    // fresh active replacement KP produced by rotate() (whose keyPackageRef
    // does NOT match the welcome — refs are content-derived). joinGroup
    // must therefore consume the deprecated KP. This proves the
    // grace-window fallback path on its own; it does NOT prove
    // active-first ordering — that is unfalsifiable at the join layer
    // because content-derived refs guarantee at most one KP matches any
    // given Welcome. Ordering is asserted at the manager level (see the
    // listForWelcomeDecrypt unit test).
    const { welcomeRumor, originalKeyPackageRef } =
      await setupRotatedKPScenario();

    const { group } = await inviteeClient.joinGroupFromWelcome({
      welcomeRumor,
    });
    expect(group).toBeDefined();

    // The active replacement KP is still present and untouched (no
    // regression on AC-GRACE-3: deprecated entries did not leak into
    // list()).
    const active = await inviteeClient.keyPackages.list();
    expect(active.length).toBeGreaterThanOrEqual(1);
    expect(
      active.some(
        (p) =>
          Buffer.from(p.keyPackageRef).toString("hex") ===
          Buffer.from(originalKeyPackageRef).toString("hex"),
      ),
    ).toBe(false);
  });

  it("listForWelcomeDecrypt returns the deprecated KP for the join path", async () => {
    const { originalKeyPackageRef } = await setupRotatedKPScenario();

    const decryptList = await inviteeClient.keyPackages.listForWelcomeDecrypt();

    expect(
      decryptList.some(
        (p) =>
          Buffer.from(p.keyPackageRef).toString("hex") ===
          Buffer.from(originalKeyPackageRef).toString("hex"),
      ),
    ).toBe(true);

    // And the deprecated one carries deprecatedAt.
    const found = decryptList.find(
      (p) =>
        Buffer.from(p.keyPackageRef).toString("hex") ===
        Buffer.from(originalKeyPackageRef).toString("hex"),
    );
    expect(found?.deprecatedAt).toBeDefined();
  });

  // Quieten the unused-NostrEvent / unused-ciphersuite import in this
  // suite — keep the imports so future tests can extend the scenario
  // without re-wiring helpers.
  void ({} as { _e?: NostrEvent });
});
