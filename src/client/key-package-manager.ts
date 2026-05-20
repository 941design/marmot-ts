/** @module @category Client - Key Package Manager */
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import { EventSigner } from "applesauce-core";
import { NostrEvent } from "applesauce-core/helpers/event";
import { EventEmitter } from "eventemitter3";
import {
  CiphersuiteName,
  ciphersuites,
  CryptoProvider,
  defaultCryptoProvider,
  KeyPackage,
  PrivateKeyPackage,
} from "ts-mls";
import { createCredential } from "../core/credential.js";
import {
  createDeleteKeyPackageEvent,
  createKeyPackageEvent,
  getKeyPackage,
  getKeyPackageIdentifier,
  getKeyPackageReference,
  getKeyPackageRelays,
  keyPackageFilters,
} from "../core/key-package-event.js";
import {
  calculateKeyPackageRef,
  generateKeyPackage,
} from "../core/key-package.js";
import {
  ADDRESSABLE_KEY_PACKAGE_KIND,
  KEY_PACKAGE_KIND,
} from "../core/protocol.js";
import { logger } from "../utils/debug.js";
import { GenericKeyValueStore } from "../utils/key-value.js";
import { NostrNetworkInterface } from "./nostr-interface.js";

// ---------------------------------------------------------------------------
// Stored entry types
// ---------------------------------------------------------------------------

/**
 * A key package that has local private material.
 *
 * Created when generating or importing a key package for which the private
 * keys are held locally. Narrow from {@link StoredKeyPackage} by checking
 * `privatePackage !== undefined`.
 */
export type LocalKeyPackage = {
  /** The calculated key package reference */
  keyPackageRef: Uint8Array;
  /** The public key package */
  publicPackage: KeyPackage;
  /** The private key package — its presence is the discriminant for a local entry */
  privatePackage: PrivateKeyPackage;
  /** Nostr kind-30443 addressable slot identifier (`d` tag value) */
  identifier?: string;
  /** Nostr kind-443 or kind-30443 events this key package has been published under */
  published?: NostrEvent[];
  /** Whether this key package has been consumed (e.g. used to join a group). Undefined means unused. */
  used?: boolean;
  /**
   * Unix timestamp (seconds) when this entry was marked as deprecated.
   *
   * Set by {@link KeyPackageManager.markDeprecated} during rotation instead of
   * immediate deletion. Deprecated entries are excluded from {@link list} but
   * their private material remains available for Welcome decryption until
   * {@link KeyPackageManager.removeExpired} is called.
   */
  deprecatedAt?: number;
};

/**
 * A key package observed on relays for which no private material is held locally.
 *
 * Created when tracking a kind-443 or kind-30443 event from another device.
 * Enables cross-device deletion without requiring the private keys to be
 * present. The public key package is always present — events that cannot be
 * decoded are rejected as invalid.
 *
 * Narrow from {@link StoredKeyPackage} by checking `privatePackage === undefined`.
 */
export type TrackedKeyPackage = {
  /** The calculated key package reference */
  keyPackageRef: Uint8Array;
  /** The public key package, decoded from the kind-443 or kind-30443 event body */
  publicPackage: KeyPackage;
  /** Always undefined — the discriminant that identifies this as a tracked entry */
  privatePackage?: undefined;
  /** Nostr kind-30443 addressable slot identifier (`d` tag value) */
  identifier?: string;
  /** Nostr kind-443 or kind-30443 events this key package has been published under */
  published?: NostrEvent[];
  /** Whether this key package has been consumed (e.g. used to join a group). Undefined means unused. */
  used?: boolean;
  /**
   * Unix timestamp (seconds) when this entry was marked as deprecated.
   *
   * Set by {@link KeyPackageManager.markDeprecated} during rotation instead of
   * immediate deletion. Deprecated entries are excluded from {@link list} but
   * remain in the store until {@link KeyPackageManager.removeExpired} is called.
   */
  deprecatedAt?: number;
};

/**
 * A stored key package — either a locally-held one (with private material) or
 * a tracked foreign one (without private material).
 *
 * Use `privatePackage` to narrow the type:
 *
 * ```ts
 * if (pkg.privatePackage !== undefined) {
 *   // pkg is LocalKeyPackage
 * } else {
 *   // pkg is TrackedKeyPackage
 * }
 * ```
 */
export type StoredKeyPackage = LocalKeyPackage | TrackedKeyPackage;

/** A {@link LocalKeyPackage} without the private material, safe to expose in listings */
export type ListedKeyPackage = Omit<StoredKeyPackage, "privatePackage">;

function getReplaceableEventKey(event: NostrEvent): string | undefined {
  const identifier = getKeyPackageIdentifier(event);
  if (identifier === undefined) return undefined;

  return `${event.kind}:${event.pubkey}:${identifier}`;
}

function deduplicatePublishedEvents(events: NostrEvent[]): NostrEvent[] {
  const seenIds = new Set<string>();
  const replaceableIndexes = new Map<string, number>();
  const deduplicated: NostrEvent[] = [];

  for (const event of events) {
    if (seenIds.has(event.id)) continue;
    seenIds.add(event.id);

    const replaceableKey = getReplaceableEventKey(event);
    if (replaceableKey === undefined) {
      deduplicated.push(event);
      continue;
    }

    const existingIndex = replaceableIndexes.get(replaceableKey);
    if (existingIndex === undefined) {
      replaceableIndexes.set(replaceableKey, deduplicated.length);
      deduplicated.push(event);
      continue;
    }

    const existing = deduplicated[existingIndex];
    if (event.created_at > existing.created_at) {
      deduplicated[existingIndex] = event;
    }
  }

  return deduplicated;
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/**
 * Thrown by {@link KeyPackageManager.create} when no relay URLs are provided.
 * Callers can catch this specifically to prompt the user for relay configuration.
 */
export class MissingRelayError extends Error {
  constructor() {
    super("At least one relay URL is required to publish a key package");
    this.name = "MissingRelayError";
  }
}

/**
 * Thrown by {@link KeyPackageManager.create} when no slot identifier (`d` tag)
 * can be determined — neither passed in options nor set as `clientId` on the
 * manager. Set `clientId` on the manager or pass `d` in the options.
 */
export class MissingSlotIdentifierError extends Error {
  constructor() {
    super(
      "Cannot create key package: no slot identifier available. Pass 'd' in options or set 'clientId' on the manager.",
    );
    this.name = "MissingSlotIdentifierError";
  }
}

/**
 * Thrown by {@link KeyPackageManager.rotate} when the given key package
 * reference is not found in the local store.
 */
export class KeyPackageNotFoundError extends Error {
  constructor(refHex: string) {
    super(`Key package not found: ${refHex}`);
    this.name = "KeyPackageNotFoundError";
  }
}

/**
 * Thrown by {@link KeyPackageManager.rotate} when no relay URLs can be
 * determined for the replacement key package — neither passed explicitly
 * nor recoverable from the old package's publish records.
 */
export class KeyPackageRotatePreconditionError extends Error {
  constructor() {
    super(
      "Cannot rotate: no relay URLs available. Pass relays in options or ensure the old key package has published events.",
    );
    this.name = "KeyPackageRotatePreconditionError";
  }
}

// ---------------------------------------------------------------------------
// Option and entry types
// ---------------------------------------------------------------------------

/** Options for creating a new key package */
export type CreateKeyPackageOptions = {
  /** Relay URLs where the key package event will be published (required) */
  relays: string[];
  /**
   * Addressable slot identifier (`d` tag value) for the kind 30443 event.
   * MUST be 64 lowercase hex characters per MIP-00 — use
   * {@link generateKeyPackageSlot} to mint one. If omitted, falls back to
   * the manager's `clientId` (which is also subject to the same shape
   * requirement). Throws {@link MissingSlotIdentifierError} if neither is
   * available.
   */
  identifier?: string;
  /** Ciphersuite to use (default: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) */
  ciphersuite?: CiphersuiteName;
  /** Whether to mark the key package with the MLS last_resort extension (default: true) */
  isLastResort?: boolean;
  /** Client identifier string to include in the key package event */
  client?: string;
  /** Whether to include the NIP-70 protected tag on the event */
  protected?: boolean;
};

/** Options for rotating a key package */
export type RotateKeyPackageOptions = {
  /**
   * Relay URLs for the new key package event.
   * If omitted, the relays from the most recent publish of the old key package are reused.
   */
  relays?: string[];
  /**
   * Addressable slot identifier (`d` tag value) for the replacement event.
   * MUST be 64 lowercase hex characters per MIP-00 — use
   * {@link generateKeyPackageSlot} to mint one. If omitted, the `d` from the
   * stored entry is reused (preferred — the relay-replace semantics depend
   * on it). If the stored entry has no `d` (legacy kind 443 package), a
   * fresh random 64-hex value is generated automatically.
   */
  d?: string;
  /** Ciphersuite to use for the new key package */
  ciphersuite?: CiphersuiteName;
  /** Whether to mark the new key package with the MLS last_resort extension (default: true) */
  isLastResort?: boolean;
  /** Client identifier string to include in the new key package event */
  client?: string;
  /** Whether to include the NIP-70 protected tag on the new event */
  protected?: boolean;
};

export type KeyPackageManagerEvents = {
  /** Emitted when a key package is stored locally */
  added: (keyPackage: StoredKeyPackage) => void;
  /** Emitted when a key package is removed from local storage */
  removed: (keyPackageRef: Uint8Array) => void;
  /** Emitted when a key package is updated */
  updated: (keyPackage: StoredKeyPackage) => void;
  /** Emitted when a key package publish is recorded (own publish or observed relay event) */
  published: (refHex: string, eventId: string, relays: string[]) => void;
};

/** Options for creating a new KeyPackageManager */
export type KeyPackageManagerOptions = {
  /** The backend to store and load the key packages from */
  store: GenericKeyValueStore<StoredKeyPackage>;
  /** Default `d` tag value for {@link KeyPackageManager.create} and {@link KeyPackageManager.rotate}. Falls back to this when no explicit `d` is passed. */
  clientId?: string;
  /** The signer used for the clients identity */
  signer: EventSigner;
  /** The nostr relay pool to use for the client. Should implement GroupNostrInterface for group operations. */
  network: NostrNetworkInterface;
  /** The crypto provider to use for cryptographic operations */
  cryptoProvider?: CryptoProvider;
};

/**
 * Manages the full lifecycle of MLS key packages — local private material and
 * the Nostr kind-30443 events that advertise this client to potential inviters.
 *
 * Legacy kind-443 events are supported for reading and deletion only; new
 * events are always published as kind 30443.
 *
 * @example
 * ```typescript
 * const manager = new KeyPackageManager({
 *   backend: myKeyValueBackend,
 *   signer,
 *   network,
 *   // Stable per-device 64-hex slot (MIP-00). Mint once via
 *   // generateKeyPackageSlot() and persist; reuse across sessions.
 *   clientId: generateKeyPackageSlot(),
 * });
 * const pkg = await manager.create({ relays: ["wss://relay.example.com"] });
 *
 * // Feed observed relay events — kind 443 and kind 30443 with an `i` tag are recorded
 * await manager.track(nostrEvent);
 *
 * // Rotate: publish a new kind 30443 under the same `d` slot (relay replaces automatically)
 * const newPkg = await manager.rotate(pkg.keyPackageRef);
 *
 * // List all key packages, filtering to those with published events
 * const published = (await manager.list()).filter(p => p.published.length > 0);
 * ```
 */
export class KeyPackageManager extends EventEmitter<KeyPackageManagerEvents> {
  /**
   * Default slot identifier (`d` tag value) used by {@link create} when no
   * explicit `d` is passed in options.
   *
   * MUST be 64 lowercase hex characters per MIP-00 — the manager forwards
   * this value to {@link createKeyPackageEvent}, which throws on any other
   * shape (free-form labels such as `"my-app-desktop"` are rejected with a
   * message pointing at {@link generateKeyPackageSlot}). Mint a stable
   * per-device value once via `generateKeyPackageSlot()` and persist it so
   * all key packages from this manager share a single addressable slot on
   * relays.
   */
  readonly clientId: string | undefined;

  private readonly store: GenericKeyValueStore<StoredKeyPackage>;
  private readonly cryptoProvider: CryptoProvider;
  private readonly signer: EventSigner;
  private readonly network: NostrNetworkInterface;

  #log = logger.extend("KeyPackageManager");

  constructor(options: KeyPackageManagerOptions) {
    super();
    this.store = options.store;
    this.cryptoProvider = options.cryptoProvider ?? defaultCryptoProvider;
    this.signer = options.signer;
    this.network = options.network;
    this.clientId = options.clientId;
  }

  // ---------------------------------------------------------------------------
  // Storage helpers (inlined from KeyPackageStore)
  // ---------------------------------------------------------------------------

  /** Resolves a ref argument to a hex storage key */
  private resolveStorageKey(ref: Uint8Array | string): string {
    if (typeof ref === "string") return ref;
    return bytesToHex(ref);
  }

  /**
   * Adds a {@link LocalKeyPackage} to the store.
   *
   * @param keyPackage - Must include `publicPackage` and `privatePackage`.
   *   Optionally include `identifier` to persist the addressable slot identifier.
   * @returns The storage key (hex ref string)
   */
  async add(
    keyPackage: Pick<LocalKeyPackage, "publicPackage" | "privatePackage"> &
      Partial<Pick<LocalKeyPackage, "published" | "identifier">>,
  ): Promise<string> {
    const keyPackageRef = await calculateKeyPackageRef(
      keyPackage.publicPackage,
      this.cryptoProvider,
    );
    const key = bytesToHex(keyPackageRef);

    const entry: LocalKeyPackage = {
      keyPackageRef,
      publicPackage: keyPackage.publicPackage,
      privatePackage: keyPackage.privatePackage,
      ...(keyPackage.identifier !== undefined
        ? { identifier: keyPackage.identifier }
        : {}),
      ...(keyPackage.published !== undefined
        ? { published: deduplicatePublishedEvents(keyPackage.published) }
        : {}),
    };

    await this.store.setItem(key, entry);
    this.emit("added", entry);
    this.#log(
      "added %s" + (entry.privatePackage ? " with private key" : ""),
      key,
    );

    return key;
  }

  /**
   * Appends a kind-443 or kind-30443 Nostr event to the `published` list of
   * the key package identified by `ref`. If no entry exists yet, a
   * {@link TrackedKeyPackage} is created by decoding the public key package
   * from the event body.
   *
   * Throws if the event body cannot be decoded as a valid key package.
   */
  private async storeAddPublished(
    ref: string | Uint8Array,
    event: NostrEvent,
  ): Promise<void> {
    const key = typeof ref === "string" ? ref : bytesToHex(ref);
    const existing = await this.store.getItem(key);

    // Extract the addressable slot identifier if this is a kind 30443 event
    const identifier = getKeyPackageIdentifier(event);

    if (existing) {
      const published = deduplicatePublishedEvents([
        ...(existing.published ?? []),
        event,
      ]);
      const shouldPersistIdentifier =
        identifier !== undefined && existing.identifier === undefined;
      const publishedChanged =
        existing.published === undefined ||
        published.length !== existing.published.length ||
        !published.every(
          (e, index) => e.id === existing.published?.[index]?.id,
        );

      if (!publishedChanged && !shouldPersistIdentifier) {
        return;
      }

      const updated: StoredKeyPackage = {
        ...existing,
        // Persist identifier if discovered for the first time on this entry
        ...(shouldPersistIdentifier ? { identifier } : {}),
        published,
      };

      await this.store.setItem(key, updated);
      this.emit("updated", updated);
      this.#log("stored published event %s for %s", event.id, ref);
    } else {
      // No local entry — decode the public key package from the event body.
      // Throws if the event content is not a valid encoded KeyPackage.
      const publicPackage = getKeyPackage(event);

      const keyPackageRef = await calculateKeyPackageRef(
        publicPackage,
        this.cryptoProvider,
      );

      const entry: TrackedKeyPackage = {
        keyPackageRef,
        publicPackage,
        ...(identifier !== undefined ? { identifier } : {}),
        published: [event],
      };

      await this.store.setItem(key, entry);
      this.emit("added", entry);
      this.#log("added key package from event %s", event.id);
    }
  }

  /**
   * Retrieves the stored key package entry.
   * Returns any entry regardless of whether it has private material.
   */
  private async storeGetKeyPackage(
    ref: Uint8Array | string,
  ): Promise<StoredKeyPackage | null> {
    const key = this.resolveStorageKey(ref);
    return this.store.getItem(key);
  }

  /**
   * Removes a key package from the backend.
   */
  private async storeRemove(ref: Uint8Array | string): Promise<void> {
    const key = this.resolveStorageKey(ref);
    const stored = await this.store.getItem(key);
    await this.store.removeItem(key);

    if (stored) {
      this.emit("removed", stored.keyPackageRef);
      this.#log("removed key package %s", key);
    }
  }

  /**
   * Lists all {@link LocalKeyPackage} entries (those with private material),
   * without the private package itself.
   *
   * By default, deprecated entries (those with `deprecatedAt` set) are
   * excluded. Pass `includeDeprecated: true` to include them — used by
   * {@link listForWelcomeDecrypt} so the welcome-decrypt path can recover
   * Welcomes built against a rotated-but-still-in-grace KeyPackage. See
   * {@link markDeprecated} for the grace-window contract.
   *
   * {@link TrackedKeyPackage} entries are excluded — use {@link get} to
   * retrieve a specific tracked entry by ref.
   */
  private async storeList(
    options: { includeDeprecated?: boolean } = {},
  ): Promise<ListedKeyPackage[]> {
    const { includeDeprecated = false } = options;
    const allKeys = await this.store.keys();

    const packages = await Promise.all(
      allKeys.map((key) => this.store.getItem(key)),
    );

    return packages
      .filter(
        (pkg): pkg is LocalKeyPackage =>
          pkg !== null &&
          pkg.privatePackage !== undefined &&
          (includeDeprecated || pkg.deprecatedAt === undefined),
      )
      .map(
        ({
          keyPackageRef,
          publicPackage,
          identifier,
          published,
          used,
          deprecatedAt,
        }) => ({
          keyPackageRef,
          publicPackage,
          ...(identifier !== undefined ? { identifier } : {}),
          ...(published !== undefined ? { published } : {}),
          ...(used !== undefined ? { used } : {}),
          ...(deprecatedAt !== undefined ? { deprecatedAt } : {}),
        }),
      );
  }

  // ---------------------------------------------------------------------------
  // Creation and publishing
  // ---------------------------------------------------------------------------

  /**
   * Creates a new key package, stores the private material locally, signs and
   * publishes a kind 30443 addressable event to the specified relays, and
   * records the event.
   *
   * The `d` (slot identifier) is resolved in order:
   * 1. `options.d` (explicit)
   * 2. `this.clientId` (manager default)
   * 3. Throws {@link MissingSlotIdentifierError}
   *
   * @param options - Creation options, including required relay URLs
   * @returns The stored key package (without private material)
   * @throws {MissingRelayError} if relays is empty
   * @throws {MissingSlotIdentifierError} if no slot identifier can be determined
   */
  async create(options: CreateKeyPackageOptions): Promise<ListedKeyPackage> {
    if (!options.relays || options.relays.length === 0) {
      throw new MissingRelayError();
    }

    const identifier = options.identifier ?? this.clientId;
    if (!identifier) {
      throw new MissingSlotIdentifierError();
    }

    this.#log("creating key package on relays: %O", options.relays);

    const pubkey = await this.signer.getPublicKey();
    const credential = createCredential(pubkey);
    const ciphersuite = await this.#getCiphersuiteImpl(options.ciphersuite);

    const keyPackage = await generateKeyPackage({
      credential,
      ciphersuiteImpl: ciphersuite,
      isLastResort: options.isLastResort,
    });

    // Build the kind 30443 event template FIRST — createKeyPackageEvent enforces
    // the MIP-00 64-hex slot shape on `identifier`. Doing this before this.add()
    // ensures an invalid identifier throws without leaving orphaned private
    // material in the store.
    const eventTemplate = await createKeyPackageEvent({
      keyPackage: keyPackage.publicPackage,
      identifier: identifier,
      relays: options.relays,
      client: options.client,
      protected: options.protected,
    });

    // Store private material locally, including the slot identifier
    const refHex = await this.add({ ...keyPackage, identifier: identifier });

    const signed = await this.signer.signEvent(eventTemplate);
    await this.network.publish(options.relays, signed);

    // Record the published event on the stored entry
    await this.storeAddPublished(refHex, signed);

    const stored = await this.storeGetKeyPackage(refHex);
    if (!stored) throw new Error("Key package not found after store operation");

    this.emit("published", refHex, signed.id, options.relays);
    this.#log(
      "created and published key package %s with slot %s",
      refHex,
      identifier,
    );

    return {
      keyPackageRef: stored.keyPackageRef,
      publicPackage: stored.publicPackage,
      identifier: stored.identifier,
    };
  }

  // ---------------------------------------------------------------------------
  // Rotation
  // ---------------------------------------------------------------------------

  /**
   * Rotates a key package: publishes a new kind 30443 event (reusing the same
   * `d` slot so relays replace the old event automatically), then removes the
   * old private key material.
   *
   * For legacy kind-443 published events on the entry, a NIP-09 deletion is
   * sent before publishing the replacement. Kind-30443 published events do not
   * need explicit deletion — the new event supersedes them on relays.
   *
   * @param ref - The key package reference of the key package to rotate
   * @param options - Options for the new key package
   * @returns The new stored key package (without private material)
   * @throws {KeyPackageNotFoundError} if the key package ref is not found in the local store
   * @throws {KeyPackageRotatePreconditionError} if no relay URLs can be determined for the new key package
   */
  async rotate(
    ref: Uint8Array | string,
    options?: RotateKeyPackageOptions,
  ): Promise<ListedKeyPackage> {
    const refHex = typeof ref === "string" ? ref : bytesToHex(ref);
    this.#log("rotating key package %s", refHex);

    const existing = await this.storeGetKeyPackage(ref);
    if (!existing) {
      throw new KeyPackageNotFoundError(refHex);
    }

    // Determine relays for the new key package
    const oldEvents = existing.published ?? [];
    const relaysForNew =
      options?.relays ??
      (oldEvents.length > 0
        ? getKeyPackageRelays(oldEvents[oldEvents.length - 1])
        : undefined);

    if (!relaysForNew || relaysForNew.length === 0) {
      throw new KeyPackageRotatePreconditionError();
    }

    // Resolve the slot identifier for the new event:
    // prefer an explicit override, then the stored entry's d (same slot = relay auto-replaces),
    // then generate a fresh random value.
    const newD =
      options?.d ?? existing.identifier ?? bytesToHex(randomBytes(32));

    // Publish NIP-09 deletion only for legacy kind-443 published events.
    // Kind-30443 events are superseded automatically by the new event on relays.
    const legacyEvents = oldEvents.filter((e) => e.kind === KEY_PACKAGE_KIND);
    if (legacyEvents.length > 0) {
      const eventIds = legacyEvents.map((e) => e.id);
      const deleteTemplate = createDeleteKeyPackageEvent({ events: eventIds });
      const signedDelete = await this.signer.signEvent(deleteTemplate);
      const allOldRelays = [
        ...new Set(legacyEvents.flatMap((e) => getKeyPackageRelays(e) ?? [])),
      ];
      await this.network.publish(allOldRelays, signedDelete);
    }

    // Create and publish the new key package under the resolved slot
    const newPkg = await this.create({
      relays: relaysForNew,
      identifier: newD,
      ciphersuite: options?.ciphersuite,
      isLastResort: options?.isLastResort,
      client: options?.client,
      protected: options?.protected,
    });

    // Deprecate old private key material instead of removing it immediately.
    // Stale copies of the old KeyPackage may persist on lagging relays; keeping
    // the old init_key alive for a grace window ensures Welcome messages built
    // from those stale copies remain decryptable.
    await this.markDeprecated(ref, Math.floor(Date.now() / 1000));

    return newPkg;
  }

  /**
   * Removes all deprecated key package entries whose grace window has elapsed.
   *
   * Call this periodically (e.g. on app startup or after rotation) to reclaim
   * storage. The default grace window of 24 hours gives lagging relays time to
   * propagate the new last_resort KeyPackage before the old init_key is discarded.
   *
   * @param maxAgeSec - Grace window in seconds (default: 86400 = 24 hours).
   *   Entries deprecated more than this many seconds ago are removed.
   * @returns The number of entries removed
   */
  async cleanupDeprecated(maxAgeSec: number = 86400): Promise<number> {
    const count = await this.removeExpired(maxAgeSec);
    this.#log("cleanupDeprecated removed %d expired entries", count);
    return count;
  }

  // ---------------------------------------------------------------------------
  // Removal
  // ---------------------------------------------------------------------------

  /**
   * Removes a key package from local private key storage only.
   *
   * Does not publish a relay deletion and does not touch publish records.
   * Use when the key package was never published, or when relay cleanup has
   * already been handled separately.
   *
   * @param ref - The key package reference to remove
   */
  async remove(ref: Uint8Array | string): Promise<void> {
    const refHex = typeof ref === "string" ? ref : bytesToHex(ref);
    await this.storeRemove(ref);
    this.#log("removed key package %s from local store", refHex);
  }

  /**
   * Completely purges one or more key packages: publishes a NIP-09 deletion
   * for all known relay event IDs, removes local private key material, and
   * clears the publish records.
   *
   * @param refs - One or more key package references (hex string or Uint8Array)
   */
  async purge(
    refs: Uint8Array | string | Array<Uint8Array | string>,
  ): Promise<void> {
    const refList = Array.isArray(refs) ? refs : [refs];
    this.#log("purging %d key package(s)", refList.length);

    // Collect all published events and relays across the provided refs
    const allEvents: NostrEvent[] = [];
    const allRelays = new Set<string>();

    for (const ref of refList) {
      const stored = await this.storeGetKeyPackage(ref);
      const events = stored?.published ?? [];
      for (const event of events) {
        allEvents.push(event);
        for (const relay of getKeyPackageRelays(event) ?? []) {
          allRelays.add(relay);
        }
      }
    }

    // Publish a single kind 5 deletion covering all events, if any
    if (allEvents.length > 0) {
      const draft = createDeleteKeyPackageEvent({ events: allEvents });
      const signed = await this.signer.signEvent(draft);
      await this.network.publish([...allRelays], signed);
      this.#log(
        "published %s delete event for %d key packages",
        signed.id,
        allEvents.length,
      );
    }

    // Remove local private key material for all refs
    for (const ref of refList) {
      await this.storeRemove(ref);
    }
  }

  // ---------------------------------------------------------------------------
  // Publish tracking
  // ---------------------------------------------------------------------------

  /**
   * Observes a Nostr event and, if it is a kind 443 or kind 30443 key package
   * event with a valid `i` tag (MIP-00 keyPackageRef), records it in the store.
   *
   * @param event - Any Nostr event; non-key-package events are silently ignored
   * @returns `true` if the event was recorded, `false` if ignored
   */
  async track(event: NostrEvent): Promise<boolean> {
    if (
      event.kind !== KEY_PACKAGE_KIND &&
      event.kind !== ADDRESSABLE_KEY_PACKAGE_KIND
    ) {
      return false;
    }

    const refHex = getKeyPackageReference(event);
    if (!refHex) return false;

    try {
      await this.storeAddPublished(refHex, event);
    } catch {
      // Event body could not be decoded as a KeyPackage — treat as invalid
      return false;
    }

    const relays = getKeyPackageRelays(event) ?? [];
    this.emit("published", refHex, event.id, relays);
    return true;
  }

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  /**
   * Lists all locally stored key packages, each enriched with their published
   * Nostr events.
   *
   * Deprecated entries are excluded. For the welcome-decrypt path (which must
   * recover Welcomes targeting a rotated-but-still-in-grace KeyPackage), use
   * {@link listForWelcomeDecrypt} instead.
   */
  async list(): Promise<ListedKeyPackage[]> {
    return this.#buildSnapshot();
  }

  /**
   * Lists local key packages eligible for decrypting an incoming Welcome —
   * active entries followed by entries still inside the deprecation grace
   * window. Used by {@link MarmotClient.joinGroupFromWelcome} so a Welcome
   * built against a rotated KeyPackage can still be consumed while the new
   * KP propagates to relays.
   *
   * Active entries appear first so the existing happy-path candidate
   * selection is unchanged; deprecated entries (those with `deprecatedAt`
   * set) appear after them. See {@link markDeprecated} for the storage-side
   * contract and {@link cleanupDeprecated} for the grace-window cutoff.
   */
  async listForWelcomeDecrypt(): Promise<ListedKeyPackage[]> {
    // Route through #buildSnapshot so the published-array normalization
    // (undefined → []) matches list()'s contract — keeps the public
    // ListedKeyPackage shape consistent across both public accessors.
    const all = await this.#buildSnapshot({ includeDeprecated: true });
    // Stable sort: active first, deprecated last. Within each partition the
    // original storage order is preserved.
    return all.sort(
      (a, b) =>
        (a.deprecatedAt === undefined ? 0 : 1) -
        (b.deprecatedAt === undefined ? 0 : 1),
    );
  }

  /** Returns the number of locally stored key packages. */
  async count(): Promise<number> {
    return (await this.storeList()).length;
  }

  /** Checks whether a key package exists in local private key storage. */
  async has(ref: Uint8Array | string): Promise<boolean> {
    const key = this.resolveStorageKey(ref);
    const item = await this.store.getItem(key);
    return item !== null && item.privatePackage !== undefined;
  }

  /** Retrieves the full key package from the store. */
  async get(ref: Uint8Array | string): Promise<StoredKeyPackage | null> {
    return this.storeGetKeyPackage(ref);
  }

  /**
   * Alias for {@link get} — retrieves the full key package from the store.
   * @deprecated Prefer {@link get}
   */
  async getKeyPackage(
    ref: Uint8Array | string,
  ): Promise<StoredKeyPackage | null> {
    return this.storeGetKeyPackage(ref);
  }

  /**
   * Fetches all KeyPackage events for a user from relays, querying both
   * legacy (kind 443) and current (kind 30443) events for migration
   * compatibility.
   *
   * Each returned event is also tracked via {@link track} so it enters
   * the local publish record.
   *
   * @param pubkey - The Nostr public key of the user
   * @param relays - Relay URLs to query
   * @returns All valid KeyPackage events found
   */
  async fetchKeyPackagesForUser(
    pubkey: string,
    relays: string[],
  ): Promise<NostrEvent[]> {
    const filters = keyPackageFilters([pubkey]);
    const events = await this.network.request(relays, filters);

    for (const event of events) {
      await this.track(event);
    }

    return events;
  }

  /**
   * Retrieves the private key material for a key package.
   * Used internally by {@link MarmotClient} when processing Welcome messages.
   *
   * @param ref - The key package reference
   * @returns The private key package, or null if not found
   */
  async getPrivateKey(
    ref: Uint8Array | string,
  ): Promise<PrivateKeyPackage | null> {
    const key = this.resolveStorageKey(ref);
    const stored = await this.store.getItem(key);
    return stored?.privatePackage ?? null;
  }

  /**
   * Marks a key package as used by setting `used = true` on the stored entry.
   *
   * Does nothing if no entry is found for the given ref.
   *
   * @param ref - The key package reference
   */
  async markUsed(ref: Uint8Array | string): Promise<void> {
    const refHex = typeof ref === "string" ? ref : bytesToHex(ref);
    const key = this.resolveStorageKey(ref);
    const existing = await this.store.getItem(key);
    if (!existing) return;

    const updated: StoredKeyPackage = { ...existing, used: true };
    await this.store.setItem(key, updated);
    this.emit("updated", updated);
    this.#log("marked key package %s as used", refHex);
  }

  /**
   * Marks a stored key package as deprecated with a timestamp instead of
   * removing it immediately.
   *
   * Deprecated entries are excluded from {@link list} (and therefore
   * {@link count} and {@link watchKeyPackages} snapshots), but their private
   * key material remains accessible via {@link getPrivateKey} for a grace
   * window. This prevents Welcome messages built from stale relay copies of a
   * rotated last_resort KeyPackage from becoming undecryptable.
   *
   * Call {@link removeExpired} to clean up entries whose grace window has elapsed.
   *
   * Does nothing if no entry exists for the given ref.
   *
   * @param ref - The key package reference (as Uint8Array or hex string)
   * @param timestamp - Unix timestamp (seconds) to record as the deprecation time
   */
  async markDeprecated(
    ref: Uint8Array | string,
    timestamp: number,
  ): Promise<void> {
    const key = this.resolveStorageKey(ref);
    const existing = await this.store.getItem(key);
    if (!existing) return;

    const updated: StoredKeyPackage = { ...existing, deprecatedAt: timestamp };
    await this.store.setItem(key, updated);
    this.emit("updated", updated);
    this.#log("marked key package %s as deprecated at %d", key, timestamp);
  }

  /**
   * Removes all entries whose `deprecatedAt` timestamp is older than
   * `maxAgeSec` seconds ago (relative to the current wall clock).
   *
   * Only entries that have been explicitly deprecated via {@link markDeprecated}
   * are candidates for removal — active entries are never touched.
   *
   * @param maxAgeSec - Grace window in seconds (default: 86400 = 24 hours)
   * @returns The number of entries removed
   */
  async removeExpired(maxAgeSec: number = 86400): Promise<number> {
    const allKeys = await this.store.keys();
    const cutoff = Math.floor(Date.now() / 1000) - maxAgeSec;
    let removed = 0;

    for (const key of allKeys) {
      const stored = await this.store.getItem(key);
      if (stored?.deprecatedAt !== undefined && stored.deprecatedAt <= cutoff) {
        await this.store.removeItem(key);
        this.emit("removed", stored.keyPackageRef);
        this.#log("removed expired deprecated key package %s", key);
        removed++;
      }
    }

    return removed;
  }

  /** Clears all entries (local and tracked) from the store. */
  async clear(): Promise<void> {
    const allKeys = await this.store.keys();
    for (const key of allKeys) {
      const stored = await this.store.getItem(key);
      await this.store.removeItem(key);
      if (stored) {
        this.emit("removed", stored.keyPackageRef);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Watching
  // ---------------------------------------------------------------------------

  /**
   * Watches for any change to key packages or their published events.
   *
   * Yields the current snapshot on subscription, then re-yields on every
   * subsequent change.
   */
  async *watchKeyPackages(): AsyncGenerator<ListedKeyPackage[]> {
    let resolveNext: (() => void) | null = null;
    let pending = false;

    const signal = () => {
      if (resolveNext) {
        resolveNext();
        resolveNext = null;
      } else {
        pending = true;
      }
    };

    this.on("added", signal);
    this.on("removed", signal);
    this.on("updated", signal);
    this.on("published", signal);

    try {
      yield [...(await this.#buildSnapshot())];

      while (true) {
        await new Promise<void>((resolve) => {
          if (pending) {
            pending = false;
            resolve();
          } else {
            resolveNext = resolve;
          }
        });
        yield [...(await this.#buildSnapshot())];
      }
    } finally {
      this.off("added", signal);
      this.off("removed", signal);
      this.off("updated", signal);
      this.off("published", signal);
    }
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  async #buildSnapshot(
    options: { includeDeprecated?: boolean } = {},
  ): Promise<ListedKeyPackage[]> {
    const local = await this.storeList(options);
    return local.map((pkg) => ({
      ...pkg,
      published: pkg.published ?? [],
    }));
  }

  async #getCiphersuiteImpl(name?: CiphersuiteName) {
    const ciphersuiteName =
      name ?? "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
    const id = ciphersuites[ciphersuiteName];
    return defaultCryptoProvider.getCiphersuiteImpl(id);
  }
}
