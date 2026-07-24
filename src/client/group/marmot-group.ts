/** @module @category Client - Group */
import type { Rumor } from "applesauce-common/helpers/gift-wrap";
import type { EventSigner } from "applesauce-core/event-factory";
import {
  bytesToHex,
  getEventHash,
  type NostrEvent,
} from "applesauce-core/helpers/event";
import { Debugger } from "debug";
import { EventEmitter } from "eventemitter3";
import {
  acceptAll,
  CiphersuiteImpl,
  type ClientConfig,
  ClientState,
  contentTypes,
  createApplicationMessage,
  createCommit,
  CreateCommitOptions,
  createProposal,
  CryptoProvider,
  defaultCryptoProvider,
  defaultKeyPackageEqualityConfig,
  defaultKeyRetentionConfig,
  defaultLifetimeConfig,
  defaultPaddingConfig,
  defaultProposalTypes,
  getCredentialFromLeafIndex,
  type IncomingMessageCallback,
  type LeafIndex,
  type MlsFramedMessage,
  MlsMessage,
  processMessage,
  type ProcessMessageResult,
  Proposal,
  wireformats,
} from "ts-mls";
import { sha256 } from "@noble/hashes/sha2.js";

import { marmotAuthService } from "../../core/auth-service.js";
import {
  deserializeClientState,
  getMarmotGroupData,
  serializeClientState,
} from "../../core/client-state.js";
import { getCredentialPubkey } from "../../core/credential.js";
import {
  createGroupEvent,
  decryptGroupMessages,
  deserializeApplicationData,
  GroupMessagePair,
  isBetterCandidate,
  isReplayOfApplied,
  mlsCommitContentHash,
  serializeApplicationRumor,
  sortGroupCommits,
  tryDecryptGroupMessageEventWithExporterSecret,
} from "../../core/group-message.js";
import { getKeyPackage } from "../../core/key-package-event.js";
import {
  canonicalizeMimeType,
  decryptMediaFile,
  deriveMediaEncryptionKey,
  encryptMediaFile,
  type MediaAttachment,
  MIP04_VERSION,
} from "../../core/media.js";
import {
  ADDRESSABLE_KEY_PACKAGE_KIND,
  KEY_PACKAGE_KIND,
  MarmotGroupData,
} from "../../core/protocol.js";
import { createWelcomeRumor } from "../../core/welcome.js";
import { logger } from "../../utils/debug.js";
import type { GenericKeyValueStore } from "../../utils/key-value.js";
import type { SerializedClientState } from "../../core/client-state.js";
import { createGiftWrap, hasAck } from "../../utils/index.js";
import type {
  EpochSnapshotStoreBackend,
  EpochSnapshotStoreFactory,
} from "./epoch-snapshot.js";
import { InMemoryEpochSnapshotStore } from "../../extra/in-memory-epoch-snapshot-store.js";
import { unixNow } from "../../utils/nostr.js";
import { NostrNetworkInterface, PublishResponse } from "../nostr-interface.js";
import { proposeInviteUser } from "./proposals/invite-user.js";
import { proposeLeaveGroup } from "./proposals/leave-group.js";

/** An error that is thrown when a group has no relays available to send messages. */
export class NoGroupRelaysError extends Error {
  constructor() {
    super("Group has no relays available to send messages.");
  }
}

/** An error that is thrown the client is unable to find the MarmotGroupData in the ClientState of a group. */
export class NoMarmotGroupDataError extends Error {
  constructor() {
    super("MarmotGroupData not found in ClientState.");
  }
}

function toLeafIndex(index: number): LeafIndex {
  return index as LeafIndex;
}

/**
 * An application message whose MLS-authenticated sender has been resolved and
 * verified against the rumor's claimed `pubkey`. This is the payload delivered on
 * the `authenticatedApplicationMessage` event and the shape consumers bind their
 * own author fields to.
 */
export interface AuthenticatedApplicationMessage {
  /** The decrypted rumor bytes, unchanged. */
  message: Uint8Array;
  /** The authenticated sender's Nostr hex pubkey, from the MLS leaf credential. */
  senderPubkey: string;
  /** The authenticated sender's leaf index in the ratchet tree. */
  senderLeafIndex: number;
}

/** Why an application message failed the Marmot receiver check. */
export type UnauthenticatedMessageReason =
  | "unauthenticated-sender"
  | "undeserializable";

/**
 * Diagnostic payload for the `unauthenticatedMessage` event, emitted when an
 * application message is dropped because its claimed sender could not be
 * authenticated.
 */
export interface UnauthenticatedMessageInfo {
  /** The MLS-authenticated sender's Nostr hex pubkey (empty if unresolvable). */
  senderPubkey: string;
  /** The sender the rumor claimed; absent when the payload could not be deserialized. */
  claimedPubkey?: string;
  /** Why the message was dropped. */
  reason: UnauthenticatedMessageReason;
  /** The Nostr event that was dropped. */
  event: NostrEvent;
}

/** A proposal or commit whose MLS message was successfully processed */
export type ProcessedStateChangeIngestResult = {
  kind: "processed";
  /** The result of processing the event (a group-state change). */
  result: Extract<ProcessMessageResult, { kind: "newState" }>;
  /** The event that was processed */
  event: NostrEvent;
  /** The MLS message that was processed */
  message: MlsMessage;
};

/**
 * An application message that passed sender authentication and was delivered.
 * `senderPubkey` is the decoded MLS-authenticated sender; `result.senderLeafIndex`
 * carries the authenticated leaf index (AC-SURFACE-1).
 */
export type ProcessedApplicationMessageIngestResult = {
  kind: "processed";
  /** The ts-mls application-message result, carrying senderLeafIndex/senderCredential. */
  result: Extract<ProcessMessageResult, { kind: "applicationMessage" }>;
  /** The event that was processed */
  event: NostrEvent;
  /** The MLS message that was processed */
  message: MlsMessage;
  /** The MLS-authenticated sender, decoded to a Nostr hex pubkey. */
  senderPubkey: string;
};

/**
 * An event whose MLS message was successfully processed. Discriminate the
 * application-message case (which carries `senderPubkey`) from the state-change
 * case via `result.kind`.
 */
export type ProcessedIngestResult =
  | ProcessedStateChangeIngestResult
  | ProcessedApplicationMessageIngestResult;

/** A commit that was rejected by the admin-verification callback */
export type CommitRejectedIngestResult = {
  kind: "rejected";
  /** Discriminates this rejection from an application-message authentication drop. */
  reason: "admin-policy";
  /** The result returned by processMessage (actionTaken === "reject") */
  result: ProcessMessageResult;
  /** The event that was rejected */
  event: NostrEvent;
  /** The MLS message that was rejected */
  message: MlsMessage;
};

/**
 * An application message dropped because its claimed sender failed MLS
 * authentication, or its bytes could not be deserialized. The decrypted payload
 * is deliberately NOT surfaced — only the sender attribution is (AC-OBSERVABLE-1).
 */
export type UnauthenticatedIngestResult = {
  kind: "rejected";
  /** Why the message was dropped. */
  reason: UnauthenticatedMessageReason;
  /** The event that was rejected */
  event: NostrEvent;
  /** The MLS-authenticated sender's Nostr hex pubkey (empty if unresolvable). */
  senderPubkey: string;
  /** The sender the rumor claimed; absent when the payload could not be deserialized. */
  claimedPubkey?: string;
};

/** An event that was rejected (not delivered) */
export type RejectedIngestResult =
  | CommitRejectedIngestResult
  | UnauthenticatedIngestResult;

/** An event that was skipped without processing */
export type SkippedIngestResult = {
  kind: "skipped";
  /** The event that was skipped */
  event: NostrEvent;
  /** The decoded MLS message */
  message: MlsMessage;
  /**
   * Why the event was skipped:
   * - `"past-epoch"` – commit belongs to an epoch we have already advanced past (no snapshot)
   * - `"wrong-wireformat"` – the MLS wireformat is unexpected for a group message
   * - `"self-echo"` – this event was sent by us; state was already advanced at send time
   * - `"self-echo-commit"` – re-delivery of the exact commit already applied (id or content-hash match)
   * - `"lost-race"` – competing commit is deterministically worse per MIP-03; current winner is kept
   */
  reason:
    | "past-epoch"
    | "wrong-wireformat"
    | "self-echo"
    | "self-echo-commit"
    | "lost-race";
};

/**
 * Describes a completed rollback to a prior epoch (MIP-03 fork resolution).
 *
 * `invalidatedMessages` and `messagesNeedingRefetch` are populated in S3.
 * S2 emits `RollbackInfo` with empty arrays for both fields.
 */
export interface RollbackInfo {
  /** The MLS group ID bytes. */
  groupId: Uint8Array;
  /** The epoch this rollback returned to. */
  targetEpoch: bigint;
  /** Nostr event ID of the winning commit that was re-applied. */
  newHeadCommitEventId: string;
  /** Event IDs of application messages invalidated by the rollback (populated in S3). */
  invalidatedMessages: string[];
  /** Event IDs of messages that need re-fetching after the rollback (populated in S3). */
  messagesNeedingRefetch?: string[];
}

/** An event that could not be decrypted or processed after all retry attempts */
export type UnreadableIngestResult = {
  kind: "unreadable";
  /** The event that could not be processed */
  event: NostrEvent;
  /** All errors captured across every retry attempt, in chronological order */
  errors: unknown[];
};

/** Result from ingesting a group event */
export type IngestResult =
  | ProcessedIngestResult
  | RejectedIngestResult
  | SkippedIngestResult
  | UnreadableIngestResult;

/**
 * The minimum interface for a group to store them MLS messages
 * Implementations should extend this with methods for querying and loading stored messages
 */
export interface BaseGroupHistory {
  /** Saves a new application message to the group history */
  saveMessage(message: Uint8Array): Promise<void>;
  /** Purge the group history, called when group is destroyed */
  purgeMessages(): Promise<void>;
}

/** Shape of the stored media in a {@link BaseGroupMedia} implementation */
export type StoredMedia = {
  /** Plaintext (decrypted) file bytes. */
  data: Uint8Array;
  /** The full MIP-04 attachment metadata associated with this blob. */
  attachment: MediaAttachment;
};

/** A factory function that creates a {@link BaseGroupHistory} instance for a group id */
export type GroupHistoryFactory<
  THistory extends BaseGroupHistory | undefined = undefined,
> = (groupId: Uint8Array) => THistory;

/** The minimal implementation of a group media store */
export interface BaseGroupMedia {
  /** Adds a new media entry to the group media store */
  addMedia(sha256: string, entry: StoredMedia): Promise<void>;
  /** Retrieves a media entry from the group media store */
  getMedia(sha256: string): Promise<StoredMedia | null>;
  /** Removes a media entry from the group media store */
  removeMedia(sha256: string): Promise<void>;
  /** Lists all media entries in the group media store */
  listMedia(): Promise<MediaAttachment[]>;
  /** Clears all media entries from the group media store */
  clearMedia(): Promise<void>;
}

/** A factory function that creates a {@link BaseGroupHistory} instance for a group id */
export type GroupMediaFactory<
  TMedia extends BaseGroupMedia | undefined = undefined,
> = (groupId: Uint8Array) => TMedia;

export type ProposalContext = {
  state: ClientState;
  ciphersuite: CiphersuiteImpl;
  groupData: MarmotGroupData;
};

/** A function that builds an MLS Proposal from group context */
export type ProposalAction<T extends Proposal | Proposal[]> = (
  context: ProposalContext,
) => Promise<T>;

/** A method that creates a {@link ProposalAction} from a set of arguments */
export type ProposalBuilder<
  Args extends unknown[],
  T extends Proposal | Proposal[],
> = (...args: Args) => ProposalAction<T>;

export type MarmotGroupOptions<
  THistory extends BaseGroupHistory | undefined = undefined,
  TMedia extends BaseGroupMedia | undefined = undefined,
> = {
  /** The key-value backend where serialized group state bytes are persisted */
  store: GenericKeyValueStore<SerializedClientState>;
  /** The signer used for the clients identity */
  signer: EventSigner;
  /** The ciphersuite implementation to use for the group */
  ciphersuite: CiphersuiteImpl;
  /** The nostr relay pool to use for the group. Should implement GroupNostrInterface for group operations. */
  network: NostrNetworkInterface;
  /** The storage interface for the groups application message history (optional) */
  history?: THistory | GroupHistoryFactory<THistory>;
  /**
   * Backend (or pre-wrapped store) for the plaintext blob cache used by
   * {@link MarmotGroup.decryptMedia}. Defaults to an in-memory cache when
   * not provided.
   */
  media?: TMedia | GroupMediaFactory<TMedia>;
  /**
   * Epoch snapshot store backend or factory.  When omitted, an in-memory
   * store is created automatically.  Used to retain pre-apply serialized
   * state for rollback and fork-resolution (see S2).
   */
  snapshots?: EpochSnapshotStoreBackend | EpochSnapshotStoreFactory;
  /**
   * Number of past epochs to retain in the snapshot store.  Older snapshots
   * are pruned on each state advance.  Defaults to `2`.
   */
  snapshotDepth?: number;
  /**
   * Number of past epochs whose outer encryption key material (exporter_secret)
   * to retain for lagging-member decryption.  A member that has advanced
   * `pastEpochDepth` or fewer epochs beyond an application message's epoch can
   * still decrypt it without triggering a rollback.
   *
   * Kept strictly bounded for forward secrecy: key material outside the window
   * is zeroed and removed on each epoch advance.  Defaults to `5` (MDK parity).
   */
  pastEpochDepth?: number;
};

/** Information about a welcome recipient */
export type WelcomeRecipient = {
  /** The recipient's Nostr public key */
  pubkey: string;
  /** The ID of KeyPackage event (kind 443) used for add operation */
  keyPackageEventId: string;
  /** The KeyPackage event (kind 443) used for add operation */
  keyPackageEvent: NostrEvent;
};

/**
 * Build an incoming-message callback that enforces MIP-03 "admin-only commits".
 *
 * Kept as a pure helper for test ergonomics and clearer policy control.
 */
export function createAdminCommitPolicyCallback(args: {
  ratchetTree: ClientState["ratchetTree"];
  adminPubkeys: string[];
  onUnverifiableCommit?: "reject" | "retry";
}): IncomingMessageCallback {
  const { ratchetTree, adminPubkeys, onUnverifiableCommit = "retry" } = args;

  return (incoming) => {
    if (incoming.kind === "proposal") return "accept";

    // Commit must be attributable to a concrete member leaf.
    const senderLeafIndexUnknown = incoming.senderLeafIndex;
    if (senderLeafIndexUnknown === undefined) return "reject";

    const senderLeafIndex: LeafIndex =
      typeof senderLeafIndexUnknown === "number"
        ? toLeafIndex(senderLeafIndexUnknown)
        : senderLeafIndexUnknown;

    try {
      const senderCredential = getCredentialFromLeafIndex(
        ratchetTree,
        senderLeafIndex,
      );
      const senderPubkey = getCredentialPubkey(senderCredential);

      // Admins may commit any proposal set.
      if (adminPubkeys.includes(senderPubkey)) return "accept";

      // Non-admin compatibility path:
      // - accept no-proposal commits (current ts-mls self-update shape), OR
      // - accept commits whose proposals are ONLY update proposals authored by sender.
      if (incoming.proposals.length === 0) return "accept";

      const isSelfUpdateOnly = incoming.proposals.every(
        (p) =>
          p.proposal.proposalType === defaultProposalTypes.update &&
          p.senderLeafIndex !== undefined &&
          Number(p.senderLeafIndex) === Number(senderLeafIndex),
      );

      return isSelfUpdateOnly ? "accept" : "reject";
    } catch {
      // "retry" here means we don't want to permanently reject the commit;
      // MarmotGroup.ingest() will treat processing errors as unreadable/retryable.
      if (onUnverifiableCommit === "retry") {
        throw new Error("unverifiable commit sender");
      }
      return "reject";
    }
  };
}

/** Map of events that can be emitted by a MarmotGroup */
export type MarmotGroupEvents<
  THistory extends BaseGroupHistory | undefined = any,
  TMedia extends BaseGroupMedia | undefined = any,
> = {
  /** Emitted when the group state is updated */
  stateChanged: (state: ClientState) => void;
  /**
   * Emitted when a new application message is received. After sender-authentication
   * enforcement this fires only for messages that passed the Marmot receiver check;
   * it may be deprecated in a later major in favor of `authenticatedApplicationMessage`.
   */
  applicationMessage: (message: Uint8Array) => void;
  /**
   * Emitted when an authenticated application message is received, carrying the
   * MLS-resolved sender so event-style consumers can bind their own author fields.
   */
  authenticatedApplicationMessage: (
    message: AuthenticatedApplicationMessage,
  ) => void;
  /**
   * Emitted when an application message is dropped because its claimed sender
   * failed MLS authentication (or its bytes could not be deserialized).
   */
  unauthenticatedMessage: (info: UnauthenticatedMessageInfo) => void;
  /** Emitted when the group state is saved */
  stateSaved: (group: MarmotGroup<THistory, TMedia>) => void;
  /** Emitted when the group is destroyed */
  destroyed: (group: MarmotGroup<THistory, TMedia>) => void;
  /** Emitted when history persistence fails (best-effort, non-blocking) */
  historyError: (error: Error) => void;
  /** Emitted after a MIP-03 rollback completes and the winning commit is applied */
  rollback: (info: RollbackInfo) => void;
};

/**
 * The main class for interacting with a MLS group
 * @template THistory - The type of the history store to use for the group, must implement the {@link BaseGroupHistory} interface. (Default is no history store)
 */
export class MarmotGroup<
  THistory extends BaseGroupHistory | undefined = undefined,
  TMedia extends BaseGroupMedia | undefined = undefined,
> extends EventEmitter<MarmotGroupEvents<THistory, TMedia>> {
  /** The key-value backend where serialized group state bytes are persisted */
  readonly store: GenericKeyValueStore<SerializedClientState>;

  /** The signer used for the clients identity */
  readonly signer: EventSigner;

  /** The ciphersuite implementation to use for the group */
  readonly ciphersuite: CiphersuiteImpl;

  /** The nostr relay pool to use for the group */
  readonly network: NostrNetworkInterface;

  /** The storage interface for the groups application message history */
  readonly history: THistory;

  /** The storage interface for the groups media */
  readonly media: TMedia;

  /** Whether group state has been modified */
  dirty = false;

  /** Internal ClientState */
  #state: ClientState;
  #groupData: MarmotGroupData | null = null;

  /** Epoch snapshot store backend */
  #snapshots: EpochSnapshotStoreBackend;
  /** Number of past epochs to retain in the snapshot store */
  #snapshotDepth: number;

  /**
   * Bounded ring of past epochs' outer encryption key material (exporter_secret),
   * keyed by epoch.  Used by the past-epoch decryption window to retry outer
   * ChaCha20-Poly1305 decryption against retained past-epoch keys (AC-PAST-1).
   * Pruned to `#pastEpochDepth` on each state advance for forward secrecy (AC-PAST-2).
   */
  readonly #pastEpochExporterSecrets = new Map<bigint, Uint8Array>();
  /** Number of past epochs whose exporter_secret to retain. Defaults to 5. */
  #pastEpochDepth: number;
  /**
   * ts-mls ClientConfig configured with `retainKeysForEpochs = #pastEpochDepth`
   * so that ts-mls also retains inner MLS-layer historicalReceiverData for the
   * same window depth.
   */
  #mlsClientConfig: ClientConfig;

  /**
   * Event IDs of application messages we sent ourselves, used to skip self-echoes in ingest()
   * NOTE: this is not persisted at the moment, its only in memory and used to skip self-echoes in ingest()
   */
  readonly #sentEventIds = new Set<string>();

  /** In-flight media decrypts keyed by plaintext SHA-256 hex. */
  readonly #decryptingMedia = new Map<string, Promise<StoredMedia>>();

  /**
   * Tracks application message event IDs by the epoch under which they were
   * decrypted. Used by the rollback path to identify invalidated messages.
   * Entries for epochs > rollback target are moved to RollbackInfo.invalidatedMessages
   * and removed from this map when a rollback occurs.
   */
  readonly #messagesByEpoch = new Map<bigint, string[]>();

  /**
   * Prune dead per-epoch message-tracking entries. A message can only be
   * invalidated by a rollback, and a rollback can only reach epochs for which
   * a snapshot still exists. Snapshots are pruned to `snapshotDepth`, so any
   * entry for an epoch at or below `keepAtOrBelowEpoch` (the same floor passed
   * to `#snapshots.prune`) can never be rolled back to again and is dead. This
   * keeps `#messagesByEpoch` bounded by `snapshotDepth` rather than growing one
   * entry per epoch for the lifetime of the group.
   */
  #pruneMessagesByEpoch(keepAtOrBelowEpoch: bigint): void {
    for (const ep of this.#messagesByEpoch.keys()) {
      if (ep <= keepAtOrBelowEpoch) {
        this.#messagesByEpoch.delete(ep);
      }
    }
  }

  /**
   * Records the current epoch's exporter_secret in the past-epoch ring, then
   * prunes entries that fall outside `#pastEpochDepth`.  Call this immediately
   * BEFORE advancing `this.state` to a new epoch so that the CURRENT epoch's key
   * is available for lagging-member decryption after the advance.
   *
   * Key material for epochs outside the window is actively zeroed (forward secrecy).
   */
  #recordAndPruneExporterSecret(epoch: bigint, secret: Uint8Array): void {
    // Store a copy — the caller's Uint8Array may be mutated by ts-mls zero-out.
    this.#pastEpochExporterSecrets.set(epoch, secret.slice());

    // Prune: keep only the `#pastEpochDepth` most-recent epochs.
    if (this.#pastEpochExporterSecrets.size > this.#pastEpochDepth) {
      const sortedEpochs = [...this.#pastEpochExporterSecrets.keys()].sort(
        (a, b) => (a < b ? -1 : 1),
      );
      const toPrune = sortedEpochs.slice(
        0,
        sortedEpochs.length - this.#pastEpochDepth,
      );
      for (const ep of toPrune) {
        const key = this.#pastEpochExporterSecrets.get(ep);
        if (key) {
          // Zero out the bytes before removing (forward secrecy).
          key.fill(0);
        }
        this.#pastEpochExporterSecrets.delete(ep);
      }
    }
  }

  get id() {
    return this.state.groupContext.groupId;
  }

  /** The group id as a hex string */
  idStr: string;

  /** Read the current group state */
  get state() {
    return this.#state;
  }
  get groupData() {
    // If not cached, extract the group data from the state
    if (!this.#groupData) this.#groupData = getMarmotGroupData(this.state);
    return this.#groupData;
  }
  get unappliedProposals() {
    return this.state.unappliedProposals;
  }

  /**
   * Overrides the current group state
   * @warning It is not recommended to use this
   */
  set state(newState: ClientState) {
    // Read new group data from the state
    this.#groupData = getMarmotGroupData(newState);

    // Set new state and mark as dirty
    this.#state = newState;
    this.dirty = true;
    this.emit("stateChanged", newState);
  }

  // Common accessors for marmot group data
  get relays() {
    return this.groupData?.relays;
  }

  private log: Debugger;

  constructor(
    state: ClientState,
    options: MarmotGroupOptions<THistory, TMedia>,
  ) {
    super();
    this.#state = state;
    this.store = options.store;
    this.signer = options.signer;
    this.ciphersuite = options.ciphersuite;
    this.network = options.network;

    // Create the history store (optional)
    if (options.history) {
      if (typeof options.history === "function") {
        this.history = options.history(this.id);
      } else {
        this.history = options.history;
      }
    } else {
      this.history = undefined as THistory;
    }

    // Create the media store
    if (options.media) {
      if (typeof options.media === "function") {
        this.media = options.media(this.id);
      } else {
        this.media = options.media;
      }
    } else {
      this.media = undefined as TMedia;
    }

    // Set useful fields
    this.idStr = bytesToHex(this.id);

    // Initialize snapshot store
    this.#snapshotDepth = options.snapshotDepth ?? 2;
    const snapshotsOpt = options.snapshots;
    if (!snapshotsOpt) {
      this.#snapshots = new InMemoryEpochSnapshotStore();
    } else if (typeof snapshotsOpt === "function") {
      this.#snapshots = snapshotsOpt(state.groupContext.groupId);
    } else {
      this.#snapshots = snapshotsOpt;
    }

    // Initialize past-epoch decryption window (AC-PAST-1, AC-PAST-2).
    this.#pastEpochDepth = options.pastEpochDepth ?? 5;
    this.#mlsClientConfig = {
      keyRetentionConfig: {
        ...defaultKeyRetentionConfig,
        retainKeysForEpochs: this.#pastEpochDepth,
      },
      lifetimeConfig: defaultLifetimeConfig,
      keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
      paddingConfig: defaultPaddingConfig,
    };

    this.log = logger.extend(`group:${this.idStr.slice(0, 8)}`);
  }

  /** Creates a new {@link MarmotGroup} instance from a {@link ClientState} object */
  static async fromClientState<
    THistory extends BaseGroupHistory | undefined = undefined,
    TMedia extends BaseGroupMedia | undefined = undefined,
  >(
    state: ClientState,
    options: Omit<MarmotGroupOptions<THistory, TMedia>, "ciphersuite"> & {
      cryptoProvider?: CryptoProvider;
    },
  ): Promise<MarmotGroup<THistory, TMedia>> {
    // Get the group's ciphersuite implementation
    // In v2, getCiphersuiteImpl is available on the cryptoProvider and takes a CiphersuiteName directly
    const cryptoProvider = options.cryptoProvider ?? defaultCryptoProvider;
    const cipherSuite = await cryptoProvider.getCiphersuiteImpl(
      state.groupContext.cipherSuite,
    );

    return new MarmotGroup(state, { ...options, ciphersuite: cipherSuite });
  }

  /**
   * Persists any pending changes to the group state in the store.
   *
   * @param force - When `true`, writes the current state even if `dirty` is
   *   `false`. Useful for persisting the initial state of a freshly constructed
   *   group (e.g. after `createGroup` / `joinGroupFromWelcome` / import) without
   *   having to mutate `dirty` externally.
   */
  async save(force = false) {
    if (!force && !this.dirty) return;

    const stateBytes = serializeClientState(this.state);
    await this.store.setItem(bytesToHex(this.id), stateBytes);
    this.dirty = false;
    this.emit("stateSaved", this);
  }

  /**
   * Performs a self-update commit (no proposals) to rotate this member's leaf key material.
   *
   * This is required by MIP-02 for forward secrecy after joining from a Welcome.
   *
   * Unlike {@link commit}, this operation is allowed for non-admin members.
   */
  async selfUpdate(): Promise<Record<string, PublishResponse>> {
    this.log("self-update commit");
    const groupData = this.groupData;
    if (!groupData) throw new NoMarmotGroupDataError();

    const relays = this.relays;
    if (!relays) throw new NoGroupRelaysError();

    // Create a commit with explicitly empty proposals. In ts-mls, this results in
    // a self-update commit that includes an UpdatePath (rotating leaf secrets).
    // Pass clientConfig so the inner-layer historicalReceiverData retention
    // matches pastEpochDepth — otherwise ts-mls's default (4) leaves locally
    // authored epoch advances with an outer exporter secret retained for 5
    // epochs but no inner receiver data for the fifth (AC-PAST-1).
    const { commit, newState } = await createCommit({
      context: {
        cipherSuite: this.ciphersuite,
        authService: marmotAuthService,
        clientConfig: this.#mlsClientConfig,
      },
      state: this.state,
      wireAsPublicMessage: false,
      ratchetTreeExtension: true,
      extraProposals: [],
    });

    const commitEvent = await createGroupEvent({
      message: commit,
      state: this.state,
      ciphersuite: this.ciphersuite,
    });

    const response = await this.network.publish(relays, commitEvent);
    if (!hasAck(response)) {
      throw new Error("Failed to publish commit event: no relay acknowledged");
    }

    // Snapshot pre-advance state (AC-SNAP-2).
    // Best-effort: a backend rejection must not abort an already-ACKed advance.
    const selfUpdateGroupIdHex = bytesToHex(this.id);
    const selfUpdateEpoch = this.state.groupContext.epoch;
    try {
      await this.#snapshots.set(selfUpdateGroupIdHex, selfUpdateEpoch, {
        groupId: this.id,
        epoch: selfUpdateEpoch,
        state: serializeClientState(this.state),
        appliedCommit: {
          eventId: commitEvent.id,
          createdAt: commitEvent.created_at,
          contentHash: mlsCommitContentHash(commit),
        },
      });
    } catch (snapErr) {
      this.log("snapshot set failed (non-fatal): %O", snapErr);
    }

    // Record the current epoch's exporter_secret before advancing (AC-PAST-1).
    this.#recordAndPruneExporterSecret(
      selfUpdateEpoch,
      this.state.keySchedule.exporterSecret,
    );

    // Advance local state after publish.
    this.state = newState;
    await this.save();

    // Prune old snapshots (AC-RET-1).  Best-effort: prune is cleanup only.
    try {
      await this.#snapshots.prune(
        selfUpdateGroupIdHex,
        selfUpdateEpoch - BigInt(this.#snapshotDepth),
      );
    } catch (pruneErr) {
      this.log("snapshot prune failed (non-fatal): %O", pruneErr);
    }
    // Keep per-epoch message tracking bounded alongside snapshot retention.
    this.#pruneMessagesByEpoch(selfUpdateEpoch - BigInt(this.#snapshotDepth));

    return response;
  }

  /**
   * Leaves the group by publishing a self-remove proposal for each of the
   * caller's leaf nodes, then purging all local group data from storage.
   *
   * Per RFC 9420 §12.4 a member cannot commit a Remove targeting their own
   * leaf. Instead, a Remove *proposal* is sent so that the next committer
   * (e.g. an admin calling {@link commit}) can include it and finalise the
   * departure. At least one relay must acknowledge the proposals before local
   * state is destroyed; if no relay acks, an error is thrown and local state
   * is preserved so the caller can retry.
   *
   * Unlike {@link commit}, this operation is allowed for non-admin members.
   *
   * @returns The relay publish responses for the leave proposal event(s).
   */
  async leave(): Promise<Record<string, PublishResponse>> {
    this.log("leave group");
    const groupData = this.groupData;
    if (!groupData) throw new NoMarmotGroupDataError();

    const relays = this.relays;
    if (!relays) throw new NoGroupRelaysError();

    // Resolve own pubkey and build self-remove proposals via the shared action.
    const ownPubkey = await this.signer.getPublicKey();
    const removeProposals = await proposeLeaveGroup(ownPubkey)({
      state: this.state,
      ciphersuite: this.ciphersuite,
      groupData,
    });

    // Publish one proposal event per leaf index (handles multi-device members).
    // RFC 9420 §12.4 forbids committing a Remove targeting own leaf, so we
    // send proposals and let the next admin commit pick them up.
    const responses: Record<string, PublishResponse> = {};
    for (const proposal of removeProposals) {
      const response = await this.sendProposal(proposal);
      Object.assign(responses, response);
    }

    if (!hasAck(responses)) {
      throw new Error(
        "Failed to publish leave proposals: no relay acknowledged. Local state preserved — retry leave() to try again.",
      );
    }

    // Purge all local group data (history, media, state store).
    await this.destroy();

    return responses;
  }

  /**
   * Creates and publishes a proposal as a private MLS message.
   * @returns Promise resolving to the publish response from the relays
   */
  async propose<Args extends unknown[], T extends Proposal | Proposal[]>(
    action: ProposalBuilder<Args, T>,
    ...args: Args
  ): Promise<Record<string, PublishResponse>>;
  async propose<Args extends unknown[], T extends Proposal | Proposal[]>(
    action: ProposalAction<T>,
  ): Promise<Record<string, PublishResponse>>;
  async propose<Args extends unknown[], T extends Proposal | Proposal[]>(
    ...args: Args
  ): Promise<Record<string, PublishResponse>> {
    const groupData = this.groupData;
    if (!groupData) throw new NoMarmotGroupDataError();

    const context: ProposalContext = {
      state: this.state,
      ciphersuite: this.ciphersuite,
      groupData: this.groupData,
    };

    let proposals: T;
    if (args.length === 1) {
      proposals = await (args[0] as ProposalAction<T>)(context);
    } else {
      proposals = await (args[0] as ProposalBuilder<Args, T>)(...args)(context);
    }

    if (!proposals) {
      throw new Error("Proposal is undefined. This should not happen.");
    }

    // Handle both single proposals and arrays of proposals
    const proposalArray = Array.isArray(proposals) ? proposals : [proposals];

    // Send all proposals and collect responses
    const responses: Record<string, PublishResponse> = {};
    for (const proposal of proposalArray) {
      const response = await this.sendProposal(proposal as Proposal);
      // Merge responses (later responses override earlier ones for the same relay)
      Object.assign(responses, response);
    }

    return responses;
  }

  /** Sends a proposal to the group relays */
  async sendProposal(
    proposal: Proposal,
  ): Promise<Record<string, PublishResponse>> {
    const { message, newState } = await createProposal({
      context: {
        cipherSuite: this.ciphersuite,
        authService: marmotAuthService,
        externalPsks: {},
      },
      state: this.state,
      proposal,
      wireAsPublicMessage: false,
    });

    // Wrap the message in a group event
    const proposalEvent = await createGroupEvent({
      message,
      state: this.state,
      ciphersuite: this.ciphersuite,
    });

    // Publish to the group's relays
    const relays = this.relays;
    if (!relays) throw new NoGroupRelaysError();

    const response = await this.network.publish(relays, proposalEvent);
    if (!hasAck(response)) {
      throw new Error(
        "Failed to publish proposal event: no relay acknowledged",
      );
    }

    // Advance local state only after at least one relay acknowledges the event.
    this.state = newState;
    await this.save();

    return response;
  }

  /**
   * Creates and sends an application message to the group.
   *
   * Application messages contain actual content shared within the group (e.g., chat messages,
   * reactions, etc.). The inner Nostr event (rumor) must be unsigned and will be serialized
   * according to the Marmot spec.
   *
   * @param rumor - The unsigned Nostr event (rumor) to send as an application message
   * @returns Promise resolving to the publish response from the relays
   */
  async sendApplicationRumor(
    rumor: Rumor,
  ): Promise<Record<string, PublishResponse>> {
    this.log("sending application rumor kind:%d", rumor.kind);
    // Serialize the Nostr event (rumor) to application data according to the Marmot spec
    const applicationData = serializeApplicationRumor(rumor);

    // Create the application message using ts-mls
    // In v2, createApplicationMessage takes a single params object with context
    const { newState, message } = await createApplicationMessage({
      context: {
        cipherSuite: this.ciphersuite,
        authService: marmotAuthService,
        externalPsks: {},
      },
      state: this.state,
      message: applicationData,
    });

    // Wrap the message in a group event
    // Use this.state (not newState) to get the exporter_secret for the current epoch
    const applicationEvent = await createGroupEvent({
      message,
      state: this.state,
      ciphersuite: this.ciphersuite,
    });

    // Track this event ID so ingest() can skip the self-echo without re-running
    // processMessage against an already-advanced ratchet (which would throw
    // "desired gen in the past").
    this.#sentEventIds.add(applicationEvent.id);

    // Track the message under the epoch it was sent at, so that if a later
    // rollback discards this branch the locally-sent message is reported in
    // RollbackInfo.invalidatedMessages alongside received ones (AC-MSG-1).
    const sentEpoch = this.state.groupContext.epoch;
    const sentEpochMsgs = this.#messagesByEpoch.get(sentEpoch) ?? [];
    sentEpochMsgs.push(applicationEvent.id);
    this.#messagesByEpoch.set(sentEpoch, sentEpochMsgs);

    // Save to history immediately so the sender sees their own message without
    // waiting for the relay echo to arrive and be ingested.
    if (this.history) {
      try {
        await this.history.saveMessage(applicationData);
      } catch (err) {
        this.emit("historyError", err as Error);
      }
    }

    // Update the group state after successful publish
    // Application messages update state for forward secrecy (key schedule rotation)
    this.state = newState;

    // Publish to the group's relays
    const relays = this.relays;
    if (!relays) throw new NoGroupRelaysError();
    const response = await this.network.publish(relays, applicationEvent);
    if (!hasAck(response)) {
      const errors = Object.values(response)
        .filter((r) => !r.ok && r.message)
        .map((r) => r.message)
        .join("; ");
      throw new Error(
        `Failed to publish application message: ${
          errors || "no relay acknowledged"
        }`,
      );
    }

    return response;
  }

  /**
   * Creates and sends a kind 9 chat message to the group.
   *
   * This is a convenience wrapper around {@link sendApplicationRumor} that constructs
   * the rumor for you. The message is encrypted via MLS and published as a kind 445
   * group event to the group's relays.
   *
   * @param content - The text content of the chat message
   * @param tags - Optional Nostr tags to include on the rumor
   * @returns Promise resolving to the publish response from the relays
   */
  async sendChatMessage(
    content: string,
    tags: string[][] = [],
  ): Promise<Record<string, PublishResponse>> {
    const pubkey = await this.signer.getPublicKey();
    const rumor: Rumor = {
      id: "",
      kind: 9,
      pubkey,
      created_at: unixNow(),
      content,
      tags,
    };
    rumor.id = getEventHash(rumor);
    return this.sendApplicationRumor(rumor);
  }

  /**
   * Creates a commit from proposals and sends it to the group.
   *
   * Proposal sources (can be combined):
   * - **`extraProposals`** — inline {@link Proposal} values and/or {@link ProposalAction}
   *   factories (each factory receives {@link ProposalContext}).
   * - **`proposalRefs`** — keys into `state.unappliedProposals` for proposals already
   *   held in state.
   *
   * If **`extraProposals`** or **`proposalRefs`** is present on `options` (including as
   * an empty array), the commit uses exactly the merged, resolved list in array order
   * (`extraProposals` first, then each ref in `proposalRefs`). Two empty arrays means a
   * no-proposal commit. If neither property is set, the MLS layer commits every proposal
   * currently in `state.unappliedProposals`.
   *
   * Requires a group admin. Publishes the commit to group relays and updates local state
   * after an ACK. When MLS returns a welcome and **`welcomeRecipients`** is non-empty,
   * sends gift-wrapped Welcome rumors (only after the commit ACK, per MIP-02).
   *
   * @returns Per-relay publish responses for the commit group event
   */
  async commit(options?: {
    /**
     * Flattened in order; function entries are async factories;
     * resolved proposals are ordered before any from `proposalRefs`.
     */
    extraProposals?: (
      | Proposal
      | ProposalAction<Proposal>
      | (Proposal | ProposalAction<Proposal>)[]
    )[];
    /** Lookup keys on `state.unappliedProposals`; an unknown key throws. */
    proposalRefs?: string[];
    /**
     * Per-recipient key-package metadata for MLS Welcome delivery after
     * adds; see {@link WelcomeRecipient}.
     */
    welcomeRecipients?: WelcomeRecipient[];
  }): Promise<Record<string, PublishResponse>> {
    this.log(
      "committing (%d extra proposals, %d recipients)",
      options?.extraProposals?.length ?? 0,
      options?.welcomeRecipients?.length ?? 0,
    );
    const groupData = this.groupData;
    if (!groupData) throw new NoMarmotGroupDataError();

    const actorPubkey = await this.signer.getPublicKey();
    if (!groupData.adminPubkeys.includes(actorPubkey)) {
      throw new Error("Not a group admin. Cannot commit proposals.");
    }

    const context: ProposalContext = {
      state: this.state,
      ciphersuite: this.ciphersuite,
      groupData: this.groupData,
    };

    // Build new proposals from extraProposals
    const newProposals: Proposal[] = [];
    if (options?.extraProposals && options.extraProposals.length > 0) {
      for (const item of options.extraProposals.flat()) {
        if (typeof item === "function") {
          newProposals.push(await item(context));
        } else {
          newProposals.push(item);
        }
      }
    }

    // Extract proposals from unappliedProposals using the provided references
    const selectedProposals: Proposal[] = [];
    if (options?.proposalRefs) {
      for (const ref of options.proposalRefs) {
        const proposalWithSender = this.state.unappliedProposals[ref];
        if (!proposalWithSender) {
          throw new Error(
            `Proposal reference not found in unappliedProposals: ${ref}`,
          );
        }
        selectedProposals.push(proposalWithSender.proposal);
      }
    }

    // Combine new proposals with selected proposals from unappliedProposals
    const allProposals = [...newProposals, ...selectedProposals];

    // Build options for createCommit
    const commitOptions: CreateCommitOptions = {
      // All messages should be private
      wireAsPublicMessage: false,
      ratchetTreeExtension: true,
    };

    // If the caller explicitly provided extraProposals or proposalRefs, use
    // exactly those (even if empty — that means "self-update, no proposals").
    // Only fall through to the "commit all unapplied" default when neither is set.
    if (options?.extraProposals || options?.proposalRefs) {
      commitOptions.extraProposals = allProposals;
    }

    // Create the commit
    // In v2, createCommit takes a single params object with context.
    // Pass clientConfig so inner-layer past-epoch retention matches
    // pastEpochDepth (see selfUpdate for the same rationale).
    const { commit, newState, welcome } = await createCommit({
      context: {
        cipherSuite: this.ciphersuite,
        authService: marmotAuthService,
        clientConfig: this.#mlsClientConfig,
      },
      state: this.state,
      ...commitOptions,
    });

    // Wrap the commit in a group event
    // Use this.state (not newState) to get the exporter_secret for the current epoch
    // This ensures all members at the current epoch can decrypt the commit
    const commitEvent = await createGroupEvent({
      message: commit,
      state: this.state,
      ciphersuite: this.ciphersuite,
    });

    // Publish to the group's relays.
    // MIP-02 REQUIRES: Commit MUST be published and acknowledged by relays BEFORE sending Welcome messages.
    // This ordering is critical for protocol correctness - new members must be able to fetch the commit
    // that added them before processing their Welcome.
    const relays = this.relays;
    if (!relays) throw new NoGroupRelaysError();
    const response = await this.network.publish(relays, commitEvent);
    if (!hasAck(response)) {
      const errors = Object.values(response)
        .filter((r) => !r.ok && r.message)
        .map((r) => r.message)
        .join("; ");
      throw new Error(
        `Failed to publish commit: ${errors || "no relay acknowledged"}`,
      );
    }

    // Snapshot pre-advance state (AC-SNAP-2).
    // Best-effort: a backend rejection must not abort an already-ACKed commit.
    const commitGroupIdHex = bytesToHex(this.id);
    const commitEpochBefore = this.state.groupContext.epoch;
    try {
      await this.#snapshots.set(commitGroupIdHex, commitEpochBefore, {
        groupId: this.id,
        epoch: commitEpochBefore,
        state: serializeClientState(this.state),
        appliedCommit: {
          eventId: commitEvent.id,
          createdAt: commitEvent.created_at,
          contentHash: mlsCommitContentHash(commit),
        },
      });
    } catch (snapErr) {
      this.log("snapshot set failed (non-fatal): %O", snapErr);
    }

    // Record the current epoch's exporter_secret before advancing (AC-PAST-1).
    this.#recordAndPruneExporterSecret(
      commitEpochBefore,
      this.state.keySchedule.exporterSecret,
    );

    // Update the group state after successful publish
    this.state = newState;

    // Persist local-authoritative epoch transition immediately.
    await this.save();

    // Prune old snapshots (AC-RET-1).  Best-effort: prune is cleanup only.
    try {
      await this.#snapshots.prune(
        commitGroupIdHex,
        commitEpochBefore - BigInt(this.#snapshotDepth),
      );
    } catch (pruneErr) {
      this.log("snapshot prune failed (non-fatal): %O", pruneErr);
    }
    // Keep per-epoch message tracking bounded alongside snapshot retention.
    this.#pruneMessagesByEpoch(commitEpochBefore - BigInt(this.#snapshotDepth));

    // If new users were added, send welcome events
    // The commit has been published and acked, so it's safe to send Welcomes now (MIP-02 compliance)
    if (
      welcome &&
      options?.welcomeRecipients &&
      options.welcomeRecipients.length > 0
    ) {
      this.log(
        "Sending Welcome messages to %d recipient(s)",
        options.welcomeRecipients.length,
      );

      // Send all welcome events in parallel
      // In v2, welcome is wrapped in MlsWelcomeMessage, need to access welcome.welcome
      const innerWelcome = welcome?.welcome;
      if (!innerWelcome) return response;

      const welcomeResults = await Promise.allSettled(
        options.welcomeRecipients.map(async (recipient) => {
          const welcomeRumor = createWelcomeRumor({
            welcome: innerWelcome,
            author: actorPubkey,
            groupRelays: groupData.relays,
            keyPackageEventId: recipient.keyPackageEventId,
            keyPackageEvent: recipient.keyPackageEvent,
          });

          // Gift wrap the welcome event to the newly added user
          const giftWrapEvent = await createGiftWrap({
            rumor: welcomeRumor,
            recipient: recipient.pubkey,
            signer: this.signer,
          });

          // Get the newly added user's inbox relays using the GroupNostrInterface
          // Fallback to group relays if inbox relays are not available
          let inboxRelays: string[];
          try {
            inboxRelays = await this.network.getUserInboxRelays(
              recipient.pubkey,
            );
            this.log("Retrieved inbox relays for recipient: %O", inboxRelays);
          } catch (error) {
            this.log(
              "Failed to get inbox relays for recipient %s...: %O",
              recipient.pubkey.slice(0, 16),
              error,
            );
            // Fallback to group relays
            inboxRelays = groupData.relays || [];
          }

          if (inboxRelays.length === 0) {
            throw new Error(
              `No relays available to send Welcome to recipient ${recipient.pubkey.slice(
                0,
                16,
              )}...`,
            );
          }

          // Welcome is the most critical delivery — new members can't join without it.
          const publishResult = await this.network.publish(
            inboxRelays,
            giftWrapEvent,
          );

          this.log("Gift wrap publish result: %O", publishResult);

          return publishResult;
        }),
      );

      // Surface welcome delivery failures so callers can detect and retry
      const failureDetails = welcomeResults
        .map((r, i) => ({
          result: r,
          recipient: options.welcomeRecipients![i],
        }))
        .filter(
          (
            x,
          ): x is {
            result: PromiseRejectedResult;
            recipient: WelcomeRecipient;
          } => x.result.status === "rejected",
        )
        .map((x) => {
          const msg =
            x.result.reason instanceof Error
              ? x.result.reason.message
              : String(x.result.reason);
          return `${x.recipient.pubkey.slice(0, 16)}…: ${msg}`;
        });

      if (failureDetails.length > 0) {
        this.log(
          "%d/%d Welcome(s) failed to deliver: %O",
          failureDetails.length,
          options.welcomeRecipients.length,
          failureDetails,
        );
        throw new Error(
          `Failed to deliver ${failureDetails.length}/${options.welcomeRecipients.length} Welcome message(s): ${failureDetails.join(
            "; ",
          )}`,
        );
      }
    }

    return response;
  }

  /**
   * Invites a user to the group using their KeyPackage event (kind 443).
   *
   * This method:
   * 1. Validates the KeyPackage event (kind 443)
   * 2. Validates that the credential identity matches the event pubkey
   * 3. Builds an Add proposal using the KeyPackage
   * 4. Commits the proposal
   * 5. After commit ack, sends a Welcome message to the invitee via NIP-59 gift wrap
   *
   * @param keyPackageEvent - The KeyPackage event (kind 443 or kind 30443) for the user to invite
   * @returns Promise resolving to the publish response from the relays
   * @throws Error if the event is not a key package kind or if the credential identity doesn't match
   */
  async inviteByKeyPackageEvent(
    keyPackageEvent: NostrEvent,
  ): Promise<Record<string, PublishResponse>> {
    // Validate the event is a KeyPackage event (kind 443 or kind 30443)
    if (
      keyPackageEvent.kind !== KEY_PACKAGE_KIND &&
      keyPackageEvent.kind !== ADDRESSABLE_KEY_PACKAGE_KIND
    ) {
      throw new Error(
        `inviteByKeyPackageEvent: Expected KeyPackage event kind ${KEY_PACKAGE_KIND} or ${ADDRESSABLE_KEY_PACKAGE_KIND}, got ${keyPackageEvent.kind}`,
      );
    }

    // Validate that the credential identity matches the event pubkey
    const keyPackage = getKeyPackage(keyPackageEvent);
    const credentialIdentity = getCredentialPubkey(
      keyPackage.leafNode.credential,
    );
    if (credentialIdentity !== keyPackageEvent.pubkey) {
      throw new Error(
        `inviteByKeyPackageEvent: Credential identity ${credentialIdentity} does not match event pubkey ${keyPackageEvent.pubkey}`,
      );
    }

    // Build the Add proposal using the existing proposeInviteUser function
    const proposalAction = proposeInviteUser(keyPackageEvent);

    // Commit with the proposal and explicit welcome recipient
    return await this.commit({
      extraProposals: [proposalAction],
      welcomeRecipients: [
        {
          pubkey: keyPackageEvent.pubkey,
          keyPackageEventId: keyPackageEvent.id,
          keyPackageEvent,
        },
      ],
    });
  }

  /**
   * Creates an incoming message callback that enforces admin-only commits.
   *
   * Per MIP-03, only admins can send commits. This callback:
   * - Accepts all proposals (they don't require admin privileges)
   * - For commits, verifies that the sender is in the group's admin list
   * - Rejects commits from non-admin senders
   *
   * @returns An IncomingMessageCallback that enforces admin verification
   */
  /**
   * Build an admin-verification callback bound to a SPECIFIC state. The
   * callback resolves the committing leaf against `state.ratchetTree` and
   * checks it against that state's admin set. Commit application advances the
   * epoch and rotates the tree, and the rollback path validates against a
   * past-epoch snapshot — so the callback MUST be derived from the exact state
   * the commit is processed against, never a stale this.state captured earlier.
   */
  private createAdminVerificationCallbackForState(
    state: ClientState,
  ): IncomingMessageCallback {
    const groupData = getMarmotGroupData(state);
    if (!groupData) {
      // If no group data, we can't verify - accept all (shouldn't happen in normal flow)
      return acceptAll;
    }

    return createAdminCommitPolicyCallback({
      ratchetTree: state.ratchetTree,
      adminPubkeys: groupData.adminPubkeys,
      onUnverifiableCommit: "retry",
    });
  }

  /**
   * Enforce the Marmot receiver check on a decrypted application message: the
   * rumor's claimed `pubkey` MUST match the MLS-authenticated sender resolved from
   * the leaf credential. Comparison is case-insensitive hex, because
   * `deserializeApplicationData` does not normalize and an honest client may emit
   * uppercase hex (AC-CASE-1). Never throws — the caller drops the message on any
   * non-`ok` verdict while still adopting MLS state for forward secrecy.
   */
  #authenticateApplicationMessage(
    result: Extract<ProcessMessageResult, { kind: "applicationMessage" }>,
  ):
    | { ok: true; senderPubkey: string }
    | {
        ok: false;
        reason: UnauthenticatedMessageReason;
        senderPubkey: string;
        claimedPubkey?: string;
      } {
    let senderPubkey: string;
    try {
      // Decode the epoch-correct leaf credential resolved by ts-mls (do NOT
      // re-resolve the leaf index against the current tree — that reintroduces
      // the past-epoch misattribution hazard the fork prevents).
      senderPubkey = getCredentialPubkey(result.senderCredential);
    } catch {
      // The sender's leaf credential is not a valid Nostr identity: unauthenticatable.
      return { ok: false, reason: "unauthenticated-sender", senderPubkey: "" };
    }

    let claimedPubkey: string;
    try {
      claimedPubkey = deserializeApplicationData(result.message).pubkey;
    } catch {
      return { ok: false, reason: "undeserializable", senderPubkey };
    }

    if (claimedPubkey.toLowerCase() !== senderPubkey.toLowerCase()) {
      return {
        ok: false,
        reason: "unauthenticated-sender",
        senderPubkey,
        claimedPubkey,
      };
    }
    return { ok: true, senderPubkey };
  }

  /**
   * ingests an array of group messages and applies commits to the group state.
   *
   * Processing happens in two stages:
   * 1. Process all non-commit messages (proposals, application messages)
   *    - If a message fails to process, it's added to unreadable for retry
   * 2. Process commits according to MIP-03 (sorted by epoch, timestamp, event id)
   *    - Commits advance the epoch and update the group state
   *
   * After both stages, recursively retry unreadable messages until no more can be read.
   * Events that can never be processed are yielded as {@link UnreadableIngestResult}.
   *
   * @param events - Array of Nostr events containing encrypted MLS messages
   * @yields IngestResult - The result of processing the event
   */
  async *ingest(
    events: NostrEvent[],
    options?: {
      /** Current retry attempt count (internal use) */
      retryCount?: number;
      /** Maximum number of retry attempts (default: 5) */
      maxRetries?: number;
      /**
       * @internal Flat list of `{ eventId, error }` entries accumulated across
       * all retry rounds.  Passed by reference so every recursive call appends
       * to the same array, giving the final unreadable yield the full history.
       */
      _errors?: Array<{ eventId: string; error: unknown }>;
    },
  ): AsyncGenerator<IngestResult> {
    // Each ingest call gets its own sub-namespace so concurrent or sequential
    // batches can be distinguished at a glance in debug output.
    const log = this.log.extend(`ingest:${Date.now().toString(36).slice(-5)}`);

    // Set default retry options
    const retryCount = options?.retryCount ?? 0;
    const maxRetries = options?.maxRetries ?? 5;
    const errorList: Array<{ eventId: string; error: unknown }> =
      options?._errors ?? [];

    if (retryCount === 0) {
      log("start – %d event(s), maxRetries=%d", events.length, maxRetries);
    } else {
      log(
        "retry %d/%d – %d event(s) remaining",
        retryCount,
        maxRetries,
        events.length,
      );
    }

    // Check if we've exceeded the maximum retry attempts.
    //
    // IMPORTANT: ingest() processes untrusted network input. If we throw here,
    // a single permanently-unreadable message (e.g. encrypted under an epoch we
    // can never decrypt, malformed ciphertext, spam) can DoS consumers.
    // Instead, stop retrying and yield the remaining events as unreadable.
    if (retryCount > maxRetries) {
      log(
        "max retries exceeded – yielding %d event(s) as unreadable",
        events.length,
      );
      for (const event of events) {
        yield {
          kind: "unreadable",
          event,
          errors: errorList
            .filter((e) => e.eventId === event.id)
            .map((e) => e.error),
        };
      }
      return;
    }
    // Early return if no events to process
    if (events.length === 0) return;

    // ============================================================================
    // STEP 1: Decrypt NIP-44 layer to get MLSMessages
    // ============================================================================
    // Each Nostr event contains an MLSMessage encrypted with NIP-44 using the
    // group's exporter_secret. We decrypt this first layer to get the actual
    // MLS message structure.

    const { read, unreadable: decryptFailed } = await decryptGroupMessages(
      events,
      this.state,
      this.ciphersuite,
    );

    log(
      "decryption: %d/%d readable, %d failed",
      read.length,
      events.length,
      decryptFailed.length,
    );

    // Record a decryption error for each event that failed the NIP-44 layer.
    for (const event of decryptFailed) {
      log("decrypt failed event:%s", event.id.slice(0, 8));
      errorList.push({
        eventId: event.id,
        error: new Error("Failed to decrypt group message"),
      });
    }

    // ============================================================================
    // STEP 1b: Past-epoch decryption window (AC-PAST-1, AC-PAST-2)
    // ============================================================================
    // A member that has advanced N epochs beyond the sender's epoch cannot decrypt
    // with the current exporter_secret.  If N <= pastEpochDepth, we can decrypt
    // using the retained past epoch's exporter_secret and then process the inner
    // MLS message through ts-mls (which uses historicalReceiverData for the inner
    // MLS-layer decryption).
    //
    // Only application messages are resolved here.  Past-epoch commits are passed
    // through to the regular commit processing path (Step 5) which handles them
    // via the rollback decision tree (S2 / AC-ROLL-*).
    // Tracks whether the past-epoch path mutated this.state (ts-mls advances the
    // secret tree on a successful application-message decrypt). If it did and the
    // batch is otherwise empty, we must persist before the early return below so a
    // restart/replay does not see stale state (otherwise history can duplicate or
    // sender-generation tracking breaks).
    let pastEpochProcessedAny = false;
    if (decryptFailed.length > 0 && this.#pastEpochExporterSecrets.size > 0) {
      // Sort retained epochs newest-first for efficient lookup (most likely match first).
      const retainedEpochs = [...this.#pastEpochExporterSecrets.keys()].sort(
        (a, b) => (a > b ? -1 : 1),
      );

      // Events remaining after past-epoch decryption attempts (still failed).
      const stillFailed: NostrEvent[] = [];

      for (const event of decryptFailed) {
        let decryptedMessage: MlsMessage | null = null;
        let matchedEpoch: bigint | undefined;

        for (const epoch of retainedEpochs) {
          const secret = this.#pastEpochExporterSecrets.get(epoch);
          if (!secret) continue;
          const msg = await tryDecryptGroupMessageEventWithExporterSecret(
            event,
            secret,
            this.ciphersuite,
          );
          if (msg !== null) {
            decryptedMessage = msg;
            matchedEpoch = epoch;
            break;
          }
        }

        if (decryptedMessage === null || matchedEpoch === undefined) {
          // Still unreadable after past-epoch window attempt.
          stillFailed.push(event);
          continue;
        }

        log(
          "past-epoch decrypt succeeded event:%s matched-epoch:%d",
          event.id.slice(0, 8),
          matchedEpoch,
        );

        // Only application messages are handled here (AC-PAST-1 / no-rollback rule).
        // Past-epoch commits pass through to the normal commit path.
        const isPastEpochAppMsg =
          decryptedMessage.wireformat === wireformats.mls_private_message &&
          decryptedMessage.privateMessage.contentType ===
            contentTypes.application;

        if (!isPastEpochAppMsg) {
          // Past-epoch commit or proposal: add to `read` so the regular
          // commit/proposal processing path handles it.
          read.push({ event, message: decryptedMessage });
          // Remove the earlier "Failed to decrypt" error so the event doesn't
          // show two errors if it later processes successfully.
          const errIdx = errorList.findIndex((e) => e.eventId === event.id);
          if (errIdx !== -1) errorList.splice(errIdx, 1);
          continue;
        }

        // Self-echo guard (mirrors Step 3): if this is our own application
        // message coming back via a relay echo, we already advanced this.state
        // at send time. Re-processing it against the (now advanced) ratchet
        // would throw "desired gen in the past" or duplicate local history.
        // The past-epoch window can decrypt our echo via a retained key, so the
        // guard must run here too — Step 3 never sees these events.
        if (this.#sentEventIds.delete(event.id)) {
          log(
            "skip past-epoch event:%s reason:self-echo",
            event.id.slice(0, 8),
          );
          // It decrypted, so drop the earlier "Failed to decrypt" error.
          const errIdx = errorList.findIndex((e) => e.eventId === event.id);
          if (errIdx !== -1) errorList.splice(errIdx, 1);
          yield {
            kind: "skipped",
            event,
            message: decryptedMessage,
            reason: "self-echo",
          };
          continue;
        }

        // Past-epoch application message: process through ts-mls so that
        // historicalReceiverData is used for inner MLS-layer decryption.
        // Critically: do NOT invoke the rollback path (AC-PAST-1).
        try {
          // decryptedMessage is narrowed to MlsPrivateMessage (wireformat check above),
          // which satisfies the MlsFramedMessage constraint of processMessage.
          const result = await processMessage({
            context: {
              cipherSuite: this.ciphersuite,
              authService: marmotAuthService,
              externalPsks: {},
              clientConfig: this.#mlsClientConfig,
            },
            state: this.state,
            message: decryptedMessage as MlsFramedMessage,
            callback: acceptAll,
          });

          if (result.kind === "applicationMessage") {
            log(
              "past-epoch application message event:%s epoch:%d",
              event.id.slice(0, 8),
              matchedEpoch,
            );

            // Adopt MLS state regardless of the authentication verdict: the
            // message was MLS-decrypted, consuming ratchet key material (forward
            // secrecy). "Drop" suppresses only history-save, yield, and emit —
            // never state adoption or the post-batch save() below (AC-STATE-1).
            this.state = result.newState;
            pastEpochProcessedAny = true;

            // The event decrypted, so drop the earlier "Failed to decrypt" error.
            const errIdx = errorList.findIndex((e) => e.eventId === event.id);
            if (errIdx !== -1) errorList.splice(errIdx, 1);

            const verdict = this.#authenticateApplicationMessage(result);
            if (verdict.ok) {
              // Track only delivered messages under the matched past epoch, so a
              // later rollback never asks consumers to invalidate a message they
              // never received (AC-OBSERVABLE-1).
              const epochMsgs = this.#messagesByEpoch.get(matchedEpoch) ?? [];
              epochMsgs.push(event.id);
              this.#messagesByEpoch.set(matchedEpoch, epochMsgs);

              // Persist to history if configured.
              if (this.history) {
                try {
                  await this.history.saveMessage(result.message);
                } catch (err) {
                  this.emit("historyError", err as Error);
                }
              }

              yield {
                kind: "processed",
                result,
                event,
                message: decryptedMessage,
                senderPubkey: verdict.senderPubkey,
              };
              this.emit("applicationMessage", result.message);
              this.emit("authenticatedApplicationMessage", {
                message: result.message,
                senderPubkey: verdict.senderPubkey,
                senderLeafIndex: result.senderLeafIndex,
              });
            } else {
              log(
                "dropped unauthenticated past-epoch message event:%s reason:%s",
                event.id.slice(0, 8),
                verdict.reason,
              );
              yield {
                kind: "rejected",
                reason: verdict.reason,
                event,
                senderPubkey: verdict.senderPubkey,
                ...(verdict.claimedPubkey !== undefined
                  ? { claimedPubkey: verdict.claimedPubkey }
                  : {}),
              };
              this.emit("unauthenticatedMessage", {
                reason: verdict.reason,
                event,
                senderPubkey: verdict.senderPubkey,
                ...(verdict.claimedPubkey !== undefined
                  ? { claimedPubkey: verdict.claimedPubkey }
                  : {}),
              });
            }
          } else {
            // Unexpected result kind for a past-epoch application message.
            // Leave in stillFailed for unreadable reporting.
            stillFailed.push(event);
          }
        } catch (processErr) {
          log(
            "past-epoch processMessage failed event:%s: %O",
            event.id.slice(0, 8),
            processErr,
          );
          errorList.push({ eventId: event.id, error: processErr });
          stillFailed.push(event);
        }
      }

      // Replace decryptFailed with only the events that are still unresolved.
      decryptFailed.length = 0;
      decryptFailed.push(...stillFailed);
    }

    // If nothing was readable the exporter_secret cannot change this round, so
    // retrying would always fail the same way.  Yield decrypt failures now.
    if (read.length === 0) {
      // Step 1b may have advanced this.state via a past-epoch application
      // message even though `read` is empty. Persist that advance before
      // returning so a restart does not replay against stale state.
      if (pastEpochProcessedAny) {
        await this.save();
        log(
          "state saved after past-epoch-only batch – epoch:%d",
          this.state.groupContext.epoch,
        );
      }
      log(
        "nothing readable – yielding %d decrypt failure(s) as unreadable",
        decryptFailed.length,
      );
      for (const event of decryptFailed) {
        yield {
          kind: "unreadable",
          event,
          errors: errorList
            .filter((e) => e.eventId === event.id)
            .map((e) => e.error),
        };
      }
      return;
    }

    // Collect events that need a retry after state advances (e.g. after a commit
    // rotates the exporter_secret so we can decrypt previously opaque events).
    const unreadable: NostrEvent[] = [...decryptFailed];

    // ============================================================================
    // STEP 2: Separate commits from non-commit messages
    // ============================================================================
    // We process non-commit messages first (proposals, application messages),
    // then process commits. This ensures proposals are in unappliedProposals
    // before commits try to reference them.

    let commits: Array<GroupMessagePair> = [];
    const nonCommits: Array<GroupMessagePair> = [];

    for (const pair of read) {
      if (
        pair.message.wireformat === wireformats.mls_private_message &&
        pair.message.privateMessage.contentType === contentTypes.commit
      ) {
        commits.push(pair);
      } else {
        nonCommits.push(pair);
      }
    }

    log(
      "split: %d commit(s), %d non-commit(s)",
      commits.length,
      nonCommits.length,
    );

    // ============================================================================
    // STEP 3: Process all non-commit messages
    // ============================================================================
    // Process all proposals and application messages. If a message fails to process
    // (wrong epoch, invalid, etc.), add it to unreadable for retry later.
    //
    // Proposals are added to state.unappliedProposals when processed, making them
    // available for commits to reference via ProposalRef.

    for (const { event, message } of nonCommits) {
      try {
        // Skip application messages that we sent ourselves.  When we sent the
        // message we already advanced this.state via the newState returned by
        // createApplicationMessage.  If we ran processMessage again against that
        // advanced ratchet the generation counter would be in the past and
        // ts-mls would throw "desired gen in the past".  History was already
        // saved at send time, so nothing is lost by skipping here.
        if (this.#sentEventIds.delete(event.id)) {
          log("skip event:%s reason:self-echo", event.id.slice(0, 8));
          yield { kind: "skipped", event, message, reason: "self-echo" };
          continue;
        }

        // Yield unexpected wireformats as skipped rather than silently ignoring them.
        if (
          message.wireformat !== wireformats.mls_private_message &&
          message.wireformat !== wireformats.mls_public_message
        ) {
          log("skip event:%s reason:wrong-wireformat", event.id.slice(0, 8));
          yield { kind: "skipped", event, message, reason: "wrong-wireformat" };
          continue;
        }

        // Past-epoch proposal routing (eventual convergence for proposal-ref
        // commits). A proposal for an epoch we already advanced past cannot be
        // applied to current state — but a competing commit that wins a rollback
        // to that epoch may reference it via ProposalRef. If we hold a snapshot
        // for the proposal's epoch, merge the proposal into THAT snapshot's
        // unappliedProposals so the later rollback validation can resolve the
        // reference. Without this, the late proposal would be processed against
        // current state (and fail), and the winning commit would stay stuck
        // unreadable forever.
        if (
          message.wireformat === wireformats.mls_private_message &&
          message.privateMessage.contentType === contentTypes.proposal
        ) {
          const proposalEpoch =
            typeof message.privateMessage.epoch === "bigint"
              ? message.privateMessage.epoch
              : BigInt(message.privateMessage.epoch);
          if (proposalEpoch < this.state.groupContext.epoch) {
            const pastGroupIdHex = bytesToHex(this.id);
            const pastSnap = await this.#snapshots.get(
              pastGroupIdHex,
              proposalEpoch,
            );
            if (pastSnap) {
              try {
                const snapState = deserializeClientState(pastSnap.state);
                const merged = await processMessage({
                  context: {
                    cipherSuite: this.ciphersuite,
                    authService: marmotAuthService,
                    externalPsks: {},
                    clientConfig: this.#mlsClientConfig,
                  },
                  state: snapState,
                  message,
                  callback: acceptAll,
                });
                if (merged.kind === "newState") {
                  await this.#snapshots.set(pastGroupIdHex, proposalEpoch, {
                    ...pastSnap,
                    state: serializeClientState(merged.newState),
                  });
                  log(
                    "past-epoch proposal event:%s merged into epoch-%d snapshot",
                    event.id.slice(0, 8),
                    proposalEpoch,
                  );
                  yield { kind: "processed", result: merged, event, message };
                  continue;
                }
              } catch (mergeErr) {
                log(
                  "past-epoch proposal event:%s could not merge into snapshot: %O",
                  event.id.slice(0, 8),
                  mergeErr,
                );
                // Fall through to the normal path (will likely be unreadable).
              }
            }
            // No snapshot for that epoch: nothing to merge into. Fall through;
            // the normal path will queue it unreadable for a later retry.
          }
        }

        // processMessage handles:
        // - Proposals: Adds them to state.unappliedProposals (keyed by proposal reference)
        // - Application messages: Decrypts content and returns it
        // - Both update state as needed (for forward secrecy)
        // In v2, processMessage takes a single params object with context.
        // Pass clientConfig so ts-mls retains historicalReceiverData for pastEpochDepth
        // epochs (inner MLS-layer past-epoch decryption support).
        const result = await processMessage({
          context: {
            cipherSuite: this.ciphersuite,
            authService: marmotAuthService,
            externalPsks: {},
            clientConfig: this.#mlsClientConfig,
          },
          state: this.state,
          message,
          callback: acceptAll, // Accept all proposals (adds them to unappliedProposals)
        });

        // Update state if message changed it
        if (result.kind === "newState") {
          log(
            "proposal accepted event:%s epoch:%d",
            event.id.slice(0, 8),
            this.state.groupContext.epoch,
          );
          this.state = result.newState;
          yield { kind: "processed", result, event, message };
        } else if (result.kind === "applicationMessage") {
          log("application message event:%s", event.id.slice(0, 8));
          const decryptEpoch = this.state.groupContext.epoch;

          // Adopt MLS state regardless of the authentication verdict (forward
          // secrecy — the ratchet key is already consumed). "Drop" suppresses
          // only history-save, yield, and emit (AC-STATE-1).
          this.state = result.newState;

          const verdict = this.#authenticateApplicationMessage(result);
          if (verdict.ok) {
            // Track only delivered messages under the current epoch for rollback
            // invalidation; a dropped message is never tracked (AC-OBSERVABLE-1).
            const epochMsgs = this.#messagesByEpoch.get(decryptEpoch) ?? [];
            epochMsgs.push(event.id);
            this.#messagesByEpoch.set(decryptEpoch, epochMsgs);

            // Save application message to history (best-effort)
            if (this.history) {
              try {
                await this.history.saveMessage(result.message);
              } catch (err) {
                this.emit("historyError", err as Error);
              }
            }

            yield {
              kind: "processed",
              result,
              event,
              message,
              senderPubkey: verdict.senderPubkey,
            };
            this.emit("applicationMessage", result.message);
            this.emit("authenticatedApplicationMessage", {
              message: result.message,
              senderPubkey: verdict.senderPubkey,
              senderLeafIndex: result.senderLeafIndex,
            });
          } else {
            log(
              "dropped unauthenticated message event:%s reason:%s",
              event.id.slice(0, 8),
              verdict.reason,
            );
            yield {
              kind: "rejected",
              reason: verdict.reason,
              event,
              senderPubkey: verdict.senderPubkey,
              ...(verdict.claimedPubkey !== undefined
                ? { claimedPubkey: verdict.claimedPubkey }
                : {}),
            };
            this.emit("unauthenticatedMessage", {
              reason: verdict.reason,
              event,
              senderPubkey: verdict.senderPubkey,
              ...(verdict.claimedPubkey !== undefined
                ? { claimedPubkey: verdict.claimedPubkey }
                : {}),
            });
          }
        }
      } catch (error) {
        // Message processing failed - might be invalid or from wrong epoch
        // Add to unreadable for retry later (might become readable after state updates)
        log(
          "non-commit failed event:%s – queued for retry: %O",
          event.id.slice(0, 8),
          error,
        );
        errorList.push({ eventId: event.id, error });
        unreadable.push(event);
      }
    }

    // ============================================================================
    // STEP 4: Sort commits to handle race conditions (MIP-03)
    // ============================================================================
    commits = sortGroupCommits(commits);

    // ============================================================================
    // STEP 5: Process commits sequentially
    // ============================================================================
    // Commits advance the epoch and update the group state. We process them in
    // sorted order. Each commit changes the epoch and rotates keys, so later
    // commits depend on earlier ones.

    // Admin verification callbacks are built per-commit from the EXACT state
    // each commit is processed against (see createAdminVerificationCallbackForState).
    // A single callback captured here would carry a stale ratchet tree once the
    // first commit advances state, or when the rollback path validates against a
    // past-epoch snapshot.

    for (const { event, message } of commits) {
      if (message.wireformat !== wireformats.mls_private_message) {
        log(
          "skip commit event:%s reason:wrong-wireformat",
          event.id.slice(0, 8),
        );
        yield { kind: "skipped", event, message, reason: "wrong-wireformat" };
        continue;
      }

      const commitEpoch =
        typeof message.privateMessage.epoch === "bigint"
          ? message.privateMessage.epoch
          : BigInt(message.privateMessage.epoch);

      // -----------------------------------------------------------------------
      // MIP-03 rollback decision tree for past-epoch commits
      //
      // A commit whose epoch < currentEpoch might be a competing commit we
      // raced against, not necessarily one we already applied.
      // -----------------------------------------------------------------------
      if (commitEpoch < this.state.groupContext.epoch) {
        const groupIdHex = bytesToHex(this.id);
        const snapshot = await this.#snapshots.get(groupIdHex, commitEpoch);

        if (!snapshot?.appliedCommit) {
          // No snapshot / no recorded competing commit → genuinely past; skip.
          log(
            "skip commit event:%s reason:past-epoch (commit=%d current=%d)",
            event.id.slice(0, 8),
            commitEpoch,
            this.state.groupContext.epoch,
          );
          yield { kind: "skipped", event, message, reason: "past-epoch" };
          continue;
        }

        // Replay guard: same commit re-delivered (our own echo or re-wrap).
        if (
          isReplayOfApplied(
            { id: event.id, contentHash: mlsCommitContentHash(message) },
            snapshot.appliedCommit,
          )
        ) {
          log(
            "skip commit event:%s reason:self-echo-commit",
            event.id.slice(0, 8),
          );
          yield { kind: "skipped", event, message, reason: "self-echo-commit" };
          continue;
        }

        // Lost-race guard: competing commit is deterministically worse.
        if (!isBetterCandidate(event, snapshot.appliedCommit)) {
          log(
            "skip commit event:%s reason:lost-race (commit=%d current=%d)",
            event.id.slice(0, 8),
            commitEpoch,
            this.state.groupContext.epoch,
          );
          yield { kind: "skipped", event, message, reason: "lost-race" };
          continue;
        }

        // The competing commit wins the MIP-03 *metadata* race. But
        // isBetterCandidate only inspects the outer Nostr envelope
        // (created_at / id), which a hostile sender fully controls. Apply the
        // winner against a throwaway deserialization of the epoch-N snapshot
        // FIRST — with an admin callback bound to that exact state — and only
        // mutate/persist this.state once it has genuinely applied. This makes
        // the rollback TRANSACTIONAL: a candidate that fails (invalid,
        // admin-rejected, or not-yet-applicable) leaves our current branch
        // completely untouched, so a hostile or premature commit can never
        // force a durable state regression.
        const candidateState = deserializeClientState(snapshot.state);
        const candidateCallback =
          this.createAdminVerificationCallbackForState(candidateState);
        let winnerResult: ProcessMessageResult | undefined;
        try {
          const probe = await processMessage({
            context: {
              cipherSuite: this.ciphersuite,
              authService: marmotAuthService,
              externalPsks: {},
              clientConfig: this.#mlsClientConfig,
            },
            state: candidateState,
            message,
            callback: candidateCallback,
          });
          if (probe.kind !== "newState") {
            // A commit that does not yield a new state is unprocessable here.
            yield { kind: "skipped", event, message, reason: "lost-race" };
            continue;
          }
          if (probe.actionTaken === "reject") {
            log(
              "rollback candidate event:%s rejected by admin policy – keeping current state",
              event.id.slice(0, 8),
            );
            yield {
              kind: "rejected",
              reason: "admin-policy",
              result: probe,
              event,
              message,
            };
            continue;
          }
          winnerResult = probe;
        } catch (probeErr) {
          // The winner may be only TEMPORARILY unverifiable — e.g. it
          // references a proposal that has not arrived yet. Queue it for retry
          // rather than dropping it as a permanent "lost-race", so eventual
          // convergence is preserved.
          log(
            "rollback candidate event:%s not yet applicable – queued for retry: %O",
            event.id.slice(0, 8),
            probeErr,
          );
          errorList.push({ eventId: event.id, error: probeErr });
          unreadable.push(event);
          continue;
        }

        if (winnerResult === undefined || winnerResult.kind !== "newState") {
          // Defensive: all non-success paths above already continued.
          yield { kind: "skipped", event, message, reason: "lost-race" };
          continue;
        }

        // Winner applied cleanly against the epoch-N snapshot. Commit the
        // rollback now — a single in-memory mutation, persisted by the save()
        // at the end of ingest(). We never write a half-rolled-back state.
        const loserEpoch = this.state.groupContext.epoch;
        const rollbackGroupIdHex = bytesToHex(this.id);

        // Tag the epoch-N snapshot with the WINNER as the applied commit so a
        // further competing commit for epoch N compares against what we kept.
        await this.#snapshots.set(rollbackGroupIdHex, commitEpoch, {
          groupId: this.id,
          epoch: commitEpoch,
          state: snapshot.state,
          appliedCommit: {
            eventId: event.id,
            createdAt: event.created_at,
            contentHash: mlsCommitContentHash(message),
          },
        });
        // Retain epoch-N's exporter secret for the past-epoch window
        // (idempotent — recorded when the loser was first applied).
        this.#recordAndPruneExporterSecret(
          commitEpoch,
          candidateState.keySchedule.exporterSecret,
        );

        // Single state mutation: adopt the winner branch.
        this.state = winnerResult.newState;
        log(
          "rollback event:%s wins MIP-03 race – converged epoch %d->%d",
          event.id.slice(0, 8),
          loserEpoch,
          this.state.groupContext.epoch,
        );

        // Collect application messages decrypted on the discarded loser branch
        // (epochs strictly above the target) and emit the rollback event.
        const invalidatedMessages: string[] = [];
        for (let ep = commitEpoch + 1n; ep <= loserEpoch; ep++) {
          const msgs = this.#messagesByEpoch.get(ep);
          if (msgs) {
            invalidatedMessages.push(...msgs);
            this.#messagesByEpoch.delete(ep);
          }
        }
        log(
          "emit rollback – targetEpoch:%d winner:%s invalidated:%d",
          commitEpoch,
          event.id.slice(0, 8),
          invalidatedMessages.length,
        );
        this.emit("rollback", {
          groupId: this.id,
          targetEpoch: commitEpoch,
          newHeadCommitEventId: event.id,
          invalidatedMessages,
        });

        // Bounded cleanup alongside snapshot retention.
        try {
          await this.#snapshots.prune(
            rollbackGroupIdHex,
            commitEpoch - BigInt(this.#snapshotDepth),
          );
        } catch (pruneErr) {
          this.log("snapshot prune failed (non-fatal): %O", pruneErr);
        }
        this.#pruneMessagesByEpoch(commitEpoch - BigInt(this.#snapshotDepth));

        yield { kind: "processed", result: winnerResult, event, message };
        continue;
      }

      const currentEpoch = this.state.groupContext.epoch;

      // Commits too far in the future can't be applied yet.
      // Add to unreadable so they are retried after state advances.
      if (commitEpoch > currentEpoch + 1n) {
        log(
          "defer commit event:%s epoch:%d too far ahead (current=%d)",
          event.id.slice(0, 8),
          commitEpoch,
          currentEpoch,
        );
        errorList.push({
          eventId: event.id,
          error: new Error(
            `Commit epoch ${commitEpoch} is too far ahead of current epoch ${currentEpoch}`,
          ),
        });
        unreadable.push(event);
        continue;
      }

      log(
        "processing commit event:%s epoch:%d->%d",
        event.id.slice(0, 8),
        currentEpoch,
        commitEpoch,
      );

      // Snapshot pre-apply state before processMessage (AC-SNAP-1).
      // Error propagates — we do NOT apply without a snapshot.
      const ingestGroupIdHex = bytesToHex(this.id);
      await this.#snapshots.set(ingestGroupIdHex, currentEpoch, {
        groupId: this.id,
        epoch: currentEpoch,
        state: serializeClientState(this.state),
        appliedCommit: {
          eventId: event.id,
          createdAt: event.created_at,
          contentHash: mlsCommitContentHash(message),
        },
      });

      // Record the current epoch's exporter_secret before the commit advances state
      // so lagging members can still decrypt application messages encrypted under
      // this epoch after the advance (AC-PAST-1).
      this.#recordAndPruneExporterSecret(
        currentEpoch,
        this.state.keySchedule.exporterSecret,
      );

      try {
        // processMessage handles:
        // - Decrypts the private message using group secrets from the current state
        // - Verifies message authenticity and sender
        // - Resolves proposal references from state.unappliedProposals (if needed)
        // - Applies the commit (updates ratchet tree, advances epoch, rotates keys)
        // In v2, processMessage takes a single params object with context.
        // Pass clientConfig so ts-mls retains historicalReceiverData for pastEpochDepth epochs.
        // The admin callback is built from THIS state (the one being processed) —
        // not a callback captured before earlier commits advanced the tree.
        const result = await processMessage({
          context: {
            cipherSuite: this.ciphersuite,
            authService: marmotAuthService,
            externalPsks: {},
            clientConfig: this.#mlsClientConfig,
          },
          state: this.state,
          message,
          callback: this.createAdminVerificationCallbackForState(this.state),
        });

        if (result.kind === "newState") {
          // If the commit was rejected by the callback (admin verification),
          // do not advance state and do not retry — yield it so callers can observe it.
          if (result.actionTaken === "reject") {
            log(
              "commit event:%s rejected by admin policy",
              event.id.slice(0, 8),
            );
            yield {
              kind: "rejected",
              reason: "admin-policy",
              result,
              event,
              message,
            };
            continue;
          }

          // Successfully processed the commit - update our state
          // After each commit, the epoch advances and keys rotate
          this.state = result.newState;
          log(
            "commit event:%s applied – new epoch:%d",
            event.id.slice(0, 8),
            this.state.groupContext.epoch,
          );

          // Prune old snapshots (AC-RET-1).
          // Prune failures must not poison the commit result: the commit has
          // already been applied, so treat this as best-effort cleanup.
          try {
            await this.#snapshots.prune(
              ingestGroupIdHex,
              currentEpoch - BigInt(this.#snapshotDepth),
            );
          } catch (pruneErr) {
            this.log("snapshot prune failed (non-fatal): %O", pruneErr);
          }
          // Keep per-epoch message tracking bounded alongside snapshot retention.
          this.#pruneMessagesByEpoch(
            currentEpoch - BigInt(this.#snapshotDepth),
          );

          yield { kind: "processed", result, event, message };
        }
      } catch (error) {
        // Commit processing failed - add to unreadable for retry
        // It might become valid after processing more proposals or state updates
        log(
          "commit failed event:%s – queued for retry: %O",
          event.id.slice(0, 8),
          error,
        );
        errorList.push({ eventId: event.id, error });
        unreadable.push(event);
      }
    }

    // Save the group state after processing all messages
    await this.save();
    log("state saved – epoch:%d", this.state.groupContext.epoch);

    // ============================================================================
    // STEP 6: Recursively retry unreadable events
    // ============================================================================
    // After processing commits and updating the state, some events that were
    // unreadable might now be readable. For example:
    // - An event from epoch N+1 might have been unreadable when we were at epoch N
    // - After processing a commit that advances us to epoch N+1, we can now read it
    //
    // We recursively call ingest on unreadable events to retry them.
    // This continues until no more events can be read.

    if (unreadable.length > 0) {
      log("scheduling retry for %d unreadable event(s)", unreadable.length);
      yield* this.ingest(unreadable, {
        retryCount: retryCount + 1,
        maxRetries: maxRetries,
        _errors: errorList,
      });
    } else {
      log("done – no unreadable events remain");
    }
  }

  /**
   * Encrypts a media file for sharing in a group message (MIP-04 v2).
   *
   * Derives the per-file key from the current MLS epoch, encrypts with
   * ChaCha20-Poly1305, and returns the ciphertext alongside a fully
   * populated {@link MediaAttachment} ready to be serialised into an
   * `imeta` tag via `createImetaTagForAttachment` from applesauce.
   *
   * **Caller responsibilities:**
   * 1. Upload `encrypted` to Blossom (or any content-addressed store).
   * 2. Set `attachment.url` to the resulting upload URL.
   * 3. Pass `attachment` (with `url`) to `createImetaTagForAttachment` and
   *    include the resulting tag on the group message rumor.
   */
  async encryptMedia(
    blob: Blob,
    metadata: {
      filename: string;
      type?: string;
      dimensions?: string;
      blurhash?: string;
      alt?: string;
      size?: number;
    },
  ): Promise<{ encrypted: Uint8Array; attachment: MediaAttachment }> {
    const mimeType = metadata.type ?? blob.type;
    if (!mimeType) {
      throw new Error(
        "encryptMedia: MIME type is required — pass metadata.type or ensure blob.type is set",
      );
    }

    const plaintext = new Uint8Array(await blob.arrayBuffer());
    const plaintextHash = bytesToHex(sha256(plaintext));

    const skeleton: MediaAttachment = {
      sha256: plaintextHash,
      type: canonicalizeMimeType(mimeType),
      filename: metadata.filename,
      nonce: "", // filled by encryptMediaFile
      version: MIP04_VERSION,
      size: metadata.size ?? blob.size,
      ...(metadata.dimensions !== undefined
        ? { dimensions: metadata.dimensions }
        : {}),
      ...(metadata.blurhash !== undefined
        ? { blurhash: metadata.blurhash }
        : {}),
      ...(metadata.alt !== undefined ? { alt: metadata.alt } : {}),
    };

    const fileKey = await deriveMediaEncryptionKey(
      this.state,
      this.ciphersuite,
      skeleton,
    );

    return encryptMediaFile(plaintext, fileKey, skeleton);
  }

  /**
   * Decrypts a MIP-04 v2 media attachment downloaded from Blossom.
   *
   * On the first call for a given file the plaintext bytes are derived via
   * key-derivation + ChaCha20-Poly1305 decryption and stored in
   * {`@link` media}. Subsequent calls for the same `attachment.sha256`
   * are served directly from the cache, skipping key-derivation entirely.
   */
  async decryptMedia(
    encrypted: Uint8Array,
    attachment: MediaAttachment,
  ): Promise<StoredMedia> {
    if (!attachment.sha256) {
      throw new Error("decryptMedia: attachment.sha256 is required");
    }

    // Cache hit — return immediately without re-deriving the key
    const cached = await this.media?.getMedia(attachment.sha256);
    if (cached) return cached;

    const inFlight = this.#decryptingMedia.get(attachment.sha256);
    if (inFlight) return inFlight;

    const decryptPromise = (async () => {
      const fileKey = await deriveMediaEncryptionKey(
        this.state,
        this.ciphersuite,
        attachment,
      );
      const plaintext = decryptMediaFile(encrypted, fileKey, attachment);

      await this.media?.addMedia(attachment.sha256, {
        data: plaintext,
        attachment,
      });

      return { data: plaintext, attachment };
    })();

    this.#decryptingMedia.set(attachment.sha256, decryptPromise);

    try {
      return await decryptPromise;
    } finally {
      this.#decryptingMedia.delete(attachment.sha256);
    }
  }

  /** Destroys the group and purges the group history */
  async destroy() {
    this.log("destroying group");

    this.log("clearing group history");
    if (this.history) await this.history.purgeMessages();

    this.log("clearing group media");
    if (this.media) await this.media.clearMedia();

    this.log("removing group from store");
    await this.store.removeItem(bytesToHex(this.id));

    // Clear epoch snapshots so persistent backends don't retain MLS secrets.
    this.log("clearing epoch snapshots");
    await this.#snapshots.clear(bytesToHex(this.id));

    // Zero and drop the past-epoch exporter-secret ring (forward secrecy) so
    // retained key material does not linger in memory after teardown.
    for (const key of this.#pastEpochExporterSecrets.values()) {
      key.fill(0);
    }
    this.#pastEpochExporterSecrets.clear();

    // Emit the destroyed event
    this.emit("destroyed", this);
  }
}
