/** @module @category Core - Group Messages */
import { Rumor } from "applesauce-common/helpers/gift-wrap";
import { finalizeEvent, NostrEvent } from "applesauce-core/helpers/event";
import { generateSecretKey } from "applesauce-core/helpers/keys";
import {
  ClientState,
  CiphersuiteImpl,
  contentTypes,
  decode,
  encode,
  mlsExporter,
  mlsMessageDecoder,
  mlsMessageEncoder,
  type MlsMessage,
  wireformats,
} from "ts-mls";
import { decodeContent, encodeContent } from "../utils/encoding.js";
import { unixNow } from "../utils/nostr.js";
import { decryptLegacyGroupMessageEventContent } from "./group-message-legacy.js";
import { getNostrGroupIdHex } from "./client-state.js";
import { GROUP_EVENT_KIND } from "./protocol.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { concatBytes, randomBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";

/**
 * Derives the MIP-03 group-event encryption key for a group epoch.
 *
 * Uses the MLS Exporter (RFC 9420 §8.5) with label "marmot" and context
 * "group-event" to produce a 32-byte ChaCha20-Poly1305 key.
 */
async function getGroupEventEncryptionKey(
  clientState: ClientState,
  ciphersuite: CiphersuiteImpl,
): Promise<Uint8Array> {
  return mlsExporter(
    clientState.keySchedule.exporterSecret,
    "marmot",
    new TextEncoder().encode("group-event"),
    32,
    ciphersuite,
  );
}

/**
 * Reads a {@link NostrEvent} and returns the {@link MlsMessage} it contains.
 * Decrypts group-event encrypted content using the exporter_secret from the group state.
 *
 * @param message - The Nostr event containing the encrypted MLS message
 * @param clientState - The ClientState for the group (to get exporter_secret)
 * @param ciphersuite - The ciphersuite implementation
 * @returns The decoded MlsMessage
 */
export async function decryptGroupMessageEvent(
  message: NostrEvent,
  clientState: ClientState,
  ciphersuite: CiphersuiteImpl,
): Promise<MlsMessage> {
  try {
    const key = await getGroupEventEncryptionKey(clientState, ciphersuite);
    const payload = decodeBase64(message.content);
    if (payload.length < 28) {
      throw new Error(
        "Malformed group event content: expected at least 28 bytes",
      );
    }

    const nonce = payload.subarray(0, 12);
    const ciphertext = payload.subarray(12);
    const serializedMessage = chacha20poly1305(
      key,
      nonce,
      new Uint8Array(0),
    ).decrypt(ciphertext);

    const decoded = decode(mlsMessageDecoder, serializedMessage);
    if (!decoded) throw new Error("Failed to decode MLS message");
    return decoded;
  } catch (primaryError) {
    try {
      return await decryptLegacyGroupMessageEventContent(
        message.content,
        clientState,
        ciphersuite,
      );
    } catch (legacyError) {
      throw new Error(
        `Failed to decrypt group message (new format and legacy fallback failed): ${formatError(primaryError)}; legacy: ${formatError(legacyError)}`,
      );
    }
  }
}

/**
 * Encrypts the content of a group event using MIP-03.
 *
 * @returns The encrypted content
 */
export async function createEncryptedGroupEventContent({
  state,
  ciphersuite,
  message,
}: {
  /** The ClientState for the group (to get exporter_secret) */
  state: ClientState;
  /** The ciphersuite implementation */
  ciphersuite: CiphersuiteImpl;
  /** The MLS message to encrypt */
  message: MlsMessage;
}): Promise<string> {
  const serializedMessage = encode(mlsMessageEncoder, message);
  const key = await getGroupEventEncryptionKey(state, ciphersuite);
  const nonce = randomBytes(12);
  const ciphertext = chacha20poly1305(key, nonce, new Uint8Array(0)).encrypt(
    serializedMessage,
  );
  return encodeBase64(concatBytes(nonce, ciphertext));
}

export type GroupMessagePair = {
  event: NostrEvent;
  message: MlsMessage;
};

/**
 * Attempts to decrypt a kind 445 event using a raw exporter_secret value.
 * Used by the past-epoch decryption window in MarmotGroup to retry outer-layer
 * (ChaCha20-Poly1305) decryption against a retained past epoch's exporter_secret.
 *
 * @param event - The Nostr event containing the encrypted MLS message
 * @param exporterSecret - The raw exporter_secret for the target epoch
 * @param ciphersuite - The ciphersuite implementation
 * @returns The decoded MlsMessage, or null if decryption fails
 */
export async function tryDecryptGroupMessageEventWithExporterSecret(
  event: NostrEvent,
  exporterSecret: Uint8Array,
  ciphersuite: CiphersuiteImpl,
): Promise<MlsMessage | null> {
  try {
    const key = await mlsExporter(
      exporterSecret,
      "marmot",
      new TextEncoder().encode("group-event"),
      32,
      ciphersuite,
    );
    const payload = decodeBase64(event.content);
    if (payload.length < 28) return null;
    const nonce = payload.subarray(0, 12);
    const ciphertext = payload.subarray(12);
    const serializedMessage = chacha20poly1305(
      key,
      nonce,
      new Uint8Array(0),
    ).decrypt(ciphertext);
    const decoded = decode(mlsMessageDecoder, serializedMessage);
    return decoded ?? null;
  } catch {
    return null;
  }
}

/**
 * Decrypts a kind 445 event and returns the {@link MlsMessage} it contains.
 *
 * @param event - The Nostr event containing the encrypted MLS message
 * @param clientState - The ClientState for the group (to get exporter_secret)
 * @param ciphersuite - The ciphersuite implementation
 * @returns The event and the decoded MlsMessage
 */
export async function decryptGroupMessage(
  event: NostrEvent,
  clientState: ClientState,
  ciphersuite: CiphersuiteImpl,
): Promise<GroupMessagePair> {
  const message = await decryptGroupMessageEvent(
    event,
    clientState,
    ciphersuite,
  );
  return { event, message };
}

/**
 * Decrypts multiple kind 445 events and returns the {@link MlsMessage} they contain.
 *
 * @param events - The Nostr events containing the encrypted MLS messages
 * @param clientState - The ClientState for the group (to get exporter_secret)
 * @param ciphersuite - The ciphersuite implementation
 * @returns An array of event and decoded MlsMessage pairs
 */
export async function decryptGroupMessages(
  events: NostrEvent[],
  clientState: ClientState,
  ciphersuite: CiphersuiteImpl,
): Promise<{ read: GroupMessagePair[]; unreadable: NostrEvent[] }> {
  const read: GroupMessagePair[] = [];
  const unreadable: NostrEvent[] = [];

  await Promise.all(
    events.map(async (event) => {
      try {
        read.push(await decryptGroupMessage(event, clientState, ciphersuite));
      } catch {
        unreadable.push(event);
      }
    }),
  );

  return { read, unreadable };
}

export type CreateGroupEventOptions = {
  /** The serialized MLS message */
  message: MlsMessage;
  /** The ClientState for the group */
  state: ClientState;
  /** The ciphersuite implementation */
  ciphersuite: CiphersuiteImpl;
};

/**
 * Creates a Nostr event containing an encrypted MLS message.
 *
 * @param options - The options for creating the event
 * @returns A signed Nostr event
 */
export async function createGroupEvent(
  options: CreateGroupEventOptions,
): Promise<NostrEvent> {
  const { message, state, ciphersuite } = options;

  const content = await createEncryptedGroupEventContent({
    state,
    ciphersuite,
    message,
  });
  const groupId = getNostrGroupIdHex(state);

  const draft = {
    kind: GROUP_EVENT_KIND,
    created_at: unixNow(),
    content,
    tags: [["h", groupId]],
  };

  // Ephemeral keypair for signing — distinct from the encryption keypair (MIP-03)
  const ephemeralSecretKey = generateSecretKey();

  return finalizeEvent(draft, ephemeralSecretKey);
}

/**
 * Serializes an application rumor (unsigned Nostr event) to bytes.
 * This is the format used for application messages in Marmot groups.
 *
 * @param rumor - The unsigned Nostr event to serialize
 * @returns The serialized application data as bytes
 */
export function serializeApplicationRumor(rumor: Rumor): Uint8Array {
  // Serialize the rumor to a JSON string
  const json = JSON.stringify(rumor);
  // Encode as UTF-8 bytes
  return new TextEncoder().encode(json);
}

/**
 * Deserializes application data bytes back into a rumor.
 *
 * @param data - The serialized application data
 * @returns The deserialized Rumor
 */
export function deserializeApplicationData(data: Uint8Array): Rumor {
  // Decode UTF-8 bytes to string
  const json = new TextDecoder().decode(data);
  // Parse JSON
  const parsed = JSON.parse(json);

  // Validate it's a rumor-like object
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Invalid application data: not an object");
  }

  // Check required fields for a rumor
  if (!parsed.id || !parsed.pubkey || parsed.kind === undefined) {
    throw new Error("Invalid application data: missing required fields");
  }

  return parsed as Rumor;
}

/** @deprecated Kept for internal compatibility. Prefer `deserializeApplicationData`. */
export const deserializeApplicationRumor = deserializeApplicationData;

/**
 * MIP-03 tiebreak: is `candidate` the deterministically better commit vs the
 * already-applied commit? Earliest created_at wins; on tie, lexicographically
 * smallest event id wins.
 */
export function isBetterCandidate(
  candidate: { id: string; created_at: number },
  applied: { eventId: string; createdAt: number },
): boolean {
  if (candidate.created_at !== applied.createdAt) {
    // Mutation note: `<` vs `<=` here is an equivalent mutant — the guard
    // above excludes equality, so the two operators are indistinguishable.
    return candidate.created_at < applied.createdAt;
  }
  return candidate.id < applied.eventId;
}

/**
 * SHA-256 over the serialized MLS message — the replay-guard content hash.
 *
 * The hash MUST be taken over the inner MLS message bytes, NOT the outer Nostr
 * `event.content`: `createGroupEvent` NIP-44-wraps the message with a fresh
 * nonce on every (re-)wrap, so the outer ciphertext differs each time even for
 * an identical commit. The serialized MLS message is deterministic for a given
 * commit, so a re-wrapped duplicate (our own relay echo, or a re-published
 * copy) produces the same hash and is correctly recognised as a replay.
 */
export function mlsCommitContentHash(message: MlsMessage): Uint8Array {
  return sha256(encode(mlsMessageEncoder, message));
}

/**
 * Replay guard: is `candidate` a re-delivery of the already-applied commit?
 * True when ids match, or when the content hashes match. Both hashes are taken
 * over the serialized MLS message via {@link mlsCommitContentHash}; callers
 * pass the already-computed candidate hash so this stays a pure comparison.
 */
export function isReplayOfApplied(
  candidate: { id: string; contentHash: Uint8Array },
  applied: { eventId: string; contentHash: Uint8Array },
): boolean {
  if (candidate.id === applied.eventId) return true;
  // Compare all bytes — do not short-circuit on mismatch.
  // Mutation note: the length guard and the loop-bound `<`/`<=` are equivalent
  // mutants — XOR against an out-of-range `undefined` byte never spuriously
  // produces a match, so dropping/loosening the guard yields the same result.
  if (candidate.contentHash.length !== applied.contentHash.length) return false;
  let diff = 0;
  for (let i = 0; i < candidate.contentHash.length; i++) {
    diff |= candidate.contentHash[i] ^ applied.contentHash[i];
  }
  return diff === 0;
}

/**
 * Sorts group commits to handle race conditions according to MIP-03.
 *
 * Sorting order (MIP-03):
 * 1. First, sort by commit time (created_at) - older commits first
 * 2. If equal, sort by event id (lexicographically) - lower id first
 *
 * @param commits - Array of commit message pairs to sort
 * @returns Sorted array of commits
 */
export function sortGroupCommits(
  commits: GroupMessagePair[],
): GroupMessagePair[] {
  return commits.sort((a, b) => {
    // Delegate to isBetterCandidate to keep a single MIP-03 comparator.
    // a before b means a is better, so if a is better return -1.
    const aIsBetter = isBetterCandidate(
      { id: a.event.id, created_at: a.event.created_at },
      { eventId: b.event.id, createdAt: b.event.created_at },
    );
    if (aIsBetter) return -1;
    const bIsBetter = isBetterCandidate(
      { id: b.event.id, created_at: b.event.created_at },
      { eventId: a.event.id, createdAt: a.event.created_at },
    );
    if (bIsBetter) return 1;
    return 0;
  });
}

/**
 * Creates a proposal event for a group.
 *
 * @param options - The options for creating the proposal event
 * @returns A signed Nostr event
 */
export async function createProposalEvent(
  options: CreateGroupEventOptions,
): Promise<NostrEvent> {
  return createGroupEvent(options);
}

/**
 * Creates a commit event for a group.
 *
 * @param options - The options for creating the commit event
 * @returns A signed Nostr event
 */
export async function createCommitEvent(
  options: CreateGroupEventOptions,
): Promise<NostrEvent> {
  return createGroupEvent(options);
}

/**
 * Checks if a message is an application message (not a proposal or commit).
 */
export function isApplicationMessage(
  pair: GroupMessagePair,
): pair is GroupMessagePair & {
  message: MlsMessage & { wireformat: typeof wireformats.mls_private_message };
} {
  if (pair.message.wireformat !== wireformats.mls_private_message) return false;
  return pair.message.privateMessage.contentType === contentTypes.application;
}

/**
 * Checks if a message is a commit message.
 */
export function isCommitMessage(
  pair: GroupMessagePair,
): pair is GroupMessagePair & {
  message: MlsMessage & { wireformat: typeof wireformats.mls_private_message };
} {
  if (pair.message.wireformat !== wireformats.mls_private_message) return false;
  return pair.message.privateMessage.contentType === contentTypes.commit;
}

/**
 * Checks if a message is a proposal message.
 */
export function isProposalMessage(
  pair: GroupMessagePair,
): pair is GroupMessagePair & {
  message: MlsMessage & { wireformat: typeof wireformats.mls_private_message };
} {
  if (pair.message.wireformat !== wireformats.mls_private_message) return false;
  return pair.message.privateMessage.contentType === contentTypes.proposal;
}

function decodeBase64(value: string): Uint8Array {
  try {
    return decodeContent(value, "base64");
  } catch (error) {
    throw new Error(
      `Invalid base64 group event content: ${formatError(error)}`,
    );
  }
}

function encodeBase64(value: Uint8Array): string {
  return encodeContent(value, "base64");
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
