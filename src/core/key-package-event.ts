/** @module @category Core - Key Package Event */
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import { EventTemplate, NostrEvent } from "applesauce-core/helpers/event";
import { Filter } from "applesauce-core/helpers/filter";
import {
  CiphersuiteId,
  ciphersuites,
  CustomExtension,
  decode,
  defaultCredentialTypes,
  encode,
  KeyPackage,
  keyPackageDecoder,
  keyPackageEncoder,
  protocolVersions,
} from "ts-mls";
import {
  decodeContent,
  encodeContent,
  getEncodingTag,
} from "../utils/encoding.js";
import { getTagValue, unixNow } from "../utils/nostr.js";
import { isValidRelayUrl, normalizeRelayUrl } from "../utils/relay-url.js";
import { getCredentialPubkey } from "./credential.js";
import { isGreaseValue } from "./grease.js";
import { calculateKeyPackageRef } from "./key-package.js";
import {
  ADDRESSABLE_KEY_PACKAGE_KIND,
  KEY_PACKAGE_CIPHER_SUITE_TAG,
  KEY_PACKAGE_CLIENT_TAG,
  KEY_PACKAGE_EXTENSIONS_TAG,
  KEY_PACKAGE_KIND,
  KEY_PACKAGE_MLS_VERSION_TAG,
  KEY_PACKAGE_RELAYS_TAG,
  KeyPackageClient,
  LAST_RESORT_EXTENSION_TYPE,
  MARMOT_GROUP_DATA_EXTENSION_TYPE,
  MLS_VERSIONS,
  REQUIRED_CIPHERSUITE_HEX,
  REQUIRED_CIPHERSUITE_ID,
  REQUIRED_MLS_VERSION,
} from "./protocol.js";

export const KEY_PACKAGE_PROPOSALS_TAG = "mls_proposals";
/** MIP-00: self_remove (0x000a) is the only non-default proposal Marmot mandates. */
export const MIP00_SELF_REMOVE_PROPOSAL = "0x000a";

const D_TAG_RE = /^[0-9a-f]{64}$/;

/**
 * Mints a MIP-00-conformant kind-30443 slot identifier:
 * 32 cryptographically random bytes encoded as 64 lowercase hex chars.
 * Use as the `d` tag value when publishing a fresh KeyPackage.
 */
export function generateKeyPackageSlot(): string {
  return bytesToHex(randomBytes(32));
}

export type DeleteKeyPackageEventInput = string | NostrEvent;

export type CreateDeleteKeyPackageEventOptions = {
  /** List of event ids (or full events) to delete */
  events: DeleteKeyPackageEventInput[];
};

/**
 * Creates a NIP-09 delete event (kind 5) to delete one or more key package
 * events (kind 443 or kind 30443).
 *
 * For kind 30443 events, both an `e` tag (event id) and an `a` tag
 * (addressable coordinate) are included so relays can match either way.
 * For kind 443 events, only an `e` tag is included (as before).
 * String-only inputs produce only `e` tags since no pubkey/d is available.
 */
export function createDeleteKeyPackageEvent(
  options: CreateDeleteKeyPackageEventOptions,
): EventTemplate {
  const { events } = options;
  if (!events || events.length === 0) {
    throw new Error("At least one event must be provided for deletion");
  }

  const eTags: string[][] = [];
  const aTags: string[][] = [];
  const kValues = new Set<string>();

  for (const e of events) {
    if (typeof e === "string") {
      // String id only — no kind info available, emit e tag without k inference
      eTags.push(["e", e]);
    } else {
      // TODO: Remove KEY_PACKAGE_KIND (443) acceptance after May 1, 2026
      if (
        e.kind !== KEY_PACKAGE_KIND &&
        e.kind !== ADDRESSABLE_KEY_PACKAGE_KIND
      ) {
        throw new Error(
          `Event ${e.id} is not a key package event (kind ${e.kind} instead of ${KEY_PACKAGE_KIND} or ${ADDRESSABLE_KEY_PACKAGE_KIND})`,
        );
      }
      kValues.add(String(e.kind));
      eTags.push(["e", e.id]);

      if (e.kind === ADDRESSABLE_KEY_PACKAGE_KIND) {
        const identifier = getKeyPackageIdentifier(e);
        if (identifier !== undefined) {
          aTags.push([
            "a",
            `${ADDRESSABLE_KEY_PACKAGE_KIND}:${e.pubkey}:${identifier}`,
          ]);
        }
      }
    }
  }

  // Build k tags from the set of observed kinds (for full NostrEvent inputs)
  // If only string ids were provided, fall back to tagging both known kinds
  const kTags: string[][] =
    kValues.size > 0
      ? [...kValues].map((k) => ["k", k])
      : [
          ["k", String(KEY_PACKAGE_KIND)],
          ["k", String(ADDRESSABLE_KEY_PACKAGE_KIND)],
        ];

  return {
    kind: 5,
    created_at: unixNow(),
    content: "",
    tags: [...kTags, ...eTags, ...aTags],
  };
}

/**
 * Decodes the MLS KeyPackage from a kind 443 or kind 30443 event.
 *
 * **SECURITY**: This is a decode-only function — it does NOT validate tag
 * compliance, identity binding, or `i` tag integrity. For untrusted events
 * (e.g. fetched from relays), use {@link validateKeyPackageEvent} or
 * {@link softValidateKeyPackageEvent} instead.
 */
export function getKeyPackage(event: NostrEvent): KeyPackage {
  const encodingFormat = getEncodingTag(event);
  if (encodingFormat !== "base64") {
    throw new Error(
      "KeyPackage event must include encoding=base64 tag (hex and missing tags are rejected)",
    );
  }
  const content = decodeContent(event.content, encodingFormat);
  const decoded = decode(keyPackageDecoder, content);
  if (!decoded) throw new Error("Failed to decode key package");

  return decoded;
}

/** Severity level for key package validation violations */
export type ValidationSeverity = "error" | "warning";

/** A single validation violation found during key package event validation */
export type KeyPackageViolation = {
  /** Which check failed (matches the 10 validation steps) */
  check: string;
  /** Human-readable description of the violation */
  message: string;
  /** Whether this violation is a hard error or a soft warning.
   *  "error" = the event is fundamentally broken (wrong kind, decode failure,
   *  identity spoofing). "warning" = MIP-00 non-compliance that doesn't
   *  prevent the key package from being used (missing tags, wrong ciphersuite
   *  value, etc). */
  severity: ValidationSeverity;
};

/** Result of soft validation — always returns a decoded KeyPackage when
 *  possible, plus any violations found. */
export type KeyPackageValidationResult = {
  /** The decoded KeyPackage, or null if decoding itself failed */
  keyPackage: KeyPackage | null;
  /** All violations found, ordered by check sequence */
  violations: KeyPackageViolation[];
};

/**
 * Collects all MIP-00 validation violations for a KeyPackage event.
 *
 * Unlike {@link validateKeyPackageEvent} (which throws on the first failure),
 * this function runs every check and returns all violations together. Checks
 * that would make the event completely unusable are marked `severity: "error"`;
 * the rest are `severity: "warning"`.
 *
 * Hard errors (severity "error"):
 *   1. Wrong event kind
 *   9. Credential identity does not match event pubkey (spoofing)
 *   10. `i` tag does not match computed KeyPackageRef (fabrication)
 *   Content decode failure
 *
 * Soft warnings (severity "warning"):
 *   2–8. Tag presence / format / value checks
 */
async function collectViolations(
  event: NostrEvent,
): Promise<KeyPackageValidationResult> {
  const violations: KeyPackageViolation[] = [];

  // 1. Event kind check — hard error
  // TODO: Remove KEY_PACKAGE_KIND (443) acceptance after May 1, 2026
  if (
    event.kind !== KEY_PACKAGE_KIND &&
    event.kind !== ADDRESSABLE_KEY_PACKAGE_KIND
  ) {
    violations.push({
      check: "event_kind",
      message: `Expected key package event (kind ${KEY_PACKAGE_KIND} or ${ADDRESSABLE_KEY_PACKAGE_KIND}), got kind ${event.kind}`,
      severity: "error",
    });
    return { keyPackage: null, violations };
  }

  // 2. D-tag validation for kind 30443
  if (event.kind === ADDRESSABLE_KEY_PACKAGE_KIND) {
    const dValue = getTagValue(event, "d");
    if (dValue === undefined) {
      violations.push({
        check: "d_tag_presence",
        message: "Missing required d tag for kind:30443 KeyPackage event",
        severity: "warning",
      });
    } else if (dValue === "") {
      violations.push({
        check: "d_tag_value",
        message: "d tag value must not be empty",
        severity: "warning",
      });
    } else if (!D_TAG_RE.test(dValue)) {
      violations.push({
        check: "d_tag_shape",
        message:
          "d tag must be exactly 64 lowercase hex characters " +
          "(MIP-00 §addressable-key-packages, MDK key_packages.rs)",
        severity: "warning",
      });
    }
  }

  // 3–4. Protocol version
  const version = getTagValue(event, KEY_PACKAGE_MLS_VERSION_TAG);
  if (version === undefined) {
    violations.push({
      check: "mls_protocol_version_presence",
      message: "Missing required tag: mls_protocol_version",
      severity: "warning",
    });
  } else if (version !== REQUIRED_MLS_VERSION) {
    violations.push({
      check: "mls_protocol_version_value",
      message: `Unsupported protocol version: ${version}. Only version ${REQUIRED_MLS_VERSION} is supported per MIP-00`,
      severity: "warning",
    });
  }

  // 5. Ciphersuite
  const ciphersuite = getTagValue(event, KEY_PACKAGE_CIPHER_SUITE_TAG);
  if (ciphersuite === undefined) {
    violations.push({
      check: "mls_ciphersuite_presence",
      message: "Missing required tag: mls_ciphersuite",
      severity: "warning",
    });
  } else if (!/^0x[0-9a-fA-F]{4}$/.test(ciphersuite)) {
    violations.push({
      check: "mls_ciphersuite_format",
      message: `Ciphersuite value must be 0x followed by 4 hex digits, got: ${ciphersuite}`,
      severity: "warning",
    });
  } else if (parseInt(ciphersuite) !== REQUIRED_CIPHERSUITE_ID) {
    violations.push({
      check: "mls_ciphersuite_value",
      message: `Unsupported ciphersuite: ${ciphersuite}. Only ${REQUIRED_CIPHERSUITE_HEX} (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) is supported`,
      severity: "warning",
    });
  }

  // 6. Extensions
  const extensionsTag = event.tags.find(
    (t) => t[0] === KEY_PACKAGE_EXTENSIONS_TAG,
  );
  if (!extensionsTag) {
    violations.push({
      check: "mls_extensions_presence",
      message: "Missing required tag: mls_extensions",
      severity: "warning",
    });
  } else {
    const extensionValues = extensionsTag.slice(1);
    if (extensionValues.length === 0) {
      violations.push({
        check: "mls_extensions_empty",
        message: "Extensions tag must have at least one value",
        severity: "warning",
      });
    } else {
      for (const extValue of extensionValues) {
        if (!/^0x[0-9a-fA-F]{4}$/.test(extValue)) {
          violations.push({
            check: "mls_extensions_format",
            message: `Extension value must be 0x followed by 4 hex digits, got: ${extValue}`,
            severity: "warning",
          });
        }
      }
      const normalizedExtensions = new Set(
        extensionValues.map((v) => v.toLowerCase()),
      );
      const requiredExtensions: Array<{ id: number; name: string }> = [
        { id: LAST_RESORT_EXTENSION_TYPE, name: "LastResort" },
        { id: MARMOT_GROUP_DATA_EXTENSION_TYPE, name: "MarmotGroupData" },
      ];
      for (const req of requiredExtensions) {
        const hex = `0x${req.id.toString(16).padStart(4, "0")}`;
        if (!normalizedExtensions.has(hex)) {
          violations.push({
            check: "mls_extensions_required",
            message: `Missing required extension: ${hex} (${req.name})`,
            severity: "warning",
          });
        }
      }
    }
  }

  // 7. Relays
  const relaysTag = event.tags.find((t) => t[0] === KEY_PACKAGE_RELAYS_TAG);
  if (!relaysTag) {
    violations.push({
      check: "relays_presence",
      message: "Missing required tag: relays",
      severity: "warning",
    });
  } else {
    const relayUrls = relaysTag.slice(1);
    if (relayUrls.length === 0) {
      violations.push({
        check: "relays_empty",
        message: "Relays tag must have at least one relay URL",
        severity: "warning",
      });
    } else {
      for (const url of relayUrls) {
        if (!isValidRelayUrl(url)) {
          violations.push({
            check: "relays_invalid_url",
            message: `Invalid relay URL: ${url}`,
            severity: "warning",
          });
        }
      }
    }
  }

  // 8. `i` tag
  const iTagValue = getTagValue(event, "i");
  if (iTagValue === undefined) {
    violations.push({
      check: "i_tag_presence",
      message: "Missing required tag: i",
      severity: "warning",
    });
  } else {
    if (iTagValue === "") {
      violations.push({
        check: "i_tag_empty",
        message: "i tag value must not be empty",
        severity: "warning",
      });
    } else if (!/^[0-9a-fA-F]+$/.test(iTagValue)) {
      violations.push({
        check: "i_tag_hex",
        message: "i tag must contain valid hex-encoded data",
        severity: "warning",
      });
    }
    const iTag = event.tags.find((t) => t[0] === "i");
    if (iTag && iTag.length !== 2) {
      violations.push({
        check: "i_tag_arity",
        message: "i tag must contain exactly one value",
        severity: "warning",
      });
    }
  }

  // 8.5. mls_proposals tag — required on kind 30443
  if (event.kind === ADDRESSABLE_KEY_PACKAGE_KIND) {
    const proposalsTag = event.tags.find(
      (t) => t[0] === KEY_PACKAGE_PROPOSALS_TAG,
    );
    if (!proposalsTag) {
      violations.push({
        check: "mls_proposals_presence",
        message: "Missing required tag: mls_proposals",
        severity: "warning",
      });
    } else if (
      proposalsTag.length !== 2 ||
      proposalsTag[1] !== MIP00_SELF_REMOVE_PROPOSAL
    ) {
      violations.push({
        check: "mls_proposals_value",
        message: 'Invalid mls_proposals tag value, expected "0x000a"',
        severity: "warning",
      });
    }
  }

  // Decode the key package (also validates encoding=base64)
  let keyPackage: KeyPackage;
  try {
    keyPackage = getKeyPackage(event);
  } catch (e) {
    violations.push({
      check: "content_decode",
      message: e instanceof Error ? e.message : String(e),
      severity: "error",
    });
    return { keyPackage: null, violations };
  }

  // 9. Credential identity binding — hard error (spoofing)
  if (
    keyPackage.leafNode.credential.credentialType !==
    defaultCredentialTypes.basic
  ) {
    violations.push({
      check: "credential_type",
      message:
        "Key package does not use a basic credential, cannot verify identity binding",
      severity: "error",
    });
  } else {
    const credentialPubkey = getCredentialPubkey(
      keyPackage.leafNode.credential,
    );
    if (credentialPubkey !== event.pubkey) {
      violations.push({
        check: "identity_binding",
        message: `Credential identity (${credentialPubkey}) does not match event pubkey (${event.pubkey})`,
        severity: "error",
      });
    }
  }

  // 10. `i` tag cross-verification — hard error (fabrication)
  if (iTagValue && /^[0-9a-fA-F]+$/.test(iTagValue)) {
    const computedRef = await calculateKeyPackageRef(keyPackage);
    const computedHex = bytesToHex(computedRef);
    if (iTagValue.toLowerCase() !== computedHex.toLowerCase()) {
      violations.push({
        check: "i_tag_mismatch",
        message:
          "KeyPackageRef in i tag does not match computed value from content",
        severity: "error",
      });
    }
  }

  return { keyPackage, violations };
}

/**
 * Validates and parses a KeyPackage event with full MIP-00 compliance checks.
 * Throws on the first violation found.
 *
 * For a non-throwing variant that collects warnings, use
 * {@link softValidateKeyPackageEvent}.
 *
 * Checks performed (in order):
 *
 * 1. Event kind must be 443 or 30443
 * 2. Kind 30443 events must have a non-empty `d` tag
 * 3. Required tags: `mls_protocol_version`, `mls_ciphersuite`, `mls_extensions`, `mls_proposals`, `relays`, `i`
 * 4. Protocol version must be "1.0"
 * 5. Ciphersuite must be 0x0001 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
 * 6. Extensions must include 0x000a (LastResort) and 0xf2ee (MarmotGroupData)
 * 7. Relays tag must contain at least one valid relay URL
 * 8. `i` tag must contain a single valid hex value
 * 9. Credential identity must match event pubkey (identity binding)
 * 10. `i` tag value must match computed KeyPackageRef (content verification)
 *
 * @param event - The key package event to validate
 * @returns The validated KeyPackage
 * @throws Error describing which validation failed
 */
export async function validateKeyPackageEvent(
  event: NostrEvent,
): Promise<KeyPackage> {
  const { keyPackage, violations } = await collectViolations(event);

  if (violations.length > 0) {
    throw new Error(violations[0].message);
  }

  // keyPackage is guaranteed non-null when there are no violations
  return keyPackage!;
}

/**
 * Validates a KeyPackage event and returns the result with any violations,
 * without throwing.
 *
 * Hard errors (`severity: "error"`) indicate the event is fundamentally broken
 * or potentially malicious (wrong kind, decode failure, identity spoofing,
 * fabricated `i` tag). Callers SHOULD reject events with any error-level
 * violations.
 *
 * Warnings (`severity: "warning"`) indicate MIP-00 non-compliance that doesn't
 * prevent the key package from being cryptographically usable (missing metadata
 * tags, wrong ciphersuite value, etc). Callers can log these and still proceed.
 *
 * @param event - The key package event to validate
 * @returns The validation result with decoded KeyPackage (if possible) and all
 *   violations found
 */
export async function softValidateKeyPackageEvent(
  event: NostrEvent,
): Promise<KeyPackageValidationResult> {
  return collectViolations(event);
}

/** Gets the MLS protocol version from a kind 443 or kind 30443 event */
export function getKeyPackageMLSVersion(
  event: NostrEvent,
): MLS_VERSIONS | undefined {
  const version = getTagValue(event, KEY_PACKAGE_MLS_VERSION_TAG);
  return version as MLS_VERSIONS | undefined;
}

/** Gets the MLS cipher suite from a kind 443 or kind 30443 event */
export function getKeyPackageCipherSuiteId(
  event: NostrEvent,
): CiphersuiteId | undefined {
  const cipherSuite = getTagValue(event, KEY_PACKAGE_CIPHER_SUITE_TAG);
  if (!cipherSuite) return undefined;

  const id = parseInt(cipherSuite) as CiphersuiteId;

  // Verify that cipher suite is a valid ID
  if (!(Object.values(ciphersuites) as number[]).includes(id)) {
    throw new Error(`Invalid MLS cipher suite ID ${id}`);
  }

  return id;
}

/** Gets the MLS extensions for a kind 443 or kind 30443 event */
export function getKeyPackageExtensions(
  event: NostrEvent,
): number[] | undefined {
  const tag = event.tags.find((t) => t[0] === KEY_PACKAGE_EXTENSIONS_TAG);
  if (!tag) return undefined;

  const ids = tag
    .slice(1)
    // NOTE: we are intentially not passing a radix to parseInt here so that it can handle base 10 and 16 (with leading 0x)
    .map((t) => parseInt(t))
    .filter((id) => Number.isFinite(id));

  return ids;
}

/** Gets the relays for a kind 443 or kind 30443 event */
export function getKeyPackageRelays(event: NostrEvent): string[] | undefined {
  const tag = event.tags.find((t) => t[0] === KEY_PACKAGE_RELAYS_TAG);
  if (!tag) return;
  return tag.slice(1).filter(isValidRelayUrl).map(normalizeRelayUrl);
}

/** Gets the client for a kind 443 or kind 30443 event */
export function getKeyPackageClient(
  event: NostrEvent,
): KeyPackageClient | undefined {
  const tag = event.tags.find((t) => t[0] === KEY_PACKAGE_CLIENT_TAG);
  if (!tag) return undefined;

  // TODO: parse the rest of the client tag
  return {
    name: tag[1],
  };
}

/**
 * Gets the addressable slot identifier (`d` tag) from a kind 30443 event.
 * Returns `undefined` for kind 443 events (which have no `d` tag).
 */
export function getKeyPackageIdentifier(event: NostrEvent): string | undefined {
  if (event.kind !== ADDRESSABLE_KEY_PACKAGE_KIND) return undefined;
  return getTagValue(event, "d");
}

export type CreateKeyPackageEventOptions = {
  keyPackage: KeyPackage;
  /**
   * The addressable slot identifier (`d` tag value). Required — callers must
   * supply this; {@link KeyPackageManager} handles defaulting to `clientId` or
   * throwing {@link MissingSlotIdentifierError} when none is available.
   */
  identifier: string;
  /** Relay URLs to advertise in the event */
  relays?: string[];
  client?: string;
  /**
   * Whether to include the NIP-70 protected tag (["-"]).
   *
   * Per MIP-00 this SHOULD be omitted by default because many relays reject
   * protected events.
   */
  protected?: boolean;
};

/**
 * Creates an addressable key package event (kind 30443) from a key package.
 *
 * @param options - The options for creating the key package event
 * @returns The unsigned key package event template
 */
export function createKeyPackageEvent(
  options: CreateKeyPackageEventOptions,
): Promise<EventTemplate> {
  return createKeyPackageEventInternal(options);
}

async function createKeyPackageEventInternal(
  options: CreateKeyPackageEventOptions,
): Promise<EventTemplate> {
  if (!options.identifier) {
    throw new Error(
      "d tag value must not be empty — kind 30443 events require a 64-char lowercase hex slot identifier (MIP-00). " +
        "Use generateKeyPackageSlot() to mint one.",
    );
  }
  if (!D_TAG_RE.test(options.identifier)) {
    throw new Error(
      `d tag value "${options.identifier}" is not a valid MIP-00 slot identifier (must match /^[0-9a-f]{64}$/). ` +
        'MDK rejects non-conformant slots with "d tag must be exactly 64 hex characters". ' +
        "Use generateKeyPackageSlot() to mint one.",
    );
  }

  const { keyPackage, relays, client } = options;

  // Serialize the key package according to RFC 9420
  const encodedBytes = encode(keyPackageEncoder, keyPackage);
  const content = encodeContent(encodedBytes, "base64");

  // Get the cipher suite from the key package
  // ts-mls v2: keyPackage.cipherSuite is a numeric id already
  const ciphersuiteHex = `0x${keyPackage.cipherSuite
    .toString(16)
    .padStart(4, "0")}`;

  // Extract extension types from the key package extensions
  const extensionTypes = keyPackage.extensions.map((ext: CustomExtension) => {
    // Extension type is now always a number in v2
    return `0x${ext.extensionType.toString(16).padStart(4, "0")}`;
  });

  // Also include extensions from leaf node capabilities to signal support
  // This ensures Marmot Group Data Extension (0xf2ee) is included in the event
  if (keyPackage.leafNode.capabilities?.extensions) {
    for (const extType of keyPackage.leafNode.capabilities.extensions) {
      // Only add if not already present (avoid duplicates)
      const hexValue = `0x${extType.toString(16).padStart(4, "0")}`;
      if (!extensionTypes.includes(hexValue)) {
        extensionTypes.push(hexValue);
      }
    }
  }

  // Filter out GREASE values from the extension types
  // We only want to include actual extensions (last_resort and Marmot Group Data Extension)
  const filteredExtensionTypes = extensionTypes.filter((hexValue) => {
    // Parse the hex value back to number to check if it's a GREASE value
    const extType = parseInt(hexValue);
    return !isGreaseValue(extType);
  });

  // Get the protocol version - keyPackage.version is a numeric ProtocolVersionValue
  // NIP tag expects a display string like "1.0".
  const versionName = (
    Object.keys(protocolVersions) as Array<keyof typeof protocolVersions>
  ).find((k) => protocolVersions[k] === keyPackage.version);
  const version = versionName === "mls10" ? "1.0" : String(keyPackage.version);

  // Build tags
  const tags: string[][] = [];

  // NIP-70: protected event — relay must not serve this event to non-authors.
  // NOTE: Optional/opt-in because many popular relays reject protected events.
  if (options.protected) tags.push(["-"]);

  // Addressable identifier (required for kind 30443)
  tags.push(["d", options.identifier]);

  tags.push(
    [KEY_PACKAGE_MLS_VERSION_TAG, version],
    [KEY_PACKAGE_CIPHER_SUITE_TAG, ciphersuiteHex],
    [KEY_PACKAGE_EXTENSIONS_TAG, ...filteredExtensionTypes],
    ["encoding", "base64"],
    // MIP-00: required non-default proposal type (self_remove). MDK enforces exactly two
    // entries with the second being "0x000a" (slice.len() == 2), so this is hard-coded.
    [KEY_PACKAGE_PROPOSALS_TAG, MIP00_SELF_REMOVE_PROPOSAL],
  );

  // MIP-00: required KeyPackageRef tag ("i")
  const keyPackageRef = await calculateKeyPackageRef(keyPackage);
  tags.push(["i", bytesToHex(keyPackageRef)]);

  // Add client tag if provided
  if (client) tags.push([KEY_PACKAGE_CLIENT_TAG, client]);

  // Add relay tags if provided
  if (relays && relays.length > 0) {
    const validRelays = relays.filter(isValidRelayUrl).map(normalizeRelayUrl);
    if (validRelays.length > 0) {
      tags.push([KEY_PACKAGE_RELAYS_TAG, ...validRelays]);
    }
  }

  return {
    kind: ADDRESSABLE_KEY_PACKAGE_KIND,
    created_at: unixNow(),
    content,
    tags,
  };
}

/**
 * Gets the nostr public key from a key package event.
 *
 * @param event - The key package event (kind 443 or kind 30443)
 * @returns The nostr public key (hex string)
 * @throws Error if the credential is not a basic credential
 */
export function getKeyPackageNostrPubkey(event: NostrEvent): string {
  const keyPackage = getKeyPackage(event);

  if (
    keyPackage.leafNode.credential.credentialType !==
    defaultCredentialTypes.basic
  ) {
    throw new Error(
      "Key package does not use a basic credential, cannot get nostr public key",
    );
  }

  return getCredentialPubkey(keyPackage.leafNode.credential);
}

/**
 * Returns the KeyPackageRef (MIP-00 `i` tag value) from a kind 443 or kind
 * 30443 KeyPackage event.
 *
 * Per MIP-00, new events MUST include this tag. Older events may not.
 */
export function getKeyPackageReference(event: NostrEvent): string | undefined {
  return getTagValue(event, "i");
}

/**
 * Selects the best KeyPackage event from a set of candidates for a given user.
 *
 * Selection criteria (in order):
 * 1. Reject events that are not kind 443 or 30443
 * 2. Reject events that fail KeyPackage decoding
 * 3. Prefer non-last_resort over last_resort candidates
 * 4. Among equal-priority candidates, prefer the newest created_at
 * 5. Tie-break by lexicographically smallest event id
 *
 * @param candidates - Array of NostrEvent objects to select from
 * @returns The best candidate NostrEvent, or null if no valid candidates exist
 */
export function selectBestKeyPackage(
  candidates: NostrEvent[],
): NostrEvent | null {
  type ValidCandidate = { event: NostrEvent; isLastResort: boolean };

  const valid: ValidCandidate[] = [];

  // TODO: Remove KEY_PACKAGE_KIND (443) acceptance after May 1, 2026
  for (const event of candidates) {
    if (
      event.kind !== KEY_PACKAGE_KIND &&
      event.kind !== ADDRESSABLE_KEY_PACKAGE_KIND
    ) {
      continue;
    }

    let keyPackage;
    try {
      keyPackage = getKeyPackage(event);
    } catch {
      continue;
    }

    const isLastResort = keyPackage.extensions.some(
      (ext) => ext.extensionType === LAST_RESORT_EXTENSION_TYPE,
    );

    valid.push({ event, isLastResort });
  }

  if (valid.length === 0) return null;

  const hasNonLastResort = valid.some((c) => !c.isLastResort);
  const pool = hasNonLastResort
    ? valid.filter((c) => !c.isLastResort)
    : valid;

  return pool.reduce((best, candidate) => {
    if (candidate.event.created_at > best.event.created_at) return candidate;
    if (candidate.event.created_at < best.event.created_at) return best;
    return candidate.event.id < best.event.id ? candidate : best;
  }).event;
}

/**
 * Returns Nostr filters that match both legacy (kind 443) and current
 * (kind 30443) KeyPackage events for the given authors.
 *
 * Use during the migration period to discover KeyPackages regardless of
 * whether the publishing client has upgraded.
 */
// TODO: Remove KEY_PACKAGE_KIND (443) filter after May 1, 2026
export function keyPackageFilters(authors: string[]): Filter[] {
  return [
    { kinds: [KEY_PACKAGE_KIND], authors },
    { kinds: [ADDRESSABLE_KEY_PACKAGE_KIND], authors },
  ];
}
