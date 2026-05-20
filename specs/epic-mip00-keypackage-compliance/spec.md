# Feature request: bring kind-30443 KeyPackage emission and validation into MIP-00 compliance

**Repository:** `941design/marmot-ts` (branch `addressable-key-packages`)
**Affected files:** `src/core/key-package-event.ts`, `src/client/key-package-manager.ts`
**Verified against:** `@internet-privacy/marmot-ts@0.5.1` (the `addressable-key-packages` branch HEAD as consumed by `notestr-web` master)
**Reporter:** triage from interactive debug session, 2026-05-20
**Severity:** **Interop-blocking.** Every kind-30443 KeyPackage produced by current `marmot-ts` is rejected by MDK's `parse_key_package`. Any Marmot consumer that uses MDK to validate KeyPackages — most importantly **`notestr-cli` and any other Rust-based admin client** — cannot invite a `marmot-ts`-published device into a group. The end-user-visible failure is "I signed into notestr-web on my phone, my desktop CLI cannot pull the phone into our group."
**Type:** Spec-compliance bug fix (two parts: tag emission + validator parity)
**Companion (consumer side):** `notestr-web@master` — `src/marmot/storage.ts` patched to mint MIP-00-conformant 64-hex client slots and migrate legacy slots on read. That patch is necessary but insufficient: the `mls_proposals` tag must be emitted by `marmot-ts` itself, since `createKeyPackageEvent` is the canonical event-build path.

---

## 1. Summary

Two independent gaps between `marmot-ts` and MIP-00 / MDK cause every kind-30443 event produced by `marmot-ts` to fail parsing in MDK:

1. **`mls_proposals` tag is never emitted.** MIP-00 makes `["mls_proposals", "0x000a"]` a required tag on kind-30443 events. `marmot-ts`'s `createKeyPackageEvent` does not emit any `mls_proposals` tag, and its own `parseKeyPackageEvent` validator does not check for one — so the omission is invisible inside the `marmot-ts` ecosystem and only surfaces when an MDK consumer parses the same wire bytes.

2. **`d` tag shape is not enforced.** MIP-00 mandates the `d` tag value be a cryptographically random 32-byte value encoded as 64 lowercase hex characters; MDK enforces this as a hard rejection (`D_TAG_HEX_LEN = 64`, ASCII hex only). `marmot-ts`'s `createKeyPackageEvent` accepts any non-empty string and emits it verbatim. `KeyPackageManager.create()` propagates the manager's `clientId` field straight into the `d` tag, so any consumer that passes a free-form identifier (e.g. `notestr-<uuid>`, an app name, a UUID without hex encoding) silently produces unparseable events. The validator does not check for hex shape either.

Both gaps are present on the emit side **and** the parse side. Fixing only one side leaves the divergence latent: the validator should fail on the same conditions MDK fails on, otherwise the next regression in the emit path goes undetected the same way this one did.

---

## 2. Background

### 2.1 What kind 30443 is for, briefly

Kind 30443 is the [addressable](https://github.com/nostr-protocol/nips/blob/master/01.md#kinds) variant of the legacy non-addressable kind 443 KeyPackage event. MIP-00 introduced it so a device can rotate its KeyPackage (used → replaced) without leaving a graveyard of one-shot KP events on relays — replaceable semantics keyed on `(pubkey, kind, d)` mean a `rotate()` collapses to a single live event per slot per device per pubkey.

The `d` tag is therefore load-bearing: it is the **slot identifier** that distinguishes one device's KeyPackages from a sibling device's KeyPackages under the same `pubkey`. MIP-00 specifies the slot as 32 cryptographically random bytes hex-encoded so the slot space is collision-free across the network without coordination.

### 2.2 What `mls_proposals` is for, briefly

The `mls_proposals` tag advertises the set of non-default MLS Proposal types this KeyPackage's owner supports. Default proposal types (Add, Update, Remove, PreSharedKey, ReInit, ExternalInit, GroupContextExtensions) MUST NOT be listed. MIP-00 currently requires implementations to declare support for exactly one non-default proposal, `self_remove (0x000a)`, which Marmot uses for the leaf-self-removal flow. Future MIP revisions may add more.

### 2.3 What `marmot-ts` currently emits

From `src/core/key-package-event.ts` `createKeyPackageEvent` (line ~640 onward, verified against `@internet-privacy/marmot-ts@0.5.1` dist):

```ts
const tags = [];
if (options.protected) tags.push(["-"]);
tags.push(["d", options.identifier]);
tags.push(
  [KEY_PACKAGE_MLS_VERSION_TAG, version],
  [KEY_PACKAGE_CIPHER_SUITE_TAG, ciphersuiteHex],
  [KEY_PACKAGE_EXTENSIONS_TAG, ...filteredExtensionTypes],
  ["encoding", "base64"],
);
const keyPackageRef = await calculateKeyPackageRef(keyPackage);
tags.push(["i", bytesToHex(keyPackageRef)]);
if (client) tags.push([KEY_PACKAGE_CLIENT_TAG, client]);
if (relays?.length) tags.push([KEY_PACKAGE_RELAYS_TAG, ...validRelays]);
```

There is no `mls_proposals` push. There is no shape check on `options.identifier` beyond a non-empty guard (`createKeyPackageEvent` line ~443):

```ts
if (!options.identifier) {
  throw new Error("d tag value must not be empty — kind 30443 events require a non-empty addressable identifier (NIP-33)");
}
```

The validator side (`parseKeyPackageEvent`, same file) checks for `mls_protocol_version`, `mls_ciphersuite`, `mls_extensions`, `relays`, `i` — but not `mls_proposals`, and the `d` tag check only enforces presence and non-emptiness, not the 64-hex shape (line ~115-128).

### 2.4 What MDK enforces

Verified from `parres-hq/mdk` — `crates/mdk-core/src/key_packages.rs`:

- **d-tag shape (lines ~75–90):** `D_TAG_HEX_LEN = 64`, exact length match, ASCII hex digits only. Rejection message: `"d tag must be exactly 64 hex characters"`.
- **`mls_proposals` presence and shape (lines ~415–431):** required on kind 30443. The tag value must satisfy `slice.len() == 2` and the second entry must equal `"0x000a"`. Rejection messages: `"Missing required tag: mls_proposals"` and `"Invalid mls_proposals tag value, expected 0x000a"`.

The MIP-00 text uses SHOULD for the 64-hex shape; MDK chose to enforce it as MUST. Whether to align by loosening MDK or by tightening MIP-00 is a coordination question with the MDK maintainers — see §8.5 below. Regardless of how that resolves, `marmot-ts` should match MDK in the meantime so events are accepted on the network as it is, not as the spec wishes it were.

---

## 3. Empirical evidence

Reproduction from `notestr-cli` against a real npub with one CLI device and several `notestr-web` browser sessions on the same identity:

```
notestr(cli)> list-kps npub10pen…
┌───────────────────────────────┬───────┬──────────────────────────────────────────────────┐
│         Slot (d tag)          │ Kind  │                   Parse result                   │
├───────────────────────────────┼───────┼──────────────────────────────────────────────────┤
│ 7075d9fa… (64-hex)            │ 30443 │ Invalid: Missing required tag: mls_proposals     │
│ 8e409a13… (64-hex) ×2         │ 30443 │ Invalid: Missing required tag: mls_proposals     │
│ c912f5dc… (64-hex)            │ 30443 │ ok — this is the CLI device                      │
│ notestr-079251af-… (44 chars) │ 30443 │ Invalid: d tag must be exactly 64 hex characters │
│ notestr-7236294c-… (44 chars) │ 30443 │ Invalid: d tag must be exactly 64 hex characters │
└───────────────────────────────┴───────┴──────────────────────────────────────────────────┘
```

Five `marmot-ts`-published slots, zero pass MDK. The only KP that parses is the CLI's own (MDK-built). Attempting `invite npub10pen…` (self-invite to bring a sibling device into a group) fails immediately with:

```
Error: [kp-watcher] add failed: Failed to add members:
       Duplicate signature key in proposals and group.
```

— because the CLI exhausts the candidate list, falls back to its own KP, and tries to re-add the leaf it is already publishing under. The user's mental model ("invite my own npub to sync my devices") becomes unreachable.

The two distinct failure modes correspond to two distinct historical formats of `notestr-web`'s `clientId`:

- **44-char `notestr-<uuid>`** — current `notestr-web@master` format prior to this fix, generated as `` `notestr-${crypto.randomUUID()}` ``. Fails the 64-hex check.
- **64-hex** — generated by a different code path (likely the in-fork `KeyPackageManager.rotate()` fallback at `key-package-manager.ts:367`, `bytesToHex(randomBytes(32))`). Passes the 64-hex check, fails on the missing `mls_proposals` tag.

Both modes are produced by current `marmot-ts`. The fork's emit path is wrong in both shapes.

---

## 4. Gap analysis

### 4.1 Emission gaps in `createKeyPackageEvent`

| Gap | Current behavior | Required behavior |
|---|---|---|
| `mls_proposals` not emitted | tag absent from output | Always emit `["mls_proposals", "0x000a"]` on kind-30443 events |
| `d` tag shape not enforced | accepts any non-empty string | Reject non-64-hex `identifier` with a clear error, **or** auto-generate when caller passes no identifier |

### 4.2 Validator gaps in `parseKeyPackageEvent`

| Gap | Current behavior | Required behavior |
|---|---|---|
| `mls_proposals` not validated | tag absence is silently accepted on kind 30443 | Add presence check (kind 30443 only) and value check (exactly `["mls_proposals", "0x000a"]`) |
| `d` tag shape not validated | only presence + non-empty checked | Add `/^[0-9a-f]{64}$/` check (kind 30443 only) |

### 4.3 Manager-level gap

`KeyPackageManager.clientId` is typed as `string | undefined` and threaded straight into `createKeyPackageEvent`'s `identifier` field in `.create()` (`key-package-manager.ts:292`). Consumers naturally reach for "a stable string identifying this device" (app name, UUID, hostname-userid combination) and have no signal that the value has cryptographic shape requirements. This is the **proximate cause** of how the bug landed in `notestr-web`: a consumer treated `clientId` as a free-form label.

The downstream consequence: even after this fix lands, any new consumer that supplies a non-conforming `clientId` will hit the `createKeyPackageEvent` validation error. That's the intended outcome (fail loud rather than silently produce broken events), but the API surface still encourages the mistake. See §8.3 for an open design question on renaming or repurposing this field.

---

## 5. Proposed changes

### 5.1 Emit `mls_proposals` (mandatory)

`src/core/key-package-event.ts` — inside `createKeyPackageEvent`, after the `mls_protocol_version` / `mls_ciphersuite` / `mls_extensions` / `encoding` push and before the `i` tag push:

```ts
// MIP-00: required mls_proposals tag. Advertises supported non-default
// MLS proposal types. The only non-default proposal Marmot mandates is
// self_remove (0x000a); default proposal types MUST NOT be listed.
// MDK's validator enforces exactly two entries with the second being
// "0x000a" (slice.len() == 2), so the tag is hard-coded for now and
// can be parameterized if MIP-00 adds further required proposals.
tags.push([KEY_PACKAGE_PROPOSALS_TAG, MIP00_SELF_REMOVE_PROPOSAL]);
```

In the same file's tag-constants block:

```ts
export const KEY_PACKAGE_PROPOSALS_TAG = "mls_proposals";
/** MIP-00 mandates support for the self_remove proposal type (0x000a). */
export const MIP00_SELF_REMOVE_PROPOSAL = "0x000a";
```

### 5.2 Enforce 64-hex `d` tag in `createKeyPackageEvent`

Replace the existing non-empty check:

```ts
const D_TAG_RE = /^[0-9a-f]{64}$/;

if (!options.identifier) {
  throw new Error(
    "d tag value must not be empty — kind 30443 events require a 64-char " +
    "lowercase hex slot identifier (MIP-00 §addressable-key-packages). " +
    "Use generateKeyPackageSlot() to mint one.",
  );
}
if (!D_TAG_RE.test(options.identifier)) {
  throw new Error(
    `d tag value "${options.identifier}" is not a valid MIP-00 slot ` +
    `identifier (must match /^[0-9a-f]{64}$/). MDK rejects non-conformant ` +
    `slots with "d tag must be exactly 64 hex characters". ` +
    "Use generateKeyPackageSlot() to mint one.",
  );
}
```

### 5.3 Add `generateKeyPackageSlot()` helper

Export from `src/core/key-package-event.ts`:

```ts
/**
 * Mints a MIP-00-conformant kind-30443 slot identifier:
 * 32 cryptographically random bytes encoded as 64 lowercase hex chars.
 *
 * Use as the `d` tag value when publishing a fresh KeyPackage. The
 * resulting slot is collision-free across the network (2^256 space)
 * and accepted by every MIP-00-compliant validator including MDK.
 */
export function generateKeyPackageSlot(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}
```

`KeyPackageManager.create()` and `.rotate()` should call this when the caller does not supply an explicit slot — replacing the existing `bytesToHex(randomBytes(32))` inline mint at `key-package-manager.ts:367` and removing the implicit "use `this.clientId` verbatim" fallback at line 292 with a `D_TAG_RE.test(this.clientId)` guard plus the `generateKeyPackageSlot()` fallback. (See §8.3 for a deeper open question on the manager's `clientId` field.)

### 5.4 Tighten `parseKeyPackageEvent`

Add two new validation checks, both gated on `event.kind === 30443` so legacy kind-443 events (pre-addressable) are unaffected:

```ts
// d-tag must be exactly 64 lowercase hex characters on kind 30443
if (event.kind === 30443) {
  const dValue = getTagValue(event, "d");
  if (dValue !== undefined && !D_TAG_RE.test(dValue)) {
    errors.push({
      check: "d_tag_shape",
      message:
        'd tag must be exactly 64 lowercase hex characters ' +
        '(MIP-00 §addressable-key-packages, MDK key_packages.rs)',
    });
  }
}

// mls_proposals tag must be present and equal ["mls_proposals", "0x000a"]
if (event.kind === 30443) {
  const proposalsTag = event.tags.find(
    (t) => t[0] === KEY_PACKAGE_PROPOSALS_TAG,
  );
  if (!proposalsTag) {
    errors.push({
      check: "mls_proposals_presence",
      message: "Missing required tag: mls_proposals",
    });
  } else if (
    proposalsTag.length !== 2 ||
    proposalsTag[1] !== MIP00_SELF_REMOVE_PROPOSAL
  ) {
    errors.push({
      check: "mls_proposals_value",
      message: 'Invalid mls_proposals tag value, expected "0x000a"',
    });
  }
}
```

Error message strings deliberately match MDK's wording so consumers searching logs across implementations see the same text.

### 5.5 Update `parseKeyPackageEvent` JSDoc

The "Required tags" comment at line ~432 should list `mls_proposals` alongside the existing five.

---

## 6. Test recommendations

### 6.1 Unit tests in `src/core/__tests__/key-package-event.test.ts`

| Test | Expected outcome |
|---|---|
| `createKeyPackageEvent` with a 64-hex `identifier` | Returns event with `["mls_proposals","0x000a"]` and `["d", <hex>]` tags |
| `createKeyPackageEvent` with `identifier = "notestr-<uuid>"` | Throws with the new error message naming `generateKeyPackageSlot()` |
| `createKeyPackageEvent` with `identifier = "deadbeef".repeat(8)` (64 chars but uppercase variant) | Throws (lowercase requirement) |
| `createKeyPackageEvent` with `identifier = ""` | Throws (existing behavior, message updated) |
| `generateKeyPackageSlot()` × 1000 | All outputs match `/^[0-9a-f]{64}$/`, no duplicates in sample |

### 6.2 Round-trip test (the critical interop guard)

```ts
it("createKeyPackageEvent output passes its own parseKeyPackageEvent", async () => {
  const ev = await createKeyPackageEvent({
    keyPackage,
    identifier: generateKeyPackageSlot(),
    relays: ["wss://relay.example"],
  });
  const result = parseKeyPackageEvent(ev);
  expect(result.errors).toEqual([]);
});
```

This test would have caught the original gap had it existed. Critically, the validator changes in §5.4 are what give this test teeth — without them it would have passed before this fix too.

### 6.3 Negative validator tests

| Input | Expected `errors[]` entry |
|---|---|
| Valid event with `mls_proposals` tag removed | `mls_proposals_presence` |
| Valid event with `mls_proposals` value = `"0x000b"` | `mls_proposals_value` |
| Valid event with `mls_proposals` value with extra entry `[m, "0x000a", "0x0001"]` | `mls_proposals_value` |
| Valid event with `d` value = `"notestr-079251af-…"` | `d_tag_shape` |
| Legacy kind-443 event with no `mls_proposals` and free-form `d` | No new errors (back-compat — neither check applies to kind 443) |

### 6.4 Cross-implementation snapshot test (optional but recommended)

Pin a known KeyPackage + slot, build the event, snapshot the sorted tags as a JSON string, and assert equality. If MDK ever tightens further, the snapshot drift becomes a one-line diff in CI rather than a runtime relay-rejection incident.

---

## 7. Migration and consumer impact

### 7.1 Breaking changes

- **`createKeyPackageEvent`** throws on non-64-hex `identifier`. Any consumer that passes a free-form string (the documented footgun) breaks immediately on upgrade. **This is the intended outcome.** The error message names `generateKeyPackageSlot()` so the fix path is obvious from the stack trace.
- **`parseKeyPackageEvent`** rejects kind-30443 events without `mls_proposals` or with non-hex `d`. Events emitted by older `marmot-ts` versions will fail this validator. Consumers that need to introspect old events for archive/diagnostic purposes can either keep an older `marmot-ts` around or set up a `legacy: true` option on `parseKeyPackageEvent` that skips the new kind-30443 checks. See §8.4 for the recommended posture.

### 7.2 Non-breaking but observable

- **Wire-level**: every kind-30443 event gains one tag (`mls_proposals`). Relays that filter on tag count or tag schema should be checked, but no popular relay does this in practice.
- **`KeyPackageManager.create()`**: now throws synchronously if the manager's `clientId` is set to a non-conforming value. Recommended migration in consumers: on app boot, validate the stored `clientId` against `/^[0-9a-f]{64}$/` and regenerate via `generateKeyPackageSlot()` if it doesn't match. The reference implementation lives at `notestr-web` `src/marmot/storage.ts:106` (`getOrCreateClientId`) as of the companion patch.

### 7.3 Known downstream consumers to notify

- `notestr-web` — companion patch already in place locally; will pick up cleanly once `marmot-ts` ships the fix and `package-lock.json` is updated to the new SHA.
- `nostling-web` — verify whether they generate `clientId` correctly and emit `mls_proposals`. If they use `marmot-ts` directly, this fix unblocks them automatically.
- Any other in-tree consumer of `@internet-privacy/marmot-ts` — please cross-check.

---

## 8. Open design questions for maintainers

These are decisions where reasonable maintainers might choose differently. The reporter has a recommendation but not strong opinions; the maintainers should pick.

### 8.1 Should `createKeyPackageEvent` auto-generate the slot when `identifier` is omitted?

**Option A** (current behavior, plus shape enforcement): callers must always supply `identifier`. Wrong format → throw.

**Option B**: make `identifier` optional. If omitted, mint via `generateKeyPackageSlot()`. Wrong format if supplied → throw.

**Reporter recommendation: B.** Most callers don't care about the slot value — they care that the KeyPackage gets published under a stable slot. Optional + auto-mint removes a footgun and reduces consumer code. Callers that do care (rotation, sibling-device coordination) keep full control.

### 8.2 Should the `mls_proposals` value be parameterizable?

**Option A**: hard-code `["mls_proposals", "0x000a"]` because MDK currently enforces `slice.len() == 2` and that specific value. Future MIP revisions that add proposals would require a `marmot-ts` release anyway.

**Option B**: accept an optional `mlsProposals?: string[]` option that defaults to `["0x000a"]`. Consumers exploring future proposals can pass extras at their own interop risk.

**Reporter recommendation: A for now.** MDK's `slice.len() == 2` check is the binding constraint; passing extras silently produces events MDK rejects. Revisit when MIP-00 adds another required proposal.

### 8.3 Should `KeyPackageManager.clientId` be renamed?

The field name `clientId` implies "a stable label identifying this client app." Consumers reach for things like `"notestr-desktop-2026"` or `"my-app-v1.4"` and have no signal that the value lands as a cryptographic slot identifier. The companion `notestr-web` patch documents this in the storage.ts comment, but the API itself remains a footgun.

**Option A**: leave the field name, document the constraint loudly in the JSDoc and via the new throw.

**Option B**: deprecate `clientId`, introduce `slot?: string` (or `keyPackageSlot?: string`), mark `clientId` as deprecated alias for one release, remove next major.

**Reporter recommendation: B.** The name `clientId` is descriptive of an entirely different concept (think OIDC client_id), and the existing field's JSDoc actively encourages the wrong mental model with the example `"my-app-desktop"`. Renaming costs one minor release of deprecation churn and removes a class of consumer bug permanently.

### 8.4 Validator strictness — flag-gated or default?

The validator changes in §5.4 are strictly tighter than today's behavior. Events emitted by older `marmot-ts` versions, or by any other implementation that hasn't shipped `mls_proposals`, will start failing.

**Option A**: ship the tightening default-on, no flag. Forces consumers to upgrade or pin the old version.

**Option B**: ship behind `parseKeyPackageEvent(ev, { strict: true })` — default `true`, allow `false` for archive/diagnostic use.

**Option C**: ship default-on with a separate `validateLegacy()` helper for archive cases.

**Reporter recommendation: B.** Round-trip compatibility with new emit is what matters in the hot path; an opt-out lets diagnostic tooling inspect the relay graveyard without rebuilding `marmot-ts`. The `strict: false` mode skips only the new kind-30443 checks (`d_tag_shape`, `mls_proposals_presence`, `mls_proposals_value`); all other validation stays on.

### 8.5 Coordinate MIP-00 text with MDK?

MIP-00 says the `d` tag SHOULD be cryptographically random 32-byte hex. MDK enforces it as MUST. The spec / implementation gap exists; only one side is the gatekeeper for cross-impl interop. Worth raising in `marmot-protocol/marmot` whether to:

- Tighten MIP-00 text to MUST so the spec matches the deployed enforcement, or
- Ask MDK to loosen its rejection to a warning so the spec remains correct.

**Reporter recommendation: tighten the spec.** The hex-encoded random slot is what every implementation should be doing anyway; the SHOULD was probably an oversight in MIP-00 drafting. The maintainer of MIP-00 and the maintainer of MDK overlap; this is a one-PR change in the spec text. Worth opening a tracking issue against `marmot-protocol/marmot`.

### 8.6 Semver

This PR contains:

- An additive emission change (new tag) — strictly speaking minor.
- A stricter emit-side validation (throw on non-conforming `identifier`) — breaking for misuse.
- A stricter parse-side validation — breaking for events from older versions or other non-conforming sources.

**Reporter recommendation: minor (0.5.x → 0.6.0)** so long as §8.4 lands as Option B (validator gated). The emit-side throw is a "you were already broken" surface — the events you produced before this fix wouldn't have worked on the network anyway, so callers depending on the silent acceptance had a latent bug. Calling it a minor with clear release notes is honest. If the maintainers prefer to call it a 1.0, that's also defensible — this is the change that makes `marmot-ts` actually interop with MDK, which is arguably the threshold for declaring stability.

---

## 9. Acceptance criteria

A `marmot-ts` release that closes this report SHALL:

1. Emit `["mls_proposals", "0x000a"]` on every kind-30443 event produced by `createKeyPackageEvent`.
2. Reject non-64-hex-lowercase `identifier` values passed to `createKeyPackageEvent` with an error message that names the helper used to mint a conforming slot.
3. Export `generateKeyPackageSlot(): string` from `src/core/key-package-event.ts`.
4. Add `d`-tag shape validation and `mls_proposals` presence/value validation to `parseKeyPackageEvent`, gated on `kind === 30443`, with error `check` codes that match the snippets in §5.4.
5. Include round-trip unit tests asserting `parseKeyPackageEvent(await createKeyPackageEvent(...))` produces zero errors for a fresh slot.
6. Include negative tests for each new error condition.
7. Update `package.json` version and `CHANGELOG.md` with a `### Breaking` entry naming the consumer impact in §7.1.

Acceptance is verified end-to-end by running `notestr-cli list-kps <npub-with-marmot-ts-device>` against an `npub` that has refreshed its KeyPackage under the new `marmot-ts` build and observing all events parse `ok`.

---

## 10. References

- **MIP-00 (Marmot Improvement Proposal 0):** `marmot-protocol/marmot/00.md` — §addressable-key-packages, §required-tags, §mls-proposals.
- **MDK KeyPackage validator:** `parres-hq/mdk/crates/mdk-core/src/key_packages.rs` — `D_TAG_HEX_LEN`, `parse_key_package`, `mls_proposals` validation (~lines 75–90 and 415–431).
- **Companion consumer patch (notestr-web):** `src/marmot/storage.ts:106` — `getOrCreateClientId`, mints 64-hex client slots and migrates legacy slots on read.
- **Reproducer (CLI side):** `notestr-cli list-kps` and `notestr-cli invite <self-npub>` against an `npub` with mixed-client device set.
- **Existing emit path (this fix's target):** `marmot-ts` `src/core/key-package-event.ts` `createKeyPackageEvent` (~line 577) and `parseKeyPackageEvent` (~line 432).
