# Architecture: MIP-00 KeyPackage Compliance

## Paradigm

Modular monolith. All KeyPackage event concerns live in `src/core/key-package-event.ts` (pure functions over `NostrEvent`/`KeyPackage`). `KeyPackageManager` in `src/client/key-package-manager.ts` orchestrates lifecycle (create/rotate/track) by composing those core functions. Tests in `src/core/__tests__/key-package-event.test.ts`.

## Module Map

| Module | Purpose | Directory | Owned Data |
|--------|---------|-----------|------------|
| key-package-event | Event creation, validation, query helpers | `src/core/` | `NostrEvent` tag structure |
| key-package-manager | Lifecycle management, publish tracking | `src/client/` | `StoredKeyPackage` store |

## Boundary Rules

No direct imports across module boundaries except `client/` → `core/`. `core/` must not import from `client/`. All changes in this epic live in `core/key-package-event.ts` — the manager consumes the updated functions without modification (its existing `bytesToHex(randomBytes(32))` already produces a valid 64-hex slot; the 64-hex validation in `createKeyPackageEvent` is a gate, not a change to caller logic).

## Seams

None — single-story epic with no cross-story dependencies.

## Implementation Constraints

- `KEY_PACKAGE_PROPOSALS_TAG = "mls_proposals"` and `MIP00_SELF_REMOVE_PROPOSAL = "0x000a"` must be exported (used by validator and creator).
- `D_TAG_RE = /^[0-9a-f]{64}$/` is module-private (only referenced internally).
- `generateKeyPackageSlot()` must be exported from `src/core/key-package-event.ts` and re-exported via `src/core/index.ts` (which already does `export * from "./key-package-event.js"`).
- The `mls_proposals` tag must be pushed AFTER `["encoding", "base64"]` and BEFORE the `i` tag — matches the tag ordering visible in the spec's wire example.
- Validator checks (`d_tag_shape`, `mls_proposals_presence`, `mls_proposals_value`) are `severity: "warning"` — consistent with all other tag-compliance checks in `collectViolations`. Hard errors are reserved for decode failures and identity spoofing.
- Kind-443 back-compat: all three new checks are gated on `event.kind === ADDRESSABLE_KEY_PACKAGE_KIND (30443)` — legacy events are never touched.
- `generateKeyPackageSlot` uses `bytesToHex(randomBytes(32))` from `@noble/hashes/utils` (same pattern as `key-package-manager.ts:652`); `randomBytes` must be added to the import.
