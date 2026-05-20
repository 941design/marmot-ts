# Acceptance Criteria: MIP-00 KeyPackage Compliance

## AC-EMIT-1
`createKeyPackageEvent` output includes `["mls_proposals", "0x000a"]` as a tag on every kind-30443 event.

## AC-EMIT-2
`createKeyPackageEvent` throws when `identifier` does not match `/^[0-9a-f]{64}$/`, with an error message that names `generateKeyPackageSlot()`.

## AC-EMIT-3
`createKeyPackageEvent` throws (with updated message naming `generateKeyPackageSlot()`) when `identifier` is empty or falsy.

## AC-SLOT-1
`generateKeyPackageSlot()` is exported from `src/core/key-package-event.ts` and produces a string matching `/^[0-9a-f]{64}$/`.

## AC-VAL-1
`collectViolations` (and therefore `validateKeyPackageEvent`/`softValidateKeyPackageEvent`) adds a `d_tag_shape` warning when a kind-30443 event's `d` tag value does not match `/^[0-9a-f]{64}$/`.

## AC-VAL-2
`collectViolations` adds an `mls_proposals_presence` warning when a kind-30443 event has no `mls_proposals` tag.

## AC-VAL-3
`collectViolations` adds an `mls_proposals_value` warning when a kind-30443 event has an `mls_proposals` tag but it is not exactly `["mls_proposals", "0x000a"]` (wrong value OR extra entries).

## AC-COMPAT-1
None of AC-VAL-1, AC-VAL-2, AC-VAL-3 fire on legacy kind-443 events. Kind-443 events pass validation without `mls_proposals` and with any-shape `d` value.

## AC-ROUND-1
A fresh event produced by `createKeyPackageEvent({ identifier: generateKeyPackageSlot(), ... })` passes `validateKeyPackageEvent` with zero violations.

## AC-VER-1
`package.json` version is bumped to 0.6.0 and `CHANGELOG.md` includes a `### Breaking` entry describing the `identifier` shape requirement and the tightened validator.
