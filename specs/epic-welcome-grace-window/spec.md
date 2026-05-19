# joinGroupFromWelcome must honor the KeyPackage rotation grace window

**Status**: Implemented 2026-05-19
**Source**: `specs/marmot-ts-welcome-grace-window-2.md` (v2)
**Scope (this fork)**: `941design/marmot-ts#addressable-key-packages` — the
storage-side grace window already exists (`markDeprecated`, `cleanupDeprecated`,
`removeExpired`, `getPrivateKey` is deprecation-agnostic). The gap is that
`joinGroupFromWelcome` enumerates candidates via `keyPackages.list()`, which
filters deprecated entries out. This epic wires the welcome-decrypt path
through to the grace-window store.

## Problem

`KeyPackageManager.rotate()` calls `markDeprecated(ref, now)`. Deprecated
entries are dropped from `storeList()` (and therefore `list()`,
`#buildSnapshot`, `watchKeyPackages`) but their `privatePackage` is still
in IndexedDB and reachable via `getPrivateKey(ref)` until
`cleanupDeprecated(maxAgeSec)` runs.

`MarmotClient.joinGroupFromWelcome` at `src/client/marmot-client.ts:212`
does:

```ts
const allKeyPackages = await this.keyPackages.list();
```

Because `list()` excludes deprecated, a Welcome rumor whose `secrets[].new_member`
matches a now-deprecated `keyPackageRef` is silently dropped with
`"No matching KeyPackage found in local store"` — even though the matching
private material is in store and within the grace window.

This is the exact failure the grace window was added to absorb.

## Solution

Adopt **option (B)** from the spec. Smallest-correct change:

1. Make private `storeList(options?: { includeDeprecated?: boolean })` accept
   an opt-in flag. Default behavior unchanged — `list()`, `count()`,
   `#buildSnapshot()` and `watchKeyPackages()` are NOT touched.
2. Add public `listForWelcomeDecrypt(): Promise<ListedKeyPackage[]>` that
   delegates to `storeList({ includeDeprecated: true })` and returns
   active entries first, deprecated entries last.
3. In `MarmotClient.joinGroupFromWelcome`, swap the `list()` call for
   `listForWelcomeDecrypt()`. Existing prioritization by
   `hasMatchingSecret` is preserved.
4. Add a debug log at the call site when the matched candidate has
   `deprecatedAt` set — diagnostic signal that the grace window saved
   the join (telemetry suggestion from spec §7).

Option (C) — making `list()` itself include deprecated — is **rejected** for
the reason in spec §5.C: consumer code (notestr-web `device-sync.ts`) uses
`list()` to decide "is this event one of my own KPs, skip self-invite"; a
silent inclusion of deprecated entries would re-invite the device into
groups it had already rotated out of.

## Scope

### In Scope

- `src/client/key-package-manager.ts`: `storeList` signature widening,
  `listForWelcomeDecrypt` addition.
- `src/client/marmot-client.ts`: `joinGroupFromWelcome` accessor swap +
  deprecation telemetry log.
- `src/client/__tests__/key-package-manager.test.ts`: tests for the new
  accessor + a regression test that `list()` still excludes deprecated.
- `src/client/__tests__/marmot-client.test.ts` (or sibling): an end-to-end
  test exercising the rotation-race scenario.

### Out of Scope

- Auto-wiring `cleanupDeprecated()` (spec §8 follow-up — separate issue).
- Differentiating the error string for grace-window-elapsed vs
  never-published (spec §8 follow-up).
- Inviter-side `device-sync.ts` change in notestr-web (different repo).
- Adopting the grace-window storage feature into `marmot-protocol/marmot-ts`
  HEAD (different fork; we're on `941design`).

## Stories

Single story: **S1 — Wire welcome-decrypt through the grace window**. See
`acceptance-criteria.md`.

## Design Decisions

- `listForWelcomeDecrypt` is a separate public method, not an overload of
  `list()`. The RFC for option (C) above is the load-bearing reason.
- The active-first sort is intentional: when both an active and a
  deprecated KP could match the welcome (unusual but possible during
  rotation churn), prefer the active one. The existing
  `hasMatchingSecret`-prioritization in `joinGroupFromWelcome` already
  partitions by RFC 9420 `keyPackageRef` match, so the active/deprecated
  ordering is a secondary tiebreak when neither has a definitive RFC match.
- The debug log on a deprecated match uses the existing `#log` /
  `log` debug channel — no new dependency or telemetry plumbing.

## Non-Goals

- No protocol-level change (Welcome wire format unchanged).
- No change to `deprecatedAt` semantics in storage.
- No change to `rotate()`, `markDeprecated()`, `cleanupDeprecated()`,
  `removeExpired()`, or `getPrivateKey()`.

## Amendments

- **2026-05-19** — During AC-GRACE-2 implementation, the spec's pseudo-test
  in §6 of the source spec was found to conflate two valid post-grace-window
  failure modes. After `rotate()` runs, the store retains an active
  replacement KP at the same `d` slot. `cleanupDeprecated(0)` removes only
  the deprecated entry, so `joinGroupFromWelcome` still finds the
  replacement as a candidate but fails at the ts-mls join step with
  `"Failed to join group with any matching key package. Last error: No
  matching secret found"` rather than the pre-candidate-loop
  `"No matching KeyPackage found in local store"`. Both errors are
  semantically correct rejections — the Welcome cannot decrypt. AC-GRACE-2
  is split into two test cases: (a) post-rotation cleanup, where the
  rejection matches `/No matching KeyPackage|Failed to join group/`; and
  (b) bare `markDeprecated` + `cleanupDeprecated(0)` with no replacement,
  which matches the literal `/No matching KeyPackage/` from the spec.
