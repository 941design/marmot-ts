# Acceptance Criteria — welcome-grace-window

Tags: **GRACE** (correctness), **API** (surface), **TEST** (test coverage),
**OBS** (observability).

---

**AC-GRACE-1** — `MarmotClient.joinGroupFromWelcome({ welcomeRumor })`
resolves (does not throw) when the Welcome's `secrets[].new_member`
matches the `keyPackageRef` of a deprecated KP whose `deprecatedAt` is
within the current grace window (i.e., the entry has NOT been removed by
`cleanupDeprecated` / `removeExpired`).

**AC-GRACE-2** — `MarmotClient.joinGroupFromWelcome({ welcomeRumor })`
rejects with the existing `"No matching KeyPackage found in local store."`
error when the matching KP has been removed (after
`cleanupDeprecated(0)` runs). The error message is unchanged from the
status quo.

**AC-GRACE-3** — Active KP enumeration semantics are unchanged.
`KeyPackageManager.list()`, `count()`, `#buildSnapshot()`, and
`watchKeyPackages()` continue to exclude entries with `deprecatedAt`
set. (Regression guard against silently picking option (C).)

**AC-GRACE-4** — When `joinGroupFromWelcome` succeeds against a candidate
whose `deprecatedAt` is set, the candidate ordering preferred an active
matching KP if one existed (i.e., active-first ordering is honored).

**AC-API-1** — A new public method
`KeyPackageManager.listForWelcomeDecrypt(): Promise<ListedKeyPackage[]>`
exists. It returns all entries with `privatePackage !== undefined`
(active + deprecated), active first.

**AC-OBS-1** — When `joinGroupFromWelcome` matches a deprecated candidate,
a debug-level log line records the deprecation timestamp and the matched
ref. The log uses the existing client-level debug channel; no new
dependency.

**AC-TEST-1** — `src/client/__tests__/key-package-manager.test.ts` covers:

- `listForWelcomeDecrypt()` returns both active and deprecated entries,
  active first.
- `list()` continues to exclude deprecated entries (regression on
  AC-GRACE-3).

**AC-TEST-2** — A test in the client-level test suite reproduces the
rotation-race scenario end-to-end:

- A KP is created locally.
- A Welcome rumor targeting that KP is built (via the existing invite /
  group-creation helpers in the test tree).
- The local KP is rotated (which calls `markDeprecated`).
- `joinGroupFromWelcome` is called and succeeds (AC-GRACE-1).
- After `cleanupDeprecated(0)`, the same flow rejects (AC-GRACE-2).

**AC-TEST-3** — All pre-existing tests in `src/client/__tests__/` continue
to pass (no regression).
