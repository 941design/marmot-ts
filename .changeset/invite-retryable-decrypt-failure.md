---
"@internet-privacy/marmot-ts": minor
---

Add a `shouldRemoveOnFailure` option to `InviteManager` (also reachable via `MarmotClientOptions.inviteOptions`) so apps can keep a gift wrap retrievable for retry after a transient decrypt failure instead of losing it after one attempt.
