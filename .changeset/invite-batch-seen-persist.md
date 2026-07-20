---
"@internet-privacy/marmot-ts": patch
---

Persist the invite seen-set once per `InviteManager.ingestEvents` batch instead of once per event, keeping large cold-start drains O(n) in storage writes.
