---
"@internet-privacy/marmot-ts": minor
---

Application messages whose claimed sender fails MLS authentication are now dropped, and the authenticated sender is surfaced on the ingest() result and a new authenticatedApplicationMessage event.
