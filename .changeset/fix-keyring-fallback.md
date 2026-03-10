---
"@googleworkspace/cli": patch
---

Fix credential key loss in Docker/keyring-less environments by no longer deleting `.encryption_key` on keyring success
