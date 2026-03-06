---
"@googleworkspace/cli": minor
---

Redesign the scope picker to show **services** instead of raw scope names.

**Before:** Users saw a flat list of scope shortcodes like `drive.metadata.readonly`, `gmail.compose`, `calendar.events`.

**After:** Users see services by name with descriptions:
- `Drive` — Manage files, folders, and shared drives · 8 scopes · ⛔ 7 restricted
- `Gmail` — Send, read, and manage email · 5 scopes · ⛔ 6 restricted
- `Calendar` — Manage calendars and events · 2 scopes

Templates (Recommended, Read Only, Full Access) now select/deselect services.
Scope resolution to URLs happens automatically based on the selected service and template.
