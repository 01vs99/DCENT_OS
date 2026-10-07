# S19k native identity fixtures

These unchanged 256-byte deployed EEPROM pages exercise the production decoder and exact slot/SKU admission. They are identity fixtures, not hashing or electrical test results. Tests deliberately allow duplicate pages across slots; board count comes from selected physical endpoints, not serial-number uniqueness.

| File | Held source |
|---|---|
| `s19k-bhb56903.bin` | , decoded from its byte-text representation |
| `epic-bhb56902.bin` | , key `BHB56902\|fmt=5\|keyver=17`, `raw_data` |
| `epic-bhb56801.bin` | Same matched-sample document, key `BHB56801\|fmt=5\|keyver=17`, `raw_data` |

The BHB56801 S19 XP sample shares header `05 11` and ASIC family BM1366 with S19k. Its rejection demonstrates why that header or chip family alone cannot select S19k's NoPic power/reset profile.
