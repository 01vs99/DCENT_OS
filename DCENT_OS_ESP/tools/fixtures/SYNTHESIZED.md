# Synthesized fields in the scenario fixtures

`fixtures/_base/` is a **captured** read-only snapshot of the bench BitAxe Hex Supra
(see `tools/README.md`). Scenario directories override only the endpoints that differ, and
most of those overrides are edits of captured values. This file records the fields that are
**invented rather than measured**, so nobody reads a fixture screenshot as device evidence.

| scenario | endpoint | field | value | why |
|---|---|---|---|---|
| `mining` | `/api/system/info` | `dcentaxe.poolTruth.rejectReasonCounts` | 5 kinds, 24 rejects | The capture had one real reject (`Stale` x1), which exercises exactly one row of the Pool page's rejection list. The synthesized set covers four of the seven explanation classes plus one deliberately **unmapped** key (`Server busy, retry`) so the "we never invent an explanation" path is visible. |
| `mining` | `/api/system/info` | `sharesSubmitted` / `sharesRejected` / `sharesRejectedReasons` / `lastRejectReason` | 893 / 24 / `["Stale"]` / `Stale` | Kept arithmetically consistent with the synthesized histogram (`accepted 869 + rejected 24 = submitted 893`; the reason counts sum to `sharesRejected`). `sharesAccepted` is still the captured 869. |
| `pool-offline` | `/api/system/info` | `dcentaxe.poolTruth.rejectReasonCounts` | 2 kinds, 9 rejects | A pool that went away should show staleness plus an auth-class reject, not a single captured row. |
| `pool-offline` | `/api/system/info` | `sharesSubmitted` / `sharesRejected` / `sharesRejectedReasons` / `lastRejectReason` | 882 / 9 / `["Stale"]` / `Stale` | `accepted 869 + rejected 9 + pending 4 = submitted 882`. |

Everything else in those two files is as captured or as previously scenario-edited.
`first-run` is left at `sharesRejected: 0` with an empty `rejectReasonCounts` on purpose: it is
the honest empty state (`No rejected shares yet.`).

Reason keys are the pool's own wording. The firmware never rewrites them
(`dcentaxe-stratum/src/client.rs` `record_reject_reason`), and the dashboard escapes them
before insertion, so a fixture key may safely contain punctuation.

Added by lane `P1-W9` of .
