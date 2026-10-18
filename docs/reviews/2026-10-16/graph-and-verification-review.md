# Autonomous verification: graph and completion review

## Evidence from the latest local run

Read-only metadata inspection showed one SQL probe followed by three identical
planner choices. The task paused after four target requests despite enough
remaining budget for a bounded differential confirmation. No confirmation action
ran. The seed was GET, and all discovered endpoints were GET. The observation
had a GET form field that the probe targeted. This does not establish whether
the actual vulnerable behavior was exercised. Target URL, payload, response
body, credentials, and raw goal are omitted here.

## Changes

- On repeated planner action, a completed probe with linked evidence may advance
  once to a local confirmation for the same endpoint, actor, category, location,
  and field. It stays within the original request budget. An already attempted
  confirmation, missing evidence, or unresolved request cannot trigger replay.
- Differential SQL results retain suspicious observations when only nonblocking
  validity warnings occur. Blocked, truncated, rate-limited, or unauthorized
  rounds still cannot establish a finding. SQL error responses alone do not
  become a confirmed authentication bypass.
- The graph now fits in viewport coordinates. The screenshot's clipped nodes
  came from mixing model-sized SVG viewBox units with screen-pixel transforms.
  Per-step chips show category, HTTP status counts, and the linked local verdict.
  Mobile opens at a readable start position; the whole-run fit command remains.
- The graph presents local run evidence. It does not by itself prove a target
  vulnerability or the completion of every item in the ARTEX review.

## Verification and remaining work

1,101 backend tests and 135 frontend tests passed. A local SQLite fixture with
unsafe string interpolation generated a suspicious SQL differential; a bound
parameter fixture remained inconclusive. Neither was mislabelled confirmed.
Desktop and 390px mobile graph layouts were checked in a browser with synthetic
events. No real target or NVIDIA request was made for this review.

The dedicated login oracle from `sql-intent-regression.md` remains necessary for
an authentication-bypass claim. A task that hits a 500 response still requires
linked proof of changed application behavior, not a status-code-only conclusion.
