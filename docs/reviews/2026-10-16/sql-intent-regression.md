# SQL verification intent regression

## Observed failure

Read-only inspection of the latest local execution showed a SQL-specific task
running XSS against a GET query, followed by three duplicate-action retries.
The observed page contained a POST password form, but the seed had no body and
write methods were disabled. The actual login submission was not tested.
No target host, response body, credentials, or raw task text is reproduced here.

## Implemented

- Preserve explicit attack categories as local enum labels, separately from the
  broad response-blind purpose code. Structured goals take precedence over text.
- Restrict plan generation, plan validation, and both execution paths to that
  scope. Iterative category mismatches receive bounded repair feedback before HTTP.
- Pause SQL tasks that encounter a POST password form through a GET/HEAD seed.
  Require a new task with the actual submission request and authorized write
  policy; never guess credentials or silently enable writes. Resume cannot skip
  this prerequisite.
- Include requested-but-untested categories in deterministic conclusions,
  including historical runs. A model finish does not establish task completion.
- Preserve original field values when constructing differential probes.
- Retain valid suspicious differential observations without promoting them to
  confirmed vulnerabilities. Blocked/truncated/invalid rounds remain excluded.

## Remaining limitations

- Category extraction uses local patterns, not full natural-language semantics.
  Use structured goals for exclusions, ambiguous phrasing, or mixed objectives.
- The HTML prerequisite guard is conservative: any POST password form on a SQL
  GET/HEAD response requires explicit submission input. JavaScript-rendered forms
  and general multistep login discovery are not implemented by this change.
- Generic SQL differential signals do not prove authentication bypass. A dedicated
  local login oracle must compare a known failed login with the candidate and
  verify session identity or protected-resource access. HTTP 200, redirects,
  cookies, and body differences alone must not be labelled confirmed bypass.
- Add an approved local login fixture for comment-based bypass, CSRF rotation,
  failed-login controls, MFA, lockout/rate limiting, and session isolation before
  claiming end-to-end login vulnerability detection.

## Verification

Tests use temporary databases and httpx MockTransport, not operational targets
or NVIDIA services. Regression coverage includes wrong-category repair and
exhaustion, plan rejection, missing POST input, historical coverage, original
query/form/JSON values, and preservation of suspicious confirmation results.
