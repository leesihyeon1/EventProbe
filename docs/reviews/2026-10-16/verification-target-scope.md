# Verification target scope

## Previous behavior

The new-task dialog always read the request editor. It did not provide an
independent domain input. Executions could discover and select same-origin links
and GET forms; they were not limited to mutations of the submitted packet.

## Current behavior

- Current request: reads the request editor, including its configured headers.
  The UI defaults to `request_only`. Discovery does not add endpoints, actions
  must use `seed`, and the outgoing request policy preserves path and method.
  Existing input mutation, local CSRF refresh, and actor sessions still apply.
- Current request can explicitly select `same_origin` to retain discovery and
  configured object-access tests. Object policies/access goals are rejected in
  request-only mode rather than silently expanding its scope.
- Domain input: accepts an HTTP(S) URL or a hostname (HTTPS by default), builds a
  new GET request, and uses `same_origin`. It never reads request-editor headers,
  default headers, body, parameters, old actor headers, or old object policies.
  It starts with a fresh session. URL credentials and unsupported schemes fail.
- Source, domain, and scope changes invalidate the previewed plan in the UI.
- Scope is persisted in RunSpec and sent to the planner as an enum. The API
  default remains `same_origin` for older callers, saved templates, and history.

## Boundaries

Same origin means the same scheme, hostname, and port, not every subdomain.
The existing request/time/step budgets and path/method policies still apply.
Static links and GET forms can be discovered; this is not a full browser crawler
and does not automatically submit POST login forms or enable writes. Fixed plan
mode still operates on its approved endpoints; selecting a domain does not imply
exhaustive coverage. For credentialed testing, use an explicitly prepared request
in the request editor. The domain mode deliberately starts without credentials.

## Verification

- Backend: 1,099 tests passed, including scope/discovery regressions.
- Frontend: 133 tests passed, including source switching and credential isolation.
- Playwright: checked the live dialog at desktop and 390px mobile widths; no
  horizontal overflow. Intercepted task creation, verified a synthetic domain
  yields a fresh GET with zero headers/actor credentials, and sent no target or
  model requests during browser verification.
