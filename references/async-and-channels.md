# Async, ASGI, and Channels

Concurrency and long-lived connection security for Django, DRF, and Channels.
Covers sync/async boundaries, request-context isolation, event-loop blocking,
WebSocket origin checks, and per-connection authentication and authorization.
Maps primarily to CWE-362, CWE-400, CWE-488, and CWE-862; relevant OWASP
categories include A01:2025 and API1, API4, and API5:2023.

## Contents
- [Principle](#principle)
- [Django, DRF & Channels implementation](#django-drf--channels-implementation)
- [Async safety and ORM access](#async-safety-and-orm-access)
- [Request and tenant context](#request-and-tenant-context)
- [WebSocket authentication and origin validation](#websocket-authentication-and-origin-validation)
- [Per-connection authorization](#per-connection-authorization)
- [Long-lived consumers and resource limits](#long-lived-consumers-and-resource-limits)
- [Review checklist](#review-checklist)

## Principle

Concurrent requests and long-lived connections break the assumption that one
thread, global, or connection-local value belongs to one principal for the
duration of work. Execution can interleave, migrate between workers, or outlive
the request that created it. The invariant is: **identity, tenant, and
authorization context must be bound to the current unit of work, propagated
deliberately, and re-checked whenever a long-lived channel acts on a resource.**

General defenses:

- Pass security context explicitly. If ambient context is unavoidable, use the
  runtime's task-local mechanism, set and reset it in a `finally` block, and do
  not let detached tasks inherit a request object or stale principal.
- Keep blocking I/O and synchronous libraries off an event loop. Use a bounded
  adapter or worker pool, preserve transaction boundaries, and apply
  backpressure rather than creating unbounded tasks.
- Treat connection establishment as authentication, not permanent
  authorization. Authorize the requested object before accepting where
  possible, and authorize every message or operation against current state.
- Validate browser connection origins even when the protocol is not ordinary
  HTTP. Cookies are sent during a cross-site WebSocket handshake and therefore
  create a cross-site hijacking risk.
- Bound connection count, handshake rate, message size and frequency, queued
  work, group fan-out, idle time, and total lifetime. Clean up subscriptions and
  tasks on disconnect.

## Django, DRF & Channels implementation

Django supports async views and async ORM query methods, but not every subsystem
is async-safe. Running under ASGI does not make synchronous code non-blocking,
and suppressing Django's safety guard does not make unsafe code safe. DRF 3.17.1
does not turn its standard synchronous `APIView`, authentication, permission,
serializer, and renderer pipeline into a native async pipeline merely because
the deployment uses ASGI. Keep ordinary DRF views synchronous unless the project
has deliberately selected and audited an async integration.

**Package decision (17 Jul 2026):** Channels `4.3.2` passes the maintained-
package gate, is maintained by the Django project, and supports Django 6.0.
Installing it does not supply origin validation, per-message authorization,
backpressure, quotas, or disconnect cleanup; retain every control below.

Channels has its own connection scope and consumer lifecycle. HTTP middleware
and DRF permission classes do not automatically authorize WebSocket messages.
Route consumers through explicit origin and authentication middleware, then
perform object and action authorization in the consumer.

## Async safety and ORM access

- Use Django's async ORM methods (`aget()`, `acreate()`, `asave()`, async
  iteration) where the required operation is supported.
- Put a synchronous ORM transaction in one synchronous function and call that
  function through `sync_to_async(..., thread_sensitive=True)`. Django
  transactions are not an async context to split across awaits.
- In Channels async consumers, use `database_sync_to_async` for synchronous ORM
  work. It also performs database-connection cleanup around the call.
- Do not pass a cursor, connection, unevaluated queryset, model manager bound to
  mutable request state, or other thread-affine object across the boundary.
- Set `CONN_MAX_AGE = 0` for async-mode database access and use database/backend
  pooling designed for the deployment when pooling is needed.
- Never set `DJANGO_ALLOW_ASYNC_UNSAFE` in a server, worker, notebook handling
  concurrent work, or test configuration that is meant to model production. It
  only disables `SynchronousOnlyOperation`; it does not add isolation.

Keep a transaction and its invariants together:

```python
from asgiref.sync import sync_to_async
from django.core.exceptions import PermissionDenied
from django.db import transaction


@sync_to_async(thread_sensitive=True)
def transfer_membership(*, actor_id, membership_id, new_tenant_id):
    with transaction.atomic():
        membership = (
            Membership.objects.select_for_update()
            .select_related("tenant")
            .get(pk=membership_id)
        )
        if not membership.tenant.admins.filter(pk=actor_id).exists():
            raise PermissionDenied
        membership.tenant_id = new_tenant_id
        membership.save(update_fields=["tenant_id"])
```

Do not perform the permission query, await unrelated work, and then update in a
separate call; authorization state can change between those operations.

## Request and tenant context

Module globals and `threading.local()` are not safe request or tenant stores in
an async server. Prefer function arguments and requester-scoped querysets. When
framework integration genuinely requires ambient state, use `ContextVar` and
always reset the token:

```python
from contextvars import ContextVar

current_tenant_id = ContextVar("current_tenant_id", default=None)


async def run_for_tenant(tenant_id, operation):
    token = current_tenant_id.set(tenant_id)
    try:
        return await operation()
    finally:
        current_tenant_id.reset(token)
```

Context variables can be copied into child tasks. Do not spawn request-derived
background work and assume the context will remain valid after the response;
pass immutable identifiers to the job and re-load and re-authorize state there.
Never cache a request, user object, mutable token claims, or tenant-bearing
queryset in process-global state.

## WebSocket authentication and origin validation

For session-authenticated browser clients, wrap routes with both origin and auth
middleware:

```python
import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")
django_asgi_app = get_asgi_application()

from myproject.routing import websocket_urlpatterns

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(
                URLRouter(websocket_urlpatterns),
            ),
        ),
    }
)
```

`AuthMiddlewareStack` populates `scope["user"]` from Django's session. It does
not prove that the user may access the room, tenant, or object named in the URL.
`AllowedHostsOriginValidator` protects deployments that maintain
`ALLOWED_HOSTS`; use `OriginValidator` with an explicit origin allowlist when
the accepted browser origins differ. Do not disable origin checks because the
handshake endpoint is otherwise authenticated.

For custom bearer-token middleware, validate signature, algorithm, issuer,
audience, expiry, and revocation before constructing a principal. Avoid tokens
in query strings because URLs reach logs, history, and monitoring systems. If a
client cannot set a header, exchange a normal authenticated HTTP request for a
short-lived, single-purpose connection ticket rather than reusing a long-lived
API token in the URL.

## Per-connection authorization

Authenticate before accepting and scope every object lookup to the principal.
Re-check authorization for each privileged message:

```python
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer


class ProjectConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        user = self.scope["user"]
        if not user.is_authenticated:
            await self.close()
            return

        self.project_id = self.scope["url_route"]["kwargs"]["project_id"]
        if not await self.can_access(user.pk, self.project_id):
            await self.close()
            return
        await self.accept()

    async def receive_json(self, content):
        user = self.scope["user"]
        if content.get("action") != "refresh":
            await self.close()
            return
        if not await self.can_access(user.pk, self.project_id):
            await self.close()
            return
        await self.send_json(await self.safe_snapshot(user.pk, self.project_id))

    @database_sync_to_async
    def can_access(self, user_id, project_id):
        return Project.objects.filter(
            pk=project_id,
            memberships__user_id=user_id,
            memberships__is_active=True,
        ).exists()

    @database_sync_to_async
    def safe_snapshot(self, user_id, project_id):
        project = Project.objects.filter(
            pk=project_id,
            memberships__user_id=user_id,
            memberships__is_active=True,
        ).get()
        return {"id": project.pk, "status": project.status}
```

Validate message schemas and allowlist actions; never map arbitrary client
method names to consumer methods. A channel-layer group name is routing
metadata, not an authorization boundary. Check authorization before adding a
connection to a sensitive group, exclude secrets from broadcast payloads, and
handle revocation for connections already joined.

## Long-lived consumers and resource limits

Session or permission state can change while a socket remains open. For
sensitive operations, refresh the user with Channels' `get_user(scope)` and
query current membership/permission state; close the connection after logout,
deactivation, tenant removal, credential revocation, or an application-defined
maximum lifetime. Do not trust the user object captured at connect time
indefinitely.

Async consumers should call `aclose_old_connections()` periodically before ORM
bursts on long-lived, low-traffic connections. Cancel per-connection tasks in
`disconnect()`, set timeouts around external I/O, and cap:

- concurrent connections per principal and source;
- connection attempts and failed authentication;
- inbound message bytes, nesting, and frequency;
- queued tasks and channel-layer capacity;
- subscriptions and fan-out per connection; and
- idle and absolute connection lifetime.

Use bounded queues and reject or shed load when full. Do not create one
untracked task per message or allow a slow client to retain unbounded outbound
data.

## Review checklist

### Stack-neutral

- [ ] Identity and tenant state are explicit or task-local, reset reliably, and
      never stored in process-global or thread-only context.
- [ ] Blocking work is off the event loop through bounded adapters; transactions
      and authorization-sensitive operations are not split across unsafe awaits.
- [ ] Every long-lived connection validates origin, authenticates once, and
      re-authorizes each object/action against current state.
- [ ] Revocation, logout, disconnect cleanup, backpressure, and connection,
      message, fan-out, idle, and lifetime limits are designed and tested.
- [ ] Connection tokens are short-lived and purpose-bound and do not leak in
      URLs or logs.

### Django, DRF & Channels

- [ ] Async ORM methods or `database_sync_to_async` /
      thread-sensitive `sync_to_async` are used correctly; no DB handles cross
      the boundary and async transactions stay inside one sync function.
- [ ] `DJANGO_ALLOW_ASYNC_UNSAFE` is absent and `CONN_MAX_AGE` is disabled for
      async DB access; standard DRF views are not assumed to be native async.
- [ ] `AllowedHostsOriginValidator` or an explicit `OriginValidator` wraps
      browser WebSockets, and `AuthMiddlewareStack` is not mistaken for object
      authorization.
- [ ] Consumer URL parameters, messages, group joins, and broadcasts use
      requester-scoped queries and explicit action schemas.
- [ ] Long-lived consumers refresh auth state where needed, close old DB
      connections, cancel tasks, and enforce bounded resource use.
