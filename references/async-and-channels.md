# Async, ASGI, and Channels

This file covers concurrency security and long-lived connection security for
Django, DRF, and Channels. The controls in scope are sync/async boundaries,
request-context isolation, the blocked event loop, WebSocket origin checks, and
per-connection authentication and authorization. Maps primarily to CWE-362,
CWE-400, CWE-488, and CWE-862. Relevant OWASP categories include A01:2025 and
API1, API4, and API5:2023.

This file owns the **long-lived or concurrent connection**. That scope is the
sync/async boundary and what crosses it, per-request context that must not
become per-process state, and the blocked event loop. It also covers the
WebSocket from handshake to close. That scope holds the origin check, the
authentication, and the per-message authorization and limits that no HTTP
middleware runs on its behalf.

The rules those controls express belong elsewhere.
`authorization-architecture.md` owns the privilege model.
`a01-broken-access-control.md` owns the access-control failure itself.
`api-drf-specific.md` owns the ordinary request/response surface.
`a10-exceptional-conditions.md` owns the race mechanics.
`deployment-and-runtime.md` owns the ASGI server and the proxy in front of it.

## Contents
- [Principle](#principle)
- [Django, DRF & Channels implementation](#django-drf--channels-implementation)
- [Async safety and ORM access](#async-safety-and-orm-access)
- [Request and tenant context](#request-and-tenant-context)
- [WebSocket authentication and origin validation](#websocket-authentication-and-origin-validation)
- [Per-connection authorization](#per-connection-authorization)
- [Long-lived consumers and resource limits](#long-lived-consumers-and-resource-limits)
- [Subscriptions as long-lived queries](#subscriptions-as-long-lived-queries)
- [Review checklist](#review-checklist)

## Principle

Concurrent requests and long-lived connections break one assumption. That
assumption is that one thread, global, or connection-local value belongs to one
principal for the duration of the work. Execution can interleave, migrate
between workers, or outlive the request that created it. The invariant is:
**identity, tenant, and authorization context must be bound to the current unit
of work and propagated deliberately. They must be re-checked whenever a
long-lived channel acts on a resource.**

General defenses:

- Pass security context explicitly. If you cannot avoid ambient context, use
  the runtime's task-local mechanism. Set it and reset it in a `finally` block.
  Do not let a detached task inherit a request object or a stale principal.
- Keep blocking I/O and synchronous libraries off an event loop. Use a bounded
  adapter or a worker pool, preserve transaction boundaries, and apply
  backpressure. Do not create unbounded tasks.
- Treat the establishment of a connection as authentication, not as permanent
  authorization. Authorize the requested object before you accept, where
  possible. Authorize every message or operation against current state.
- Validate browser connection origins even when the protocol is not ordinary
  HTTP. The browser sends cookies during a cross-site WebSocket handshake,
  which creates a cross-site hijack risk.
- Bound connection count, handshake rate, message size and frequency, queued
  work, group fan-out, idle time, and total lifetime. Remove subscriptions and
  tasks on disconnect.

## Django, DRF & Channels implementation

Django supports async views and async ORM query methods, but not every
subsystem is async-safe. A deployment under ASGI does not make synchronous code
non-blocking. Suppression of Django's safety guard does not make unsafe code
safe. DRF 3.18.0 does not turn its standard synchronous pipeline into a native
async pipeline merely because the deployment uses ASGI. That pipeline is
`APIView`, authentication, permission, serializer, and renderer. Keep ordinary
DRF views synchronous unless the project has deliberately selected and audited
an async integration.

**Package decision (9 Aug 2026):** Channels `4.3.2` passes the
maintained-package gate, is maintained by the Django project, and supports
Django 6.0. An installation of it does not supply origin validation,
per-message authorization, backpressure, quotas, or disconnect cleanup. Retain
every control below.

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
- Set `CONN_MAX_AGE = 0` for async-mode database access. Where you need
  pooling, use database or backend pooling designed for the deployment.
  Django's own native pooling requires the same setting, and it raises
  `ImproperlyConfigured` alongside persistent connections. The two rules
  therefore agree rather than conflict. `data-layer-and-database.md` owns pool
  sizing and statement timeouts.
- Never set `DJANGO_ALLOW_ASYNC_UNSAFE` in a server, a worker, a notebook that
  handles concurrent work, or a test configuration that models production. It
  only disables `SynchronousOnlyOperation`, and it does not add isolation.

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
        destination = Tenant.objects.get(pk=new_tenant_id)
        # Both sides, inside the same transaction. The source check alone
        # lets an admin move a member into any tenant by identifier.
        if not membership.tenant.admins.filter(pk=actor_id).exists():
            raise PermissionDenied
        if not destination.admins.filter(pk=actor_id).exists():
            raise PermissionDenied
        membership.tenant_id = destination.pk
        membership.save(update_fields=["tenant_id"])
```

Do not perform the permission query, await unrelated work, and then update in
a separate call. Authorization state can change between those operations. The
destination check is the half that a transfer bug drops. The source check
alone lets an admin move a member into any tenant by identifier.

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

A child task can copy context variables. Do not spawn request-derived
background work and assume that the context stays valid after the response.
Pass immutable identifiers to the job, and re-load and re-authorize the state
there. Never cache a request, a user object, mutable token claims, or a
tenant-bearing queryset in process-global state.

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
not prove that the user may access the room, tenant, or object named in the
URL. `AllowedHostsOriginValidator` protects deployments that maintain
`ALLOWED_HOSTS`. Use `OriginValidator` with an explicit origin allowlist when
the accepted browser origins differ. Do not disable origin checks because the
handshake endpoint is otherwise authenticated.

For custom bearer-token middleware, validate signature, algorithm, issuer,
audience, expiry, and revocation before you construct a principal. Avoid tokens
in query strings, because URLs reach logs, history, and monitoring systems. If
a client cannot set a header, exchange a normal authenticated HTTP request for
a short-lived, single-purpose connection ticket. Do not reuse a long-lived API
token in the URL. The server must delete the ticket at the first redemption,
because a URL in a log stays replayable.

## Per-connection authorization

Authenticate before you accept, and scope every object lookup to the principal.
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

Validate message schemas and allowlist actions. Never map an arbitrary client
method name to a consumer method. A channel-layer group name is routing
metadata, not an authorization boundary. Check authorization before you add a
connection to a sensitive group. Exclude secrets from broadcast payloads, and
handle revocation for connections that already joined.

**Write-time.** When you generate a consumer, authenticate and authorize in
`connect()`, and `close()` before `accept()` rather than after it. An accepted
socket is already a channel the client can send on. Re-check the same
authorization inside `receive_json()` for every privileged message, and
allow-list the actions by name. A connection outlives the grant that opened it,
and a revocation lands mid-session.

Scope each lookup to the principal inside the `database_sync_to_async` call. Do
not fetch by the id the URL supplied. Wrap the routing in
`AllowedHostsOriginValidator` and `AuthMiddlewareStack` in the edit that
publishes the consumer. The handshake is a cross-origin request that no CSRF
token covers.

## Long-lived consumers and resource limits

Session state or permission state can change while a socket remains open. For
sensitive operations, refresh the user with Channels' `get_user(scope)`, and
query current membership and permission state. Close the connection after
logout, deactivation, tenant removal, credential revocation, or an
application-defined maximum lifetime. Do not trust the user object from connect
time indefinitely.

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

Those caps are this file's instance of a general rule: every caller-controlled
value that multiplies work carries a server-enforced ceiling.
`a06-insecure-design.md`, "Algorithmic resource exhaustion" states that rule
with the table of surfaces it spans.

## Subscriptions as long-lived queries

A subscription is a query the client registers once and the server answers many
times. Every rule above therefore applies to it without amendment. The mapping
is worth a statement. A GraphQL library or a messaging library usually holds
the subscribe code, rather than a consumer that somebody wrote. The
documentation of that library covers its protocol rather than this boundary.
`graphql-and-alternative-api-surfaces.md` owns the schema, the resolver, and
the document limits. The socket underneath belongs here.

- **Origin.** The handshake is a cross-origin request that no CSRF token
  covers, and the browser sends cookies with it. A subscription route takes
  the same origin allowlist as any other socket route.
- **Connection authentication.** Subscription protocols typically carry
  credentials in an initialization message that the client sends after the
  socket opens. Validate that message before you acknowledge the connection,
  and close on failure. Do not acknowledge first and check when the first
  operation arrives. The ticket rule above applies, so put no long-lived token
  in the query string.
- **Authorize the subscribe, not only the connect.** The operation names a root
  field and its arguments: a channel, a document, a tenant. That is an
  object-level decision at registration. An authenticated connection is not a
  subscription to anything in particular.
- **Authorize every published event.** The grant that existed at registration
  may be gone when the server produces event N. A stream is precisely the shape
  a revocation lands in the middle of. Re-check current state before each
  publish, and build the payload for the receiving principal. Do not broadcast
  one payload to a group. A group name is routing metadata, not an
  authorization boundary.
- **Revocation ends the subscription.** Logout, deactivation, tenant removal, a
  permission change, and an application-defined maximum lifetime each close the
  socket. They do not merely withhold the next event.
- **Limits are per subscription, not per connection.** One socket can hold many
  subscriptions, and one write can fan out to every subscriber of a channel.
  Cap subscriptions per connection and per principal, event rate and payload
  size per subscription, and total fan-out per publish. Unsubscribe and cancel
  the backing tasks on disconnect. Without that step, a client that reconnects
  in a loop leaves server-side state that nothing reads.

**Write-time.** When you generate a subscription, put the object-level check on
the subscribe path, where the root field's arguments are first known. Repeat
that check on the publish path before each event. The two run at different
moments under different grants, and only the first one is visible in the
schema. Register the unsubscribe and the task cancellation in the same edit
that registers the subscription. A stream that outlives its client is both a
disclosure path and a fan-out cost that no limit counts.

## Review checklist

### Stack-neutral

- [ ] Identity and tenant state are explicit or task-local, reset reliably, and
      never stored in process-global or thread-only context.
- [ ] Bounded adapters keep blocking work off the event loop. No transaction
      and no authorization-sensitive operation splits across an unsafe await.
- [ ] Every long-lived connection validates origin, authenticates once, and
      re-authorizes each object/action against current state.
- [ ] The design and the tests cover revocation, logout, disconnect cleanup,
      backpressure, and the connection, message, fan-out, idle, and lifetime
      limits.
- [ ] Connection tokens are short-lived and purpose-bound and do not leak in
      URLs or logs.
- [ ] The server authorizes a subscription when the client registers it, and
      again before each published event. Revocation closes it. It counts
      against per-principal subscription, fan-out, and lifetime limits.

### Django, DRF & Channels

- [ ] The code uses async ORM methods, `database_sync_to_async`, or
      thread-sensitive `sync_to_async` correctly. No DB handle crosses the
      boundary, and async transactions stay inside one sync function.
- [ ] `DJANGO_ALLOW_ASYNC_UNSAFE` is absent, and `CONN_MAX_AGE` is disabled for
      async DB access. A size-capped pool does the connection reuse. The review
      does not assume that standard DRF views are native async.
- [ ] `AllowedHostsOriginValidator` or an explicit `OriginValidator` wraps
      browser WebSockets, and nobody mistakes `AuthMiddlewareStack` for object
      authorization.
- [ ] Consumer URL parameters, messages, group joins, and broadcasts use
      requester-scoped queries and explicit action schemas.
- [ ] Long-lived consumers refresh auth state where needed, close old DB
      connections, cancel tasks, and enforce bounded resource use.
