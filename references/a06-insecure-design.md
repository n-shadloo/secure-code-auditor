# A06:2025 — Insecure Design

Covers flaws that are missing controls by design, and not defective code.
Covers absent rate limits and anti-automation. Covers business-logic and
notification abuse, and unsafe defaults. Overlaps OWASP API4:2023
(Unrestricted Resource Consumption) and API6:2023 (Unrestricted Access to
Sensitive Business Flows).

This file owns **which flows are worth attacking, and why**. It owns the
inventory of the paths that move money, credits, entitlements, or durable
status. It owns the catalog of what goes wrong where nothing caps a flow. It
also owns the design rule that every input which multiplies work carries a
server-enforced bound.

This file owns none of the mechanisms that enforce those rules.
`api-drf-specific.md` owns DRF throttling, and the reasons a configured rate
is not the effective one. `a07-authentication-failures.md` owns login lockout.
`agent-and-llm-interfaces.md` owns per-agent cost and concurrency limits.
`a10-exceptional-conditions.md` owns the race and idempotency mechanics that
decide whether a limit or a transition holds under concurrent requests.

## Contents
- [Principle](#principle)
- [Rate limiting and anti-automation](#rate-limiting-and-anti-automation)
- [Algorithmic resource exhaustion](#algorithmic-resource-exhaustion)
- [Business-logic abuse](#business-logic-abuse)
- [Abuse of side-effecting actions](#abuse-of-side-effecting-actions)
- [Email and notification abuse](#email-and-notification-abuse)
- [Secure defaults and limits](#secure-defaults-and-limits)
- [Review checklist](#review-checklist)

## Principle

Some vulnerabilities are not a defective line of code. They are a control that
nobody designed in. A sensitive flow can have no limit on its rate or its
frequency. Login, password reset, checkout, invite, and coupon redemption are
such flows. An attacker abuses that flow even where each individual request is
"valid".

The principle is to **design abuse cases alongside features**. Identify the
flows worth attacking. Put limits and validations on them. Fail safe. This is
a design review, and not only a code diff.

## Rate limiting and anti-automation

**Important:** DRF's throttling is explicitly **not** a security control. The
DRF documentation says so directly. Do not treat throttling as a defense
against brute forcing or denial of service. The default classes key on an IP
origin that an attacker can spoof. The counter is also a non-atomic cache
operation.

A throttle also runs *after* authentication, so it does not protect the
authentication step. `api-drf-specific.md`, "Throttling as quota, not security
(API4)" holds the mechanics behind those caveats. Those mechanics are the
non-atomic read-modify-write, the per-process cache, and the order inside
`initial()`. This file owns which flows need anti-automation in the first
place.

Package choices do not replace layered design. `django-axes==8.3.1` passes the
maintained-package gate for login-attempt monitoring and lockout on Django
6.0. It passes only where proxy trust and client-IP extraction are correct.
Use account signals together with network and device signals. Avoid a
permanent denial of service that an attacker can trigger.

`django-ratelimit==4.1.0` and `django-defender==0.9.8` do not pass the 9 Aug
2026 maintenance gate for new use. For a general endpoint or business flow,
combine maintained edge and platform limits with application-level quotas.
Make those quotas aware of the account and the tenant, and add transactional
invariants. Fail closed on a sensitive flow. Define the degraded behavior, so
that a cache outage does not remove the protection silently.

Request rate and cost are separate controls. A machine caller defeats the
first control without a breach of it. A retry loop or an automation that runs
for hours stays inside any per-minute cap, and still exhausts a budget. A
limit keyed on IP is also useless where a whole fleet shares one egress
address.

Some flows spend money, tokens, or heavy database work on each call. Cap the
resource itself and the concurrency for such a flow, per principal identity.
Keep the request rate limit as well. A public flow has no principal, and an
address is not one. Give such a flow a ceiling on concurrency and on spend for
the endpoint itself, or require an identity before it runs. See
`agent-and-llm-interfaces.md`, "Cost and concurrency limits, not only request
rate".

## Algorithmic resource exhaustion

Maps to CWE-400 (Uncontrolled Resource Consumption) and CWE-770 (Allocation of
Resources Without Limits). Maps also to CWE-674 (Uncontrolled Recursion)
wherever the input nests. OWASP API4:2023 Unrestricted Resource Consumption is
the API-security mapping. The Top 10:2025 has no denial-of-service category.
This file therefore owns the design question, which is which inputs need a
bound. Each file in the table below owns the mechanics of one bound.

A rate limit counts requests. This is about the cost of a single one.

The work of a request can grow with a number that the caller chose. The
request rate never sees that growth. Five examples exist. They are
`?page_size=100000` on a list endpoint, and a serializer that queries once per
row over a queryset with no ceiling. They are also a selection set whose depth
the client picks, and a `count()` over a client-filtered table on every page
of a scan. The fifth is an archive that expands to a thousand times its
compressed size.

Each one is a valid request. Each one costs the server orders of magnitude
more than the attacker spent on it. That asymmetry is the vulnerability. It is
also why the defect survives review, because nothing looks wrong at the size
the developer tested.

**The design rule is that every unbounded input to an algorithm gets a bound
the server enforces.** Do not use a bound that the client is asked to respect.
Do not use a default that the client may raise. Do not use a bound that holds
only on the benchmarked path. Three questions settle whether a flow has a
bound:

- Which input under the control of the caller multiplies the work? It can be a
  count, a depth, a page size, a date range, a compression ratio, or a number
  of nested items. It can also be an offset, or a set of relations and
  computed fields that the caller asks the response to expand.
- What is the ceiling, and which layer enforces it? The layer is the edge, the
  framework, the application, or nothing.
- What happens at the ceiling? It is a rejection, a truncation that the
  response reports, or an out-of-memory kill that also ends the other requests
  of the worker.

### Django & DRF

- **A page-size query parameter without `max_page_size` removes the ceiling
  rather than adding one.** `PageNumberPagination` ships with
  `page_size_query_param = None`, so the client cannot change the page size. A
  value for it gives the client control, bounded only by `max_page_size`.
  `max_page_size` is also `None`, and is therefore no bound. Set the two
  together, or set neither. `LimitOffsetPagination` is the sharper default. It
  accepts a client `limit` immediately, with `max_limit = None` behind it, so
  set `max_limit` wherever you choose that class. Its `offset` is a second
  multiplier that the caller picks, because the database walks and discards
  every row in front of the page. Bound the offset, or use `CursorPagination`,
  which has none.
- **No `PAGE_SIZE` means no pagination at all.** `DEFAULT_PAGINATION_CLASS` is
  `None` by default. A list view with no paginator returns every row that the
  queryset matched. The failure is an absence, so a diff does not show it. It
  appears only under production data volumes.
- **Serialization cost is per row and it compounds.** A
  `SerializerMethodField` that runs a query multiplies by the page size. So
  does a nested serializer over a reverse relation. A page size that the
  client raised multiplies the cost again. `depth` on a `ModelSerializer`
  walks relations automatically to the given depth. That is the form of this
  defect that nobody reads off the class body.
- **A large read is streamed and value-scoped rather than materialized.**
  `.iterator()` keeps the whole result set out of the queryset cache.
  `.only()` and `.values()` cut the per-row payload. A server-side statement
  timeout bounds the cost of either one where the estimate is wrong. See
  `data-layer-and-database.md`, "Connection exhaustion and query timeouts".
- **`count()` is a scan the caller triggers.** `PageNumberPagination` and
  `LimitOffsetPagination` issue one `count()` per request, over the result of
  the filters. On a large table under a client-controlled filter, that is an
  expensive query on demand. `CursorPagination` issues none. That is a
  resource argument for `CursorPagination`, separate from the disclosure
  argument in `api-drf-specific.md`, "Pagination and filter leakage".
- **`DATA_UPLOAD_MAX_NUMBER_FIELDS` does not see a JSON body.** Django
  applies it in `QueryDict` and in `MultiPartParser`, so it counts the fields
  of a query string, a form body, and a multipart body. A JSON list body
  passes it at any length, and `DATA_UPLOAD_MAX_MEMORY_SIZE` bounds only the
  bytes. DRF's `ListSerializer` carries `max_length`, and that default is
  `None`. Set it on every `many=True` serializer and on every bulk route.
  `to_internal_value()` checks it before it validates the first element.
  Checked against the Django 6.0.7 and DRF 3.16.1 source on 27 Aug 2026.
- **Recursion depth is an input like any other.** A parsed structure nests.
  Examples are request bodies, selection sets, XML entities, archive members,
  and any self-referential model that Python walks. Bound the depth at the
  parser or the validator, before the recursion runs. A `RecursionError`
  caught afterwards has already paid the cost. It also leaves the interpreter
  in a state that supports no security decision.

Each surface enforces its own version of the bound, and the mechanics are not
restated here:

| Surface | The bound that applies | Owner |
|---|---|---|
| Request body bytes, form field count, file count | Edge body cap plus the Django `DATA_UPLOAD_*` thresholds | This file, "Secure defaults and limits" |
| Elements of a JSON list body | `max_length` on the list serializer, checked before the first element is validated | This file, "Algorithmic resource exhaustion" |
| Uploaded files and their expansion | Per-file and aggregate size, count, quota, and decompression ratio | `file-uploads.md`, "Size, count, and quota limits" |
| List responses | An enforced `PAGE_SIZE`, `max_page_size`, and filter and ordering allowlists | `api-drf-specific.md`, "Pagination and filter leakage" |
| Client-composed documents | Depth, alias, token, and cost limits applied before execution, and batch size | `graphql-and-alternative-api-surfaces.md`, "Bounding the document: depth, aliases, tokens, and cost" |
| Long-lived connections | Message size and rate, queued work, fan-out, idle and absolute lifetime | `async-and-channels.md`, "Long-lived consumers and resource limits" |
| Database connections and query time | Pool `max_size` and a server-side statement timeout | `data-layer-and-database.md`, "Connection exhaustion and query timeouts" |
| A pattern run over input | An input length cap before the regex, and no pattern compiled from input | `a10-exceptional-conditions.md`, "Regular expressions and algorithmic cost" |
| Model tokens and tool calls | Per-agent cost and concurrency budgets | `agent-and-llm-interfaces.md`, "Cost and concurrency limits, not only request rate" |

Rate severity on the cost of one request, and on how repeatable that request
is. Do not rate it on the words "denial of service". A single call that holds
a worker for minutes or exhausts the connection pool is High. A bound that is
only generous is a hardening finding.

**Write-time.** Sometimes the work of an endpoint, a serializer, or a parser
scales with something in the request. Write the ceiling into that same
declaration. Put `max_page_size` beside `page_size_query_param`. Put a depth
or count limit beside the field that accepts the nested input. Put
`.iterator()` and an explicit field list on a read that will grow.

The value that makes the bound obviously necessary exists only in production,
and by then the endpoint has callers that depend on its absence. Where the
caller does not need to choose the size, do not expose the parameter. Nobody
can set a bound wrong where the bound is unreachable.

## Business-logic abuse

Maps to CWE-840 (Business Logic Errors) and CWE-841 (Improper Enforcement of
Behavioral Workflow). Maps also to CWE-472 (External Control of
Assumed-Immutable Web Parameter), wherever the client supplies a value that
the server had to resolve itself. OWASP API6:2023 Unrestricted Access to
Sensitive Business Flows is the API-security mapping.

### Principle layer

The severity rubric already rates manipulation of money, orders, and balances
at the Critical tier. `a10-exceptional-conditions.md` already carries the
mechanics that hold such a flow together under concurrency. Neither one
answers the first question: **which paths in this codebase move money,
credits, entitlements, or durable status at all.** A reviewer who does not
enumerate them reads the checkout view, because its name is `checkout`. That
reviewer never opens the management command that grants the same credit with
no view.

The work therefore runs in three steps, and the order matters. Enumerate every
transition that writes one of those values, and include the transitions that
reach no view. For each transition, ask whether the database holds its
invariant, or only Python holds it. Then ask what a failure part-way through
leaves behind. Three such remnants are a captured payment with no local order,
an entitlement with no subscription, and a status that a retry can enter
twice.

A flow is worth attacking where a request passes every validator and still
produces a result the business would refuse. Five such results exist. They are
an order that ships with no payment, and a plan that upgrades with no charge.
They are also a coupon that redeems twice, a refund larger than the capture
behind it, and a trial that restarts. None of these is a defective line of
code. They therefore survive both a diff review and a scanner, and the
enumeration is the control.

### Django & DRF implementation layer

#### Finding every path that moves money or status

Start from the data rather than from the views. The views are the subset that
a reviewer finds anyway. Run three sweeps. The flow inventory is their union.

**The fields.** Read the model layer for the value, and not for the vocabulary
of one domain. Look for a balance, a quantity, a price or amount, a currency,
and a credit. Look also for a plan, a tier, a role, a seat, and an expiry.
Look for any field named `status`, `state`, or `is_active`.

The second wallet usually lives in a `DecimalField` or a
`PositiveIntegerField`, on a model whose name is not obviously financial.
Record each field against its model. Every sweep below searches for code that
writes one of them.

**The transitions.** For each recorded field, find every assignment to it.
Find every queryset call that can set it. The views are the half that is easy
to find. The other half decides the review. It is every writer of the same
field that passes through no view:

- management commands under `<app>/management/commands/`, which run with no
  request, no permission class, and often no transaction;
- Celery tasks and beat schedules, which write on a redelivery as readily as
  on the first attempt;
- admin actions and a `ModelAdmin.save_model` override, which reach an
  operator's fingers and no serializer at all;
- signal receivers, which write in response to another model's save and are
  skipped entirely by the bulk paths below;
- data migrations, which write once, under the invariants of the day they were
  written, and are never re-reviewed;
- `update()`, `bulk_create()`, and `bulk_update()` on a queryset, which write
  with no `save()`, no `full_clean()`, and no save signals.
  `QuerySet.delete()` belongs here too, because it does not call the model's
  own `delete()`. `api-drf-specific.md`, "Bulk endpoints" owns the
  authorization half;
- `.raw()`, `.extra()`, and `connection.cursor()`, which reach the column
  with no model code above them at all;
- `loaddata` and any import feature behind it, which write through
  `save_base(raw=True)`. Such a write skips the model's own `save()`
  completely. See `a08-integrity-and-deserialization.md`, "Insecure
  deserialization".

`scripts/entrypoint_inventory.py` produces the entry-point half of this sweep.
It reports routes at their resolved prefixes, and router registrations and
actions. It also reports tasks, commands, signals, admin, and middleware.
`01-audit-workflow.md`, "Phase 1 — entry-point inventory" owns how to run it,
and what it structurally cannot see.

This section adds the question to ask of each row that it returns. Ask which
of the recorded fields this entry point can write. Ask which of the paths
above it uses.

**The external events.** The last sweep is where an inbound callback meets a
state machine. Four sources drive a transition on an event that this codebase
did not originate. They are the webhook of a provider, the callback of a
partner, a scheduled reconciliation job, and a queue consumer. The guard on
the transition is therefore the only control between a forged or replayed
event and a status change.

Enumerate them with the receivers themselves. Look for a `csrf_exempt` POST
route, a view with `authentication_classes([])`, and any handler that reads
`request.body`. `a08-integrity-and-deserialization.md`, "Webhook and callback
integrity" owns what such a receiver must prove before anything believes its
payload. This sweep is about what the payload may then change.

Ask one more question of each recorded field. Does a writer of it live
outside this codebase? A second service, a reporting job, and an operator
console all reach the same table. A conditional `update()` guards the caller
you can read, and a constraint guards the writer you cannot. Where another
system shares the database, only a constraint holds the transition.

The inventory is finished when every recorded field has a complete list of
writers. It is not finished when the views look covered. Where you sampled the
writers of a field rather than enumerated them, record that field as sampled.
Follow the budget rule in `01-audit-workflow.md`.

**Write-time.** You can generate a model field that holds a balance, a price,
a quantity, or a credit. The same applies to a plan or tier, an expiry, and a
status. In that same change, write down which code may write the field. Give
the field its database constraint there.

Somebody who has not read the first writer always adds the second writer
later, and the field is the only place where all writers meet. You can also
generate one of the non-view writers above, such as a command, a task, an
admin action, a receiver, or a data migration. State which of those fields it
writes before you write its body. The path that skips the serializer also
skips every check inside that serializer.

#### The invariant question

For each transition you find, one question decides the finding: **is the
invariant enforced by the database, or only by Python?** The database is the
only layer that every writer in the sweep above shares. An invariant held
anywhere else holds only on the paths that somebody remembered.

| The invariant | The database form | The form that holds on one path only |
|---|---|---|
| A value stays in range — non-negative, non-zero, at most a ceiling | `CheckConstraint(condition=Q(balance__gte=0))` | `if balance >= amount:` before a `save()` |
| At most one live row of a kind — one active subscription, one redemption per coupon per account | `UniqueConstraint(fields=[...])`, with `condition=Q(cancelled_at__isnull=True)` where a cancelled or superseded row must stop blocking a new one | `.exists()` before a `.create()` |
| A transition runs from exactly one prior state | `.update()` filtered on that prior state, with the affected-row count as the answer | `get()`, an `if` on `status`, and a later `save()` |
| An arithmetic change applies to the committed value | `F("balance") - amount` | `obj.balance = obj.balance - amount` |
| A field is never set by a client | absent or read-only on every serializer, written server-side | a `validate_amount` on one of several serializers |
| A total over many rows stays inside a ceiling — the refunds against one capture, the discounts against one order | a running total on the parent row, moved by `F()` in the same transaction as the child row, under a `CheckConstraint` that bounds it | a check of each new row against the parent, one row at a time |

The right-hand column is not a list of defective code. Each entry is a check
that works in the one place where it runs. That is exactly why it survives
review. Four shapes account for most of them:

- **A Python comparison before a `save()`** is correct until a second caller
  interleaves with it. `a10-exceptional-conditions.md`, "Races, TOCTOU, and
  adversarial sequencing" owns the race mechanics. It owns the choice between
  a constraint and a lock. It also owns the four ways `select_for_update()`
  silently does nothing, and the conditional-`update()` and constraint forms
  above.
- **A `clean()` method** runs only where something calls `full_clean()`.
  Django's `save()` does not, so a `clean()` is enforced on the ModelForm and
  admin paths and nowhere else.
- **A serializer `validate_` method** is a check on one entry point. It is not
  an invariant. The sweep above exists because a field has other writers. A
  serializer method reaches none of them. It does not reach the command, the
  task, or the admin action. It also does not reach the second serializer that
  somebody adds for the mobile client.
- **A signal receiver** is skipped by every bulk path in the sweep. An
  invariant held in `post_save` therefore disappears when somebody rewrites a
  slow loop as `bulk_update()`. That rewrite has no connection to the
  invariant.

Two conditions remove a constraint that the model file declares. The database
then holds nothing, and the model still reads as though it holds everything.

- **A bounded column that accepts NULL.** A `CheckConstraint` rejects only a
  condition that is false, so `Q(balance__gte=0)` accepts a NULL balance. A
  `UniqueConstraint` counts two NULLs as two different values, so
  `fields=["coupon", "account"]` permits unlimited rows with no account. Make
  every column in `fields`, and every column that a check bounds, `NOT NULL`.
  The `condition=` column is the exception, because a partial constraint tests
  it for NULL on purpose.
- **A backend that does not support the form.** Django creates a
  `CheckConstraint` only where `supports_table_check_constraints` is true. It
  creates a `UniqueConstraint(condition=...)` only where
  `supports_partial_indexes` is true. Where either is false the migration
  applies with no error, and the constraint is absent. The system check
  reports `models.W027` or `models.W047`, and a warning stops no deploy. Run
  `manage.py check` on the project. Read either identifier as a missing
  invariant. Checked against the Django 6.0.7 source on 27 Aug 2026.

A constraint added to a table that already violates it fails at deploy time;
`a03-software-supply-chain.md`, "Migration and data-integrity safety" owns
sequencing that.

**Write-time.** When you generate a transition on any inventoried field, write
the invariant as a `CheckConstraint` or a `UniqueConstraint`. Put it in the
`Meta` of the model and in the migration, in the same change.

Express the transition itself as a conditional `update()` whose affected-row
count decides the outcome. A check in Python binds only the caller you write,
and the database binds every other caller.

`QuerySet.update()` compiles to one SQL statement. It runs no `save()`, sends
no `post_save`, and applies no `auto_now`. Checked against the Django 6.0.7
source on 27 Aug 2026. Name the side effects of the transition in that same
code path. Those are the invalidation of the cache, the copy of the
entitlement, and the timestamp. A revocation written as an `update()`
otherwise leaves the cached permission live for its full window.

A serializer `validate_` method is often the natural place to give the client
a good error. Write it in addition to the constraint, and not in place of it.
Its job is the message, and the job of the constraint is the guarantee.

#### Amount and currency binding

The server resolves price, currency, quantity limits, discount eligibility,
and tax from its own records, keyed by an identifier the client supplies. **A
client that sends an amount is proposing one**, and a flow that accepts the
proposal has moved pricing into the request body. The same rule holds for
anything derived from an amount. That includes a discount percentage, a tax
rate, a shipping cost, and a loyalty multiplier. It also includes the currency
of the total. A total that is correct in one currency and labeled as another
is a manipulation, and it passes every numeric validator.

In DRF the form is that the field is absent from the serializer, or read-only
on it. The code sets the value in `perform_create()` or in the service layer
below it. `api-drf-specific.md`, "Serializer exposure and mass assignment
(API3)" owns the exposure rules themselves, including why `read_only_fields`
does not reach a declared field.

```python
# Wrong: unit_price and currency are writable, so the order is priced by
# whoever sends the request, and quantity carries no ceiling at all.
class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ["id", "product", "quantity", "unit_price", "currency"]
```

```python
# Correct: the client names what it wants and the server resolves what that
# costs. Price and currency are read-only on the serializer and written from
# the catalog row, so no request body reaches them on this path -- and the
# CheckConstraint on the model holds them on the paths that are not this one.
class OrderItemSerializer(serializers.ModelSerializer):
    quantity = serializers.IntegerField(min_value=1, max_value=100)
    # A writable relation defaults to every row of the related table. See
    # api-drf-specific.md, "Serializer exposure and mass assignment (API3)",
    # for the tenant scope this queryset also has to carry.
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.filter(is_active=True)
    )

    class Meta:
        model = OrderItem
        fields = ["id", "product", "quantity", "unit_price", "currency"]
        read_only_fields = ["id", "unit_price", "currency"]


class OrderItemViewSet(viewsets.ModelViewSet):
    serializer_class = OrderItemSerializer
    permission_classes = [IsAuthenticated]

    # ModelViewSet also serves list, retrieve, update, and destroy. The
    # default queryset is every row, so the scope belongs here. See
    # api-drf-specific.md, "Where the object check runs, and the routes that
    # skip it".
    def get_queryset(self):
        return OrderItem.objects.filter(
            order__account=self.request.user.account
        )

    def perform_create(self, serializer):
        self.save_priced(serializer)

    # A PATCH moves the row to a costlier product while unit_price stays
    # read-only and keeps the old value. Every writer prices the row again.
    def perform_update(self, serializer):
        self.save_priced(serializer)

    def save_priced(self, serializer):
        product = (
            serializer.validated_data.get("product")
            or serializer.instance.product
        )
        serializer.save(unit_price=product.price, currency=product.currency)
```

A coupon or discount is the same rule with a second half. The eligibility test
belongs on the server. The redemption needs a uniqueness invariant behind it,
per coupon, per account, and per order. Without that invariant the code
permits a replay. That invariant bounds one redemption and not the set of
them. Many separately valid coupons on one order still need a ceiling on the
discount total and a floor under the order total.

Sometimes the reward goes to a referrer. The self-referral case is then a
check that the beneficiary and the actor are different principals. The
database can hold that check as a `CheckConstraint`, rather than a Python
comparison. That check binds a pair and not a group of accounts. Cap the
credit that one actor and one beneficiary can mint inside a window.

**Write-time.** When you generate an endpoint that prices, charges, discounts,
or credits anything, accept only identifiers and quantities from the request.
Resolve every monetary value from the server's own row, on every write path.
`perform_create()` alone leaves the update path priced by the first request.
Either price the row again there, or refuse the change to the field the price
depends on. A field that is only validated is still a field the client chose.
Give the quantity its `min_value` and `max_value` on the serializer field, in
the same edit. Put that same range in a `CheckConstraint` on the model, so
that the command, the task, and the bulk write meet it too. A negative or
very large quantity multiplied by a correct price is the same manipulation
through arithmetic.

#### Capture, refund, and reversal

Each of these is a transition that must happen exactly once. An event from a
system you do not control drives each one. Each therefore inherits two sets of
mechanics. `a08-integrity-and-deserialization.md`, "Webhook and callback
integrity" owns the signature, the timestamp, the replay tolerance, and the
event de-duplication that the callback must satisfy.
`a10-exceptional-conditions.md`, "Idempotency" owns the key, the request
fingerprint, and the stored response. Neither is restated here.

What A06 owns is the design question those mechanics serve, and it is three
questions about the flow rather than about the handler.

- **Which transitions are irreversible?** Four events leave the control of
  your database at the moment they complete. They are a settled capture, a
  delivered email, a file handed to a third party, and a payout that has left.
  A transaction can roll back everything before such a step. It can roll back
  nothing after it. The order of the irreversible step against the commit is
  therefore the design. See `a10-exceptional-conditions.md`, "Side effects and
  the commit boundary".
- **Which are compensating rather than reversing?** A refund is a second,
  forward transaction that happens to move value the other way. It is not an
  undo: it has its own identifier, its own failure modes, its own fees, and
  its own reasons to be refused. A model of a refund as a status change back
  to the previous state loses the record that both events happened. A system
  that cannot tell "never charged" from "charged and refunded" cannot answer a
  dispute. It also cannot bound the refunds already made against the capture
  behind them.
- **What does a partial failure leave behind?** The gap between the external
  system and the local record is the one place a transaction cannot reach.
  Either side can succeed alone. A capture that settled while the response
  timed out leaves money taken and no local order. A local order marked paid
  before the provider confirmed leaves goods shipped against nothing. Decide
  which direction the flow fails in. Make the recoverable side the side that
  retries. Give the pair a reconciliation path that reads the record of the
  external system, and not the local one.

The severity follows from the third question rather than from the first two.
Where a reconciliation job can recover a partial failure, that failure is a
design finding. Where the failure silently grants goods, credit, or an
entitlement, it is the Critical-tier impact that the rubric names.

**Write-time.** When you generate a capture, refund, or reversal path, write
the local record and the external call as two steps in a stated order. Write
the durable row first. Register the irreversible call through
`transaction.on_commit()`. Give the flow a status that separates attempted,
confirmed, and reconciled, rather than a boolean. The reconciliation job
cannot repair a state that the model cannot represent.

Store the identifier of the provider for that operation on the local row, in
the same edit. It is the only key that a later reconciliation can join on. It
is also the only key the handler may use to find the row. A payer chooses the
metadata and the reference fields of a checkout, and a handler that reads its
target from those fields applies one payment to another account's order.
`a08-integrity-and-deserialization.md`, "Binding the event to a tenant" holds
the same rule for the tenant.

#### Entitlement grant and revocation

The question for every entitlement is whether the grant and the revocation are
symmetric. A grant is a deliberate feature that someone specified, tested, and
demonstrated. Revocation is a consequence that nobody demonstrates. The
asymmetry therefore lives there, and the failure is silent. The customer keeps
what they stopped paying for, and nothing raises an error.

Four shapes cover most of it, and each has a different owner for its
mechanics.

- **The entitlement that survives its subscription.** The plan lapses,
  cancels, or fails a renewal. Nothing then revisits the row that grants
  access. The author wrote that grant as a durable fact, rather than as a
  derivation from the current state of the subscription.

Prefer a derivation of the entitlement from the subscription at read time.
Where performance needs a materialized copy, the revocation path is a feature.
Somebody must write and test it. It is not an implication.
- **The seat that survives its removal from a team.** Membership is deleted
  and the objects, invitations, API tokens, and shares created under it stay
  live and still resolve. Enumerating what a principal's access reaches, so
  that removing the principal reaches all of it, is
  `authorization-architecture.md`, "Permission-model decay and access review".
- **The cached permission that outlives the role change.** The decision was
  correct at the moment of computation. It now comes from a cache, a session,
  or a denormalized column. It can also come from a token whose claims were
  minted before the change. A revocation that does not invalidate the cache is
  a revocation with a latency nobody has measured; state the window and make
  it deliberate.
- **The trial that can be restarted.** A trial, an introductory rate, a
  one-per-account credit, and a first-order discount are all the same
  invariant. That invariant is at most one per identity, for the life of that
  identity. It fails where a caller can create the identity again.

Key the uniqueness on something durable, and hold it with a
`UniqueConstraint`. A plus-address or a re-registration defeats a check
against an email address. That check is against the wrong column.

The row that holds this invariant must also outlive the account. A cascade
removes it on deletion, and the next registration starts the trial again. Keep
a record that survives the identity, and hold no personal data on it.
`data-lifecycle-and-privacy.md`, "Where a record survives" owns what such a
record may keep.

The revocation is sometimes a deletion rather than a state change.
`data-lifecycle-and-privacy.md`, "Where a record survives" owns whether the
copy is gone. The search index, the export, and the cache each hold their own
copy of the revoked item.

**Write-time.** When you generate an entitlement grant, write its revocation
in the same change. Name what triggers that revocation: cancellation,
non-payment, role change, membership removal, or expiry. A grant with no
revocation path is a permanent grant with a plan to write one.

Derive the entitlement from the subscription or the membership at read time,
where the query allows it. A derived entitlement cannot fall out of step with
its source. Materialise it only with an invalidation path beside it.

### Money and entitlement review checklist

#### Stack-neutral

- [ ] Every field that holds a balance, price, quantity, currency, or credit
      has a complete list of the code that writes it. The same holds for a
      plan, tier, seat, expiry, or status. That list includes the writers that
      pass through no request.
- [ ] The datastore enforces the invariant of each such transition, rather
      than a check on one entry point. A serializer or form validator counts
      as a message, and not as a guarantee.
- [ ] Prices, currencies, discounts, tax, and quantity ceilings resolve from
      server-side records. A client-supplied identifier keys those records. No
      monetary value comes from the request body.
- [ ] Coupons, referrals, invitations, and trials carry a uniqueness invariant
      keyed on something the caller cannot re-mint, and self-referral is
      excluded.
- [ ] Capture, refund, and reversal each happen exactly once, and an
      authenticated event drives each one. The flow states which direction a
      partial failure fails in, and what reconciles it.
- [ ] Refunds and other compensating actions are modeled as forward
      transactions with their own identifiers. They are not a status change
      back to the prior state.
- [ ] Every entitlement grant has a revocation path with a named trigger. The
      caches, tokens, sessions, and denormalized copies it has to reach are
      enumerated.

#### Django & DRF

- [ ] The inventory covers management commands, Celery tasks and beat
      schedules, and admin actions with `save_model`. It also covers signal
      receivers, data migrations, `update()`, `bulk_create()`,
      `bulk_update()`, and `loaddata`. It covers raw SQL and every writer
      outside this codebase. It covers more than viewsets and views.
- [ ] Every column in a `UniqueConstraint` `fields` list is `NOT NULL`, and
      so is every column a check bounds. `manage.py check` reports no
      `models.W027` and no `models.W047`. A sum over many rows carries its own
      ceiling, beside the constraint on each single row.
- [ ] Value bounds are `CheckConstraint`s, and "at most one live row" is a
      `UniqueConstraint`. That constraint carries `condition=` where a
      cancelled or superseded row must stop blocking. Both appear in
      `Meta.constraints` and in a migration.
- [ ] State changes are a conditional `.update()` whose affected-row count is
      the guard, rather than `get()` → `if` → `save()`. That same code path
      runs the invalidation and the timestamp that `.update()` skips.
- [ ] Monetary fields are absent or `read_only` on every serializer that
      reaches them and are written in `perform_create()` or the service layer.
      Every route that can change what the price depends on prices the row
      again, or refuses that change.
- [ ] Irreversible external calls are registered with
      `transaction.on_commit()`, and the provider's own operation identifier
      is stored on the local row for reconciliation. That identifier, and no
      payload field, resolves the row a callback changes.

## Abuse of side-effecting actions

The notification material below is the worked instance of a wider pattern.
That pattern decides whether a flow this section never names still needs a
bound. **A caller can trigger an action that consumes a limited resource,
notifies a third party, or performs irreversible work. Any such action is a
flow worth attacking, whether or not it sends mail.**

Invitations and shares belong to it, and so do exports and generated reports.
Magic links, referral and promotional credits, and outbound webhook deliveries
belong to it. So do re-index and re-send operations, and every "resend",
"retry", and "regenerate" control. Each is a valid request whose cost lands
somewhere the caller does not pay.

Three properties put a flow in this class, and any one of them is enough. The
flow spends a budget that is not the caller's, such as money, model tokens,
the send quota of a provider, or a worker pool. The flow reaches a third
party, so the harm falls on a person who made no request. The flow cannot be
undone, so a duplicate is not a duplicate of a read.

This file decides which of them need a limit. `api-drf-specific.md`,
"Throttling as quota, not security (API4)" owns the mechanics. That section
says why a configured rate is not the effective one. It also gives the owned
atomic counter that a limit needs in place of a throttle class, where the
limit must hold.

The same question has a consumption side. There the caller controls the work
of one request, rather than the number of requests. "Algorithmic resource
exhaustion" above owns that side.

**Write-time.** When you generate any action that spends a budget, contacts a
third party, or cannot be undone, give it a per-principal bound. Give it an
idempotency story in that same change.

A developer identifies the need for a bound exactly once, at the moment of
writing. After that the flow has callers. Where the bound is security-relevant
rather than a fair-use quota, make it an atomic counter or a database
constraint. Do not make it a throttle class. The DRF file above gives the
reasoning.

## Email and notification abuse

Maps primarily to CWE-799 (Improper Control of Interaction Frequency),
CWE-204 (Observable Response Discrepancy), and CWE-918 (SSRF), with overlap
across OWASP A06:2025, A07:2025, API4:2023, and API6:2023.

### Principle layer

An endpoint that sends email, SMS, push notifications, invitations, shares, or
previews transfers money, reputation, and attention. It sometimes transfers
credentials.

An attacker can drive a valid workflow as a spam relay or a mailbox-flooding
tool. An attacker can also drive it as an account-enumeration oracle or an
SSRF client. One invariant applies. **A notification trigger must disclose no
target existence. It must be bounded across every useful abuse dimension. It
must authorize both the action and its destination.**

- Return the same status and body whether the reset, magic-link, or invitation
  target exists or does not exist. Keep the response path materially similar
  in both cases. Do not use a literal sleep as the primary timing defense.
  Queue a uniform request shape, and keep the observable request path small.
- Layer the limits across several dimensions. Those dimensions are the source,
  the unauthenticated client, the authenticated actor, and the tenant. They
  are also the normalized destination, the target account, the template or
  action, and the time window. Include cooldowns, rolling windows, and daily
  caps. Include caps on concurrent and outstanding tokens, and global circuit
  breakers. A caller can bypass a single IP limit, and an attacker can use a
  single destination limit to deny a victim service.
- **An attacker also uses the limit.** Normalize a destination onto the
  mailbox that receives it. A plus-suffix and a letter-case variant reach one
  inbox under two keys. Scope a circuit breaker to one flow class and to one
  tenant, so volume elsewhere cannot suppress a reset message.
- Authorize every invite and share action. Constrain the recipients, the role,
  the object, and the template. Constrain the sender identity and the redirect
  or link destination. Never let a client supply an arbitrary message
  template, sender header, or URL.
- Deduplicate the enqueue and send operations, and make them idempotent. A
  retry must not send a duplicate. It must not create an extra valid token,
  and it must not bypass a quota.
- Treat a remote image, document, Open Graph, or link-preview fetch as SSRF.
  Allowlist the schemes and the destinations. Resolve and reject a private or
  link-local address. Check the redirects again, and cap the time and the
  response bytes.
- Log aggregate outcomes and abuse signals without recording reset tokens,
  magic links, message bodies, or unnecessary destination data.

### Django & DRF implementation layer

Django's password-reset views use a generic success flow, but the real-account
path performs more work and may send mail while a nonexistent account does not.
Keep the HTTP response generic and enqueue the same normalized request shape for
background handling after edge and application limits. The worker may determine
that no eligible account exists, but that outcome must not be reflected to the
caller. Build links from a configured canonical application origin, not an
untrusted `Host` header.

DRF throttles are quota tools and can be fuzzy under concurrency; they are not
the sole control for reset, magic-link, invite, share, or messaging abuse. Add
edge controls plus atomic Redis/database counters or a maintained limiter.
Store rate keys as keyed digests when raw destinations would expose personal
data. Apply destination and target-account limits silently so the response does
not become an enumeration oracle.

For reset and magic-link workflows:

- use Django's time-bounded reset tokens or a cryptographically random,
  single-use, hashed-at-rest token;
- bind the token to the intended account, purpose, and redirect allowlist;
- cap outstanding valid tokens and invalidate or supersede them on use,
  password change, email change, or account disablement; where that cap is
  full, supersede the oldest token rather than refuse the request, because a
  refusal denies the owner their own recovery;
- do not auto-login or reveal account state merely because a request was made;
  and
- notify the account of meaningful security changes without placing a usable
  credential in logs or analytics.

For an invite or share workflow, load the shareable object through a
requester-scoped queryset. Cap the recipient count and the privilege. Reject
self-escalation and a cross-tenant target. Require a verified sender identity
where that applies. Make a repeated submission idempotent.

Security-relevant database state and outbound messages must not disagree. Write
the durable event in a transaction and enqueue only after commit:

```python
from functools import partial

from django.core.exceptions import PermissionDenied
from django.db import transaction


def create_invite(*, actor, project, recipient_email, idempotency_key):
    if not project.admins.filter(pk=actor.pk).exists():
        raise PermissionDenied
    # The limit store is another service. A call to it inside the atomic
    # block below would hold a database connection for that whole call.
    enforce_invite_limits(
        actor=actor,
        tenant=project.tenant,
        recipient_email=recipient_email,
    )
    with transaction.atomic():
        invite, _ = Invite.objects.get_or_create(
            project=project,
            created_by=actor,
            idempotency_key=idempotency_key,
            defaults={"recipient_email": recipient_email},
        )
        transaction.on_commit(
            partial(enqueue_invite_once, invite_id=invite.pk),
        )
    return invite
```

The `get_or_create()` above is race-safe only because a unique constraint on
`(project, created_by, idempotency_key)` exists in the model and in a
migration. Without that constraint it silently creates duplicates under
concurrent submits. That duplicate is the failure this flow exists to prevent.

The actor is in that key because the key is a string the client chose. Two
members of one project can send the same string, and a scope without the actor
answers the second member with the invite of the first.

Keep every call to another service outside the atomic block. Such a call holds
the database connection until it returns, and a slow limit store then drains
the pool from a flow that looks bounded.

The worker must also be idempotent and re-check that the invite is pending,
unexpired, and still authorized before sending. Do not put full message bodies,
tokens, or unnecessary personal data in task arguments.

An email-preview or unfurl endpoint must use the SSRF controls in A01. Those
controls are approved schemes and destinations, and DNS and IP checks before
the connection. They also are redirect revalidation, strict connect and read
timeouts, and a response-byte cap. The endpoint carries no ambient cloud
credential, and reflects no raw upstream response. Prefer fetching in a
network-isolated worker.

Header injection remains covered in A05. Queue serialization and webhook
integrity are covered in A08; sensitive log handling is covered in A09.

### Notification-abuse review checklist

#### Stack-neutral

- [ ] Reset, magic-link, invite, share, and messaging endpoints return a
      non-enumerating response and follow a materially uniform request path.
- [ ] Atomic limits cover source, actor, tenant, destination, target, action,
      cooldown, outstanding state, and global volume. They do not enable a
      trivial denial of service against one destination.
- [ ] Recipients, roles, objects, templates, senders, and link destinations are
      server-authorized and allowlisted; retries and duplicate requests are
      idempotent.
- [ ] Tokens are purpose-bound, short-lived, single-use, hashed at rest where
      stored, capped, and revoked on relevant account changes.
- [ ] Preview fetches use full SSRF defenses and bounded, isolated processing.
- [ ] Logs, queues, and analytics contain no usable token, magic link, message
      body, or unnecessary destination data.

#### Django & DRF

- [ ] Password-reset/magic-link requests use generic responses, a canonical
      configured origin, and a queue path that does not expose account existence.
- [ ] DRF throttling is supplemented by edge limits and atomic application
      counters for security-sensitive notification flows.
- [ ] Invite/share objects are loaded through requester-scoped querysets, and
      outbound work is registered with `transaction.on_commit()`.
- [ ] Workers deduplicate and re-check pending, expiry, and authorization state
      before sending.

## Secure defaults and limits

- Enforce a hard request-body limit at the reverse proxy/gateway, plus
  endpoint-specific per-file, aggregate, count, processing, and per-principal
  quotas (see `file-uploads.md` and deployment).
- `DATA_UPLOAD_MAX_MEMORY_SIZE` excludes uploaded-file bytes, while
  `FILE_UPLOAD_MAX_MEMORY_SIZE` is the memory-to-temporary-file threshold; do
  not describe either as a hard file-size rejection control.
- `DATA_UPLOAD_MAX_NUMBER_FIELDS` and `DATA_UPLOAD_MAX_NUMBER_FILES` cap form
  and multipart complexity. Do not raise either one without a reason.
- Database connections are an exhaustible resource with a hard server-side
  ceiling. Cap them at a pool you control, rather than at the worker count.
  Set a server-side statement timeout, so that one slow query cannot hold a
  connection without end. See `data-layer-and-database.md`.
- New features should default to the least-privileged, least-exposed setting;
  opening up is a deliberate act.

**Write-time.** Some generated flows cost something to run, such as mail,
money, model tokens, an export, or a third-party call. Give such a flow its
limit in the same change that introduces it. Key that limit on the principal,
and not on the address. A flow ships without a limit exactly once, and
somebody then writes the limit under incident conditions.

Where the flow is security-sensitive, that limit must be an atomic counter or
a database constraint. It must not be a throttle class. `api-drf-specific.md`,
"Throttling as quota, not security (API4)" holds the distinction and the
mechanics behind it.

## Review checklist

- [ ] Login and every sensitive flow have real anti-automation, which is
      lockout plus limits. DRF throttles alone are not enough.
- [ ] Every expensive flow caps cost and concurrency per principal identity,
      and not only requests per minute. No such limit is keyed on IP for a
      machine caller.
- [ ] Every caller-controlled value that multiplies work has a ceiling that
      the server enforces. Those values are the page size, the offset, the
      depth, the nesting, the date range, the length of a JSON list body, and
      the batch or expansion factor. The ceiling produces a rejection, and not
      an out-of-memory kill.
- [ ] Every path that moves money, credits, entitlements, or durable status is
      enumerated from the fields that hold those values. That enumeration
      includes the writers that pass through no view. The database holds the
      invariant of each transition, rather than the validator of one entry
      point.
- [ ] The server resolves the money, the quantity, and the discount.
      Idempotency is enforced, with a unique constraint behind the key rather
      than a Python check.
- [ ] Replayable/self-referable business flows are constrained, and every
      entitlement grant has a revocation path with a named trigger.
- [ ] Actions that spend a budget, notify a third party, or cannot be undone
      carry a per-principal bound, whether or not they send mail.
- [ ] Notification triggers are non-enumerating, authorized, idempotent, and
      bounded by source, actor, tenant, destination, target, and global
      volume.
- [ ] Upload/body/count/processing limits exist at edge and application
      layers; Django memory thresholds are not mistaken for hard upload caps.
- [ ] Database connection concurrency is bounded by a pool and queries are
      time-limited server-side, rather than left to worker count.
