# RustyAuth authorization-platform direction

**Status:** Product and architecture direction; not an implemented or committed roadmap

**Date:** 7 August 2026

**Source:** [The Permission Architecture Problem Every Developer Faces](https://www.youtube.com/watch?v=AAEnEKT0GhY)

**Companion strategy:** [RustyAuth future product strategy: agent authority](FUTURE_FEATURES.md)

This document preserves the authorization lessons extracted from the source video, evaluates them
against the current RustyAuth implementation and records the resulting product direction. It is a
companion to the agent-authority strategy, not a replacement for it.

Nothing described here should be presented as shipped or committed until it has an explicit roadmap
decision, an architecture decision record, a threat model, implementation, tests and release
documentation.

## Executive decision

The source video's main lesson is correct: enterprise authorization cannot stop at broad labels such
as `admin`, `editor` and `user`. RustyAuth, however, should not become a generic application-role
database or attempt to own every application's business authorization data.

RustyAuth should add an authorization kernel built around:

```text
organisation
    -> principal
    -> action
    -> resource
    -> conditions
    -> grant
    -> decision
    -> receipt
```

Roles should be reusable authority profiles, not the fundamental unit of enforcement. The protected
application or provider remains authoritative for its business objects and native controls.

This direction supports the more differentiated product thesis already recorded in
`FUTURE_FEATURES.md`:

> Passkeys for people. Purpose-bound authority for agents.

The source video should therefore influence RustyAuth's policy structure, audit evidence, tenant
boundary and enforcement APIs without causing the project to pivot into a conventional enterprise
identity suite.

## Source-video findings

The source video makes the following substantive recommendations.

### Granular permissions

Permissions should describe an action on a resource, using discoverable names such as:

```text
users.create
users.read
reports.update
finance.approve
analytics.view_confidential
```

Broad labels such as `manage_users` or `admin_access` are too imprecise for least privilege,
explanation and audit.

### Four inputs to an authorization decision

An access-control system must determine:

1. Who is acting?
2. What action is requested?
3. Which resource is affected?
4. Under what conditions is the operation allowed?

The conditions may include ownership, department, team, resource state, role level, time, tenant,
environment and other trusted context.

### RBAC as a foundation

Conventional role-based access control groups permissions into reusable roles and assigns those
roles to users. A normalized relational implementation commonly starts with users, roles,
permissions, user-role assignments and role-permission assignments.

The video then extends that foundation with:

- multiple simultaneous roles per user;
- direct, exceptional or temporary grants;
- module or namespace organization;
- department and team scope;
- resource ownership and state checks;
- time-based conditions;
- tenant isolation;
- feature or subscription inputs;
- audit logging; and
- controlled system-administration access.

This later hybrid model is more useful than the video's earlier claim that users should never
receive direct permissions. RustyAuth should represent exceptional access as explicit, expiring and
auditable grants rather than as unstructured user-permission links.

### Layered decision pipeline

The video proposes a decision pipeline that:

1. authenticates the caller;
2. loads all role assignments;
3. resolves role permissions;
4. applies direct grants, restrictions and temporary exceptions;
5. enforces the tenant boundary; and
6. evaluates contextual policies such as ownership, resource state, department and time.

Every required layer must pass. Missing policy or context must fail closed.

### Server-side enforcement and separation of concerns

Authorization must be enforced at a server-side boundary on every operation. Front-end visibility is
only a user-experience concern and is not an enforcement control.

Route-level enforcement should reject obviously unauthorized calls before business handlers run.
Resource and contextual policy should also be evaluated before a mutation. Authorization policy
should remain separate from the business operation itself so both can be reviewed and tested.

### Caching and invalidation

The video recommends caching resolved permissions per user and role because authorization is checked
frequently. It also correctly warns that stale authority is a security risk and that affected cache
entries must be invalidated when a role, permission or assignment changes.

The video's performance numbers are illustrative, not evidence for RustyAuth's design. SableDB is
already RustyAuth's online in-memory store, so a second cache layer should be added only after
measurement. Correctness requires policy and grant revisions in cache keys, deterministic
invalidation and fail-closed behaviour when freshness cannot be established.

### Audit and compliance evidence

The video expects sensitive operations and authority changes to answer:

- who acted;
- what they attempted and what happened;
- which resource was affected;
- when and from where it happened;
- which tenant was involved; and
- what changed.

It suggests actor ID, action, resource type and ID, timestamp, tenant, source IP and before/after
values. These are useful foundations, but ordinary mutable logs do not by themselves satisfy a
compliance framework or create legally conclusive evidence. RustyAuth additionally needs retention,
access control, redaction, integrity protection, monitoring and export.

### Security practices

The video closes with six practices:

1. grant least privilege;
2. avoid hard-coded role checks;
3. log critical actions and authority changes;
4. rate-limit even authenticated actors;
5. authenticate, authorize and validate every API endpoint server-side; and
6. validate the tenant boundary on every operation.

These practices are directionally correct. The design must also include deny-by-default semantics,
explicit conflict rules, authorization regression tests and safe failure behaviour.

## Current RustyAuth baseline

RustyAuth currently keeps a deliberately small identity boundary. It:

- authenticates people with passkeys;
- stores stable user UUIDs, profiles and canonical email or phone identifiers;
- supports multiple passkeys, labels, signature counters and last-used timestamps;
- keeps opaque bearer sessions server-side and validates idle, absolute and generation expiry;
- issues short-lived, audience-bound ES256 tokens;
- rotates signing keys with prepublication and retired-key overlap;
- creates encrypted and verified backups with a tested restore path;
- emits an ordered event log; and
- fails closed on missing or invalid security state.

The current architecture intentionally does not decide application roles, subscriptions,
entitlements or object ownership. A valid RustyAuth token proves authentication under the configured
relying party; it does not independently grant access to an application resource.

### Current durable state

The implementation stores:

- user, profile, identifier and passkey records;
- identifier and credential uniqueness indexes;
- short-lived registration and authentication ceremonies;
- server-side sessions;
- signing-key lifecycle state;
- ordered events; and
- development-only agent handoffs.

The current event representation has sequence, ID, configured tenant, event type, optional subject,
timestamp and a JSON data field. Event creation currently writes an empty data object, so these
events are not yet decision-grade audit evidence.

The current session representation records the user, authentication method, current credential,
session generation and lifecycle timestamps. It does not record source, device, user-agent,
interaction, risk or authorization context.

### Contracts under development

The worktree contains protobuf contracts for:

- organizations and operators;
- service accounts and credential exchange;
- metrics; and
- webhooks and delivery history.

These contracts are compiled, but the runtime RPC router currently registers only identity and event
services. They must not be treated as implemented product capabilities.

## Gap map

| Source-video capability | Current RustyAuth state | Direction |
| --- | --- | --- |
| Granular actions and resources | Not implemented | Add typed, versioned action and resource catalogs |
| Multiple roles | Not implemented | Use multiple authority-profile assignments |
| Direct and temporary permissions | Not implemented | Model as explicit, expiring grants with provenance |
| Ownership, department, state and time policy | Not implemented | Add deterministic conditions over trusted request context |
| Tenant isolation | One configured tenant per instance; durable keys are not tenant-prefixed | Design an explicit organization boundary before shared multi-tenancy |
| Decision API | Not implemented | Add a subject-action-resource-context evaluation API |
| Server-side authorization enforcement | Authentication enforcement exists; no general authorization PEP | Add gateway and SDK enforcement points |
| Decision-grade audit | Ordered minimal events; event data currently empty | Add decisions, mutations, receipts, integrity and retention |
| Source and interaction context | Not stored in sessions or events | Add privacy-reviewed IP, user-agent, request and trace context |
| Rate limiting and abuse controls | Not implemented | Add per-source, principal, organization and operation controls |
| Permission caching | No policy evaluation exists; SableDB is already in memory | Add revision-aware evaluation caching only when measured |
| Super-admin override | Not implemented | Provide an explicit break-glass workflow, never an invisible bypass |
| Agent principals and mandates | Future strategy only | Build first-class agent identities, grants and proof-bound capabilities |

## Durable authorization model

### Organizations

Store an explicit organization resource even while a deployment supports only one organization:

- `id`, `slug`, `name` and lifecycle `status`;
- `created_at`, `updated_at` and optional offboarding timestamps;
- current `policy_revision`;
- isolation mode and storage namespace metadata; and
- audit-retention and security-policy references.

Every authorization record and storage key must be organization-scoped. Organization context must be
derived from authenticated state, not trusted directly from a client-supplied header or parameter.

Adding `tenant_id` to records is necessary but not sufficient. Shared hosting also requires scoped
indexes and uniqueness constraints, tenant-aware cache and object-storage keys, storage-level
isolation where possible, cross-tenant negative tests and a reviewed onboarding and offboarding
lifecycle.

### People and memberships

Keep the global human identity separate from organization membership so one person can participate
in more than one organization.

Store membership records containing:

- membership ID, organization ID and user ID;
- active, suspended, invited and removed state;
- group, team and department references;
- validity and expiry;
- source such as local administration, federation or SCIM;
- created-by, changed-by and change reason; and
- last review and removal timestamps.

RustyAuth should eventually federate with an existing employee directory instead of becoming the
authoritative enterprise directory itself.

### Principals

Use a common principal concept with distinct human, service-account, agent-blueprint and
agent-instance types. Do not erase the distinction between the person who approved authority and the
software workload exercising it.

For service accounts, store:

- organization, owner or sponsor;
- name, description, status and lifecycle timestamps;
- assigned profiles and grants;
- credential hashes or encrypted material references;
- credential hints, creation, expiry, use, rotation and revocation timestamps; and
- last use and emergency disablement state.

For agents, store:

- blueprint and runtime-instance IDs;
- organization and human or organizational sponsor;
- runtime type and lifecycle state;
- ephemeral public key or JWK thumbprint;
- creation, expiry, last-use and disablement timestamps;
- parent blueprint or agent instance where delegation applies; and
- runtime or workload attestation references where available.

The development handoff's `agent` authentication method must not become the production agent model.

### Action catalog

Store typed, discoverable and versioned action definitions:

- namespace or module, such as `github`;
- resource type, such as `repository` or `pull_request`;
- verb, such as `read`, `push`, `create` or `merge`;
- canonical action name;
- argument schema and supported constraints;
- risk classification;
- whether fresh or multi-party approval is required;
- connector compatibility and schema version; and
- active or retired state.

For example, prefer `github.pull_request.create` to `github.write`. Wildcards must have defined
semantics and must never accidentally include actions introduced after a grant was approved.

### Resource catalog

Store stable references and selectors rather than copying protected application data:

- organization and provider;
- external account or connection;
- resource type and canonical external identifier;
- optional parent resource;
- trusted classification labels; and
- lifecycle and synchronization metadata.

Resource ownership and state usually remain authoritative in the protected application or provider
and are supplied as trusted context when a decision is requested.

### Authority profiles

An authority profile is a reusable versioned policy template. It is not a credential and grants
nothing until assigned within an applicable scope.

Store:

- profile ID, organization, name and description;
- system or customer-defined origin;
- version and lifecycle status;
- included rule IDs;
- creator, approver and change reason; and
- creation, update, review and retirement timestamps.

Profiles may be assigned to human memberships, groups, agent teams, service accounts, individual
agent blueprints and bounded working sessions.

### Policy rules

Store deterministic policy rules with:

- `allow`, `deny` or `approval_required` effect;
- subject selector;
- action set;
- resource selector;
- typed condition expression;
- validity window;
- priority and explicit conflict semantics;
- version and status;
- creator, reviewer, reason and change ticket; and
- creation, activation and retirement timestamps.

Conditions may reference ownership, department, team, resource state, time, risk, environment and
trusted entitlement input. Missing required attributes must not silently make a rule more permissive.

The safe authority invariant is:

```text
effective authority
  = organization ceiling
  intersection person's delegable rights
  intersection provider connection rights
  intersection assigned profiles
  intersection current task grant
  intersection provider-native policy
```

Each layer may narrow the result. No lower layer may expand a higher ceiling.

### Assignments and grants

Represent both ordinary assignment and exceptional direct access explicitly. Store:

- grant or assignment ID;
- organization and subject principal;
- profile or constrained inline rule;
- resource scope;
- issuer or grantor;
- reason, ticket and approval references;
- `valid_from` and `expires_at`;
- maximum uses and current usage;
- parent grant and delegation depth;
- typed argument constraints;
- lifecycle status; and
- revocation time, reason and actor.

Parent-child delegation must obey:

```text
child authority subset-of parent authority
```

A child cannot add actions or resources, widen constraints, extend expiry, increase remaining uses or
exceed the approved delegation depth. Revoking a parent must make all descendants unusable.

### Approval records

Store approvals separately from grants so the system can prove what a person saw and approved:

- request and approval IDs;
- digest of the exact structured request;
- human approver and agent or service actor;
- action, resource and redacted constrained arguments;
- approve or deny decision and reason;
- passkey step-up session, authentication time and method;
- required and received approver count;
- policy and revision that required approval; and
- creation, expiry and consumption timestamps.

Do not store raw WebAuthn assertions, private key material or secrets in approval records.

### Capabilities

An issued capability should bind the approved authority to an identified holder. Store only the
state needed for validation, use limits and revocation:

- token or JTI hash, never the raw capability;
- organization, grant and approval IDs;
- issuer, audience and resource;
- proof-of-possession public-key thumbprint;
- action and constraint digest;
- issued, not-before and expiry timestamps;
- maximum and remaining uses;
- consumed, revoked and expiry state; and
- revocation actor and reason.

Where interoperability permits, use OAuth Rich Authorization Requests for structured authority and
DPoP for proof-of-possession token binding rather than inventing bespoke cryptography.

### Provider connections

Store:

- organization and provider type;
- external organization, workspace or account identifier;
- allowed resources and provider-granted ceiling;
- connection state and health;
- creator and administrator;
- secret-vault or encrypted credential reference;
- credential version and rotation metadata; and
- last validated, used, failed and revoked timestamps.

Agents must receive proof-bound capabilities or narrow local handles, not reusable provider tokens.
The gateway retains the underlying credential and performs the exact authorized operation.

### Authorization decisions

Every evaluation should produce a durable or appropriately retained decision record containing:

- decision, request, interaction and trace IDs;
- organization;
- human subject;
- agent or service actor;
- action and resource;
- sanitized trusted context or a canonical context digest;
- allow, deny or approval-required result;
- stable reason code;
- matched policy and grant IDs;
- policy and subject-grant revisions;
- decision timestamp and latency; and
- enforcement-point identity.

The interoperable API shape is:

```text
subject + action + resource + context -> decision
```

OpenID AuthZEN's Authorization API is the preferred Policy Enforcement Point to Policy Decision
Point boundary.

### Gateway receipts and audit events

Gateway receipts should add:

- grant, capability, approval and delegation-chain references;
- connector and provider;
- redacted argument summary and canonical digest;
- provider request or transaction ID;
- outcome and error class;
- before-and-after patch or digest where appropriate;
- source IP, user-agent and session reference;
- execution start, completion and latency;
- receipt signer or integrity metadata; and
- previous-record hash or other tamper-evidence mechanism.

Audit records need defined retention, redaction, encryption, read permissions, export and deletion
policy. Audit-log access must itself be audited. Raw tokens, session cookies, passkey assertions,
provider secrets and unnecessarily sensitive payloads must never be included.

### Rate limits and abuse state

Store rate-limit policies for relevant organization, source, principal, action and resource scopes:

- window, limit and burst;
- response or escalation action;
- policy version;
- exemption or break-glass rules; and
- monitoring and alert thresholds.

Usage counters may be transient unless billing, investigation or regulation requires longer
retention. Security events should record threshold violations and enforcement outcomes without
turning high-cardinality request data into an unbounded durable log.

### Policy and cache revisions

Store:

- organization policy revision;
- per-subject grant revision;
- resource/connector catalog revision; and
- latest successfully consumed invalidation sequence.

Any evaluation cache key must contain the revisions that influenced the result. Authority mutations
must commit their state change and invalidation event atomically or through a recoverable outbox
pattern. A stale cached allow must not survive revocation.

## Request-time context rather than duplicated state

RustyAuth should evaluate, but not necessarily own, fast-changing application facts. The enforcement
point should supply trusted context such as:

- current resource owner;
- draft, approved, deleted or locked resource state;
- current department or project relationship;
- provider-native branch protection or IAM result;
- current time and trusted environment attributes;
- transaction value and requested arguments; and
- subscription or feature entitlement from its authoritative system.

The policy schema must distinguish authoritative server-supplied attributes from untrusted caller
claims. Sensitive context may be reduced to typed facts or canonical digests for audit retention.

## Information RustyAuth should not store

Do not store:

- application business objects merely to evaluate ownership;
- raw provider tokens in agent-accessible state;
- passkey private keys or raw WebAuthn assertions;
- full sensitive provider request and response payloads by default;
- mutable feature-flag or subscription truth owned by another system;
- authorization cache entries as the source of truth;
- secrets, session cookies or bearer tokens in events and receipts;
- unbounded free-form policy code that cannot be deterministically validated; or
- long-lived mutable permission lists inside access JWTs.

Feature plans and subscription entitlements should remain in their authoritative system and be
supplied as trusted decision attributes. If RustyAuth later offers a separate entitlements product,
that must be an explicit product and trust-boundary decision.

## Corrections and cautions applied to the source video

### Pure RBAC is insufficient

The source video begins with RBAC but eventually adds enough contextual rules to approach attribute-
and relationship-based access control. RustyAuth should design directly for subject, resource,
action and environmental attributes while retaining roles or profiles as a convenient grouping
mechanism.

### Tenant IDs alone do not isolate tenants

Tenant columns or JSON fields protect nothing unless every key, index, query, cache, backup, object
path and enforcement path handles them correctly. Storage-level isolation and negative tests provide
defence in depth. RustyAuth must not claim shared multi-tenancy while its durable namespace remains
single-tenant.

### Super-admin should mean break glass

There should be no invisible `super_admin = true` bypass. Emergency access should require explicit
activation, fresh strong authentication, a reason, narrow scope, short expiry, notification,
enhanced audit and, for high-risk actions, a second approver.

### Direct permissions create long-term risk

Exceptions are sometimes necessary, but indefinite direct permissions create privilege creep and
make policy hard to explain. Direct access should be an expiring grant with provenance, review and
last-used information.

### Caching is not the source of truth

The video's claimed speed multipliers and query reductions are not design requirements. Cache only
after profiling. Versioned invalidation, tenant-aware keys and revocation correctness matter more
than a headline latency number.

### Logging does not automatically create compliance

Audit records contribute to security and compliance, but storing a few fields does not by itself
satisfy SOX, PCI DSS, HIPAA or another framework. Evidence quality also depends on integrity,
retention, monitoring, access control, operating procedures and the actual regulatory scope.

### Feature flags are inputs, not necessarily permissions

Product entitlement answers whether a customer purchased or was enabled for a feature.
Authorization answers whether this principal may perform this action on this resource now. They can
intersect in policy without being collapsed into one data model.

## Recommended implementation order

### Priority 0: complete the human trust foundation

- Account recovery and abuse-resistant recovery policy.
- Production email and phone verification delivery and consumption.
- Public revoke-all-sessions operation.
- A dedicated fresh passkey step-up ceremony.
- Authentication rate limiting and abuse telemetry.
- Stable event delivery, retention and scoped consumers.
- Cross-instance concurrency and multi-writer design.
- Broader protocol-negative and authenticator coverage.
- Independent security assessment.

Agent-authority prototypes may proceed alongside this work, but they must not be presented as
production controls while these gates remain open.

### Priority 1: establish the audit and organization substrate

- Implement the explicit organization resource and organization-scoped durable keys.
- Separate user identity from organization membership.
- Replace empty event data with typed, redacted mutation and security context.
- Add interaction, request and trace correlation.
- Define retention, export, webhook delivery and tamper-evidence mechanisms.
- Log every subsequent policy, profile, assignment, grant and revocation mutation from its first
  release.

### Priority 2: build the deterministic authorization kernel

- Principal model for humans, service accounts and agents.
- Typed action and resource catalogs.
- Versioned authority profiles and policy rules.
- Explicit grants, constraints, expiry and revocation.
- Default-deny conflict and missing-context semantics.
- Organization, subject and connector policy revisions.
- AuthZEN-compatible access-evaluation API.
- Unit, integration and cross-tenant authorization regression suites.

### Priority 3: add first-class agent authority

- Agent blueprints and ephemeral runtime instances.
- Human or organizational sponsorship.
- Ephemeral proof-of-possession keys.
- Structured mandates and passkey approvals.
- Parent-child attenuation and maximum delegation depth.
- One-use and time-bounded capabilities.
- Cascading revocation and decision receipts.

### Priority 4: prove enforcement with one connector

Build the GitHub reference path:

> Allow this agent to create a branch, push commits and open one draft pull request in
> `rusty-auth/rustyauth` during the next fifteen minutes. It cannot merge, change repository
> settings or access another repository.

The demonstration must prove:

1. Passkey approval of the exact structured mandate.
2. A separately identified agent with an ephemeral key.
3. A proof-bound, resource-specific, short-lived capability.
4. A gateway that retains the real GitHub App credential.
5. Rejection of replay, widening and use by another agent.
6. Immediate and cascading revocation.
7. A human-readable, tamper-evident receipt.

### Priority 5: scale and enterprise governance

- Revision-aware decision caching based on measured need.
- Access reviews and certification workflows.
- Dormant, unused and excessive-grant detection.
- Break-glass administration.
- SIEM and compliance-evidence export.
- Customer-hosted gateways and control-plane fleet management.
- Defined tenant onboarding, suspension, export, offboarding and deletion.

## Product boundary

The resulting platform should own:

- human authentication and approval;
- non-human and agent identity;
- organization ceilings, profiles, grants and deterministic decisions;
- proof-bound capabilities and revocation;
- provider-gateway enforcement; and
- decision receipts and audit evidence.

It should not own:

- arbitrary application business objects;
- every customer's employee directory;
- provider-native authorization policy;
- operating-system or agent-runtime sandboxing;
- product entitlements unless explicitly introduced as a separate product; or
- alternate credentials and execution paths outside its enforcement boundary.

The defensible claim remains:

> RustyAuth controls what agents can do through an organization's connected systems without giving
> those agents the underlying credentials.

## Standards and guidance

The design should prefer stable standards and authoritative security guidance:

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP Multi-Tenant Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [NIST SP 800-162: Guide to Attribute Based Access Control](https://csrc.nist.gov/pubs/sp/800/162/upd2/final)
- [OpenID Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
- [RFC 9396: OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396.html)
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449.html)

## Final direction

RustyAuth should not implement a generic `users`, `roles` and `permissions` feature and declare the
authorization problem solved. It should build a smaller but stronger authorization substrate in
which every decision can explain:

> Which human authorized which identified actor to perform which exact action on which resource,
> under which constraints, using which policy revision, and what proves the outcome?

That keeps the useful enterprise lessons from the source video while preserving RustyAuth's
differentiated agent-authority strategy.
