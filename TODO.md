# `openvpn.kill-duplicate-username` Follow-up Work

This document records the edge cases found while reviewing
`openvpn.kill-duplicate-username`. The review covers the current pull request
implementation as of 2026-07-18.

The feature keeps two encrypted, in-memory mappings:

- a username to the OpenVPN client that currently owns the username;
- a client identifier to its username, used to remove the first mapping after a
  `CLIENT:DISCONNECT` event.

Before accepting an authenticated client, the application loads the existing
username mapping and sends `client-kill <CID>` when a different client owns that
username. OpenVPN defines the CID as the identifier of the client instance killed
by `client-kill`; the session ID is a separate authentication-token identity. See
the [OpenVPN management interface documentation](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt).

## Summary

| Priority | Finding | Result |
| --- | --- | --- |
| P1 | A reused session ID with a new CID is treated as the same client | Two live OpenVPN client instances can use the same username |
| P1 | Duplicate mappings expire with `oauth2.refresh.expires` | A long-lived client becomes invisible to duplicate detection |
| P1 | A username change leaves the old username mapping behind | A later login can kill a client authenticated as another user |
| P1/P2 | A stale CID makes `client-kill` fail | Resolved: stale ownership is removed and the replacement login continues |
| P2 | Internal-token refresh has no username | Duplicate enforcement and mapping renewal are skipped during silent reauthentication |
| P2 | Duplicate state exists only in the local process | Restarts and multiple instances lose or partition duplicate ownership |
| P3 | Some accepted clients and username variants are not tracked | Bypassed or differently normalized identities can coexist |

## 1. Compare the OpenVPN client instance, not only the storage identifier

- **Priority:** P1
- **Status:** Open
- **Affected configuration:** `oauth2.refresh.use-session-id=true`

### Current behavior

When session-ID refresh is enabled, `currentClientID` and `getClientID` use the
session ID instead of the CID. `killDuplicateUsernameSession` considers a stored
and incoming client identical when only their `ClientID` values match:

- `internal/openvpn/types.go:57` selects the session ID as the client identifier.
- `internal/oauth2/handler.go:245` makes the same choice for interactive flows.
- `internal/oauth2/duplicate_username.go:82` skips `client-kill` when the stored
  and incoming client identifiers match.

This comparison does not verify that the stored CID and incoming CID also match.
OpenVPN clients can reuse an authentication-token session ID while reconnecting
with a new CID. The existing refresh tests already model a connection whose CID
changes while its session ID remains the same in
`internal/oauth2/refresh_test.go:651`.

### Failure sequence

1. CID 10 authenticates as `alice` with session ID `session-a`.
2. The mapping for `alice` stores `ClientID=session-a` and `CID=10`.
3. A reconnect or overlapping connection arrives as CID 11 with the same session
   ID and username.
4. The lookup returns the CID 10 mapping.
5. Because both logical client IDs equal `session-a`, the function returns without
   sending `client-kill 10`.
6. CID 11 is accepted while CID 10 can still be active.

### Required change

The same-client exception should identify the OpenVPN client instance. At a
minimum, it should require both the logical client ID and CID to match. A REAUTH
event for the same CID but a different KID must remain classified as the same
client and must not kill itself.

The intended identity rules should be stated explicitly:

- same CID, new KID: reauthentication of the current client;
- new CID, same session ID: a new OpenVPN client instance that must replace the
  old CID when both can be active;
- new CID, new session ID: a new client instance.

### Regression tests

- Store `alice` for CID 10 and session ID `session-a`.
- Authenticate `alice` for CID 11 and the same session ID.
- Assert that `client-kill 10` occurs before CID 11 is accepted.
- Reauthenticate CID 10 with a new KID and assert that CID 10 is not killed.

## 2. Decouple duplicate ownership from the refresh-token TTL

- **Priority:** P1
- **Status:** Open
- **Affected configuration:** all configurations; especially
  `oauth2.refresh.expires<=0`, disabled renegotiation, and long-lived sessions

### Current behavior

Duplicate mappings use the same `tokenstorage.InMemory` instance and expiry as
OAuth2 refresh tokens:

- `cmd/openvpn-auth-oauth2/root.go:75` creates the storage with
  `conf.OAuth2.Refresh.Expires`.
- `internal/oauth2/duplicate_username.go:124` stores duplicate ownership in that
  storage.
- `internal/tokenstorage/inmemory.go:83` assigns the configured expiry to every
  entry.
- `internal/tokenstorage/inmemory.go:104` deletes an expired entry when it is
  loaded.

The default expiry is eight hours. Configuration validation requires a refresh
secret only when refresh is enabled, but it does not require a positive expiry.
`internal/tokenstorage/inmemory_test.go:53` confirms that an expiry of zero makes
new entries immediately unavailable.

### Failure sequences

#### Long-lived connection

1. Alice connects and the duplicate mapping is stored for eight hours.
2. The VPN session remains active for longer than eight hours without an
   authentication path that stores the mapping again.
3. The mapping expires while the OpenVPN client remains connected.
4. A second Alice authenticates after the expiry.
5. No existing mapping is found, so the second client is accepted without killing
   the first client.

#### Zero or negative expiry

1. The operator enables `openvpn.kill-duplicate-username` and configures
   `oauth2.refresh.expires=0` or a negative duration.
2. Every duplicate mapping is already expired when it is read.
3. The feature appears enabled but never finds an existing owner.

### Required change

Duplicate ownership should live until the corresponding OpenVPN disconnect, not
until an OAuth2 token deadline. Possible approaches include:

1. add non-expiring entries to the storage abstraction for connection ownership;
2. keep duplicate ownership in a dedicated map whose entries are removed by
   disconnect handling;
3. introduce a separate, documented duplicate-session TTL and ensure active
   sessions renew it reliably.

If the implementation continues to depend on `oauth2.refresh.expires`, startup
validation must reject non-positive values when duplicate replacement is enabled,
and the dependency must be documented. Validation alone does not solve expiry for
connections that outlive the configured duration.

### Regression tests

- Use a short refresh-token expiry, keep a client logically connected beyond it,
  and verify that a second login still kills the first CID.
- Configure an expiry of zero with duplicate replacement enabled and verify that
  configuration fails with a clear error.
- Verify that a normal disconnect removes the non-expiring ownership record.

## 3. Remove the previous username mapping when a client changes username

- **Priority:** P1
- **Status:** Open

### Current behavior

`storeDuplicateUsernameSession` writes the new username-to-client mapping and
overwrites the client-to-username mapping. It does not load and delete the
username previously associated with that client ID. See
`internal/oauth2/duplicate_username.go:104`.

The username can change between authentication events because of an identity
provider rename, a changed token claim, or a changed username expression.

### Failure sequence

1. Session `session-a`, CID 10, authenticates as `alice`.
2. Storage contains `alice -> session-a` and `session-a -> alice`.
3. The same client reauthenticates as `bob`.
4. Storage now contains `alice -> session-a`, `bob -> session-a`, and
   `session-a -> bob`.
5. A different client authenticates as `alice`.
6. The stale `alice` mapping causes `client-kill 10`, although CID 10 is currently
   authenticated as `bob`.
7. A later disconnect of session A loads `session-a -> bob` and removes only the
   `bob` mapping. The stale `alice` mapping remains until expiry.

### Required change

Updating ownership for a client ID should be transactional under the existing
duplicate-session lock:

1. load the previous username for the client ID;
2. if it differs from the new username, remove the old username mapping only when
   it still points to this client ID;
3. store the new username-to-client mapping;
4. store the new client-to-username mapping;
5. roll back or return an error if any required storage operation fails.

### Regression tests

- Store a client as `alice`, then store the same client ID as `bob`.
- Assert that `alice` has no owner and `bob` owns the client.
- Authenticate another `alice` and assert that the client currently known as
  `bob` is not killed.
- Disconnect the renamed client and assert that no mapping for either name remains.

## 4. Treat a missing stale CID as successful cleanup

- **Priority:** P1/P2
- **Status:** Resolved

### Previous behavior

`KillClient` returned an error whenever OpenVPN responded with `ERROR:`. The
duplicate replacement path propagated every kill error and did not accept the new
client.

This is correct for management connection failures and command failures where the
old client may still be active. It is too strict when OpenVPN reports that the CID
no longer exists, because the requested end state has already been reached.

### Failure sequence

1. The old client disconnects in OpenVPN.
2. Its `CLIENT:DISCONNECT` event is queued, delayed, or lost before local cleanup
   removes the duplicate mapping.
3. A new client authenticates with the same username and loads the stale CID.
4. OpenVPN rejects `client-kill` because that CID is no longer present.
5. The application denies the new client even though there is no duplicate session.

If the disconnect event is merely delayed, one login attempt fails and cleanup can
then make a retry succeed. If the event is lost, attempts can fail until the stale
mapping expires or the process restarts.

### Resolution

OpenVPN's server implementation emits the exact response
`ERROR: client-kill command failed` when its CID lookup finds no active client.
`KillClient` now classifies only that response as `ErrClientNotFound`. The
duplicate replacement path handles that sentinel by:

1. removing the stale ownership records;
2. continuing with acceptance of the new client;
3. recording the stale mapping at debug level for diagnosis.

Other `ERROR:` responses, command timeouts, and management connection errors must
continue to fail closed. The exact match and a source comment protect against
treating unrelated error text as an absent client.

### Regression coverage

- The management callback test verifies that the exact OpenVPN response returns
  `ErrClientNotFound` while another error response remains `ErrErrorResponse`.
- The duplicate-session test verifies that stale mappings are removed and the new
  client is accepted when the old CID is absent.
- A separate test verifies that other kill failures still deny the new client and
  retain the existing ownership record.

## 5. Preserve username information during internal-token refresh

- **Priority:** P2
- **Status:** Open
- **Affected configuration:** `oauth2.refresh.enabled=true` and
  `oauth2.refresh.validate-user=false`

### Current behavior

When refresh validation is disabled, `RefreshClientAuth` returns an empty
`types.UserInfo` because the internal token stores profiles but not the resolved
username. The silent acceptance path passes this empty username to duplicate
handling, which deliberately skips all work for an empty username:

- `internal/oauth2/refresh.go:49` returns an empty user after decoding the internal
  token.
- `internal/openvpn/client.go:139` passes `user.Username` to duplicate handling.
- `internal/oauth2/duplicate_username.go:47` bypasses duplicate handling when the
  username is empty.

### Consequences

- Silent reauthentication does not check duplicate ownership.
- Silent reauthentication does not renew the ownership mapping if the current
  design continues using an expiring mapping.
- A mapping therefore expires after `oauth2.refresh.expires` even when OpenVPN
  regularly reauthenticates the active session.

An empty profile-selection username has a similar result. The profile callback
converts the configured omit marker back to an empty string before duplicate
handling in `internal/oauth2/handler.go:206`.

### Required change

Store the resolved username in the internal refresh token or in separate state
keyed by the logical client ID. Silent reauthentication should recover the same
canonical username used during initial acceptance. If username omission is an
intentional mode, document that duplicate replacement cannot enforce uniqueness
without a stable username and either reject the incompatible configuration or
define a safe fallback identity.

### Regression tests

- Authenticate Alice with refresh validation disabled.
- Perform silent REAUTH and verify that duplicate handling receives `alice`.
- Verify that the ownership record remains valid for the active connection.
- Cover the configured username-omit mode and assert the chosen documented
  behavior.

## 6. Define restart and multi-instance behavior

- **Priority:** P2
- **Status:** Open design decision

### Current behavior

Duplicate ownership uses process-local in-memory storage. `runLoop` creates an
empty `tokenstorage.DataMap` at process startup in
`cmd/openvpn-auth-oauth2/root.go:49`. The map is reused across the application's
in-process SIGHUP reload loop, but it is not preserved across a process or
container restart.

Separate `openvpn-auth-oauth2` processes also have separate ownership maps and
separate OpenVPN management connections. A process cannot issue `client-kill` for
a CID owned by another OpenVPN server.

### Consequences

- If OpenVPN preserves established clients while this application restarts, those
  clients are absent from the new ownership map.
- The first post-restart login for the same username is accepted without detecting
  the pre-restart client.
- Multiple application or OpenVPN instances enforce uniqueness only within each
  local instance, not across the deployment.

### Required change

Choose and document the intended scope:

- **Per process/OpenVPN server:** state explicitly that restarts clear ownership
  and that the setting does not provide deployment-wide uniqueness. If OpenVPN can
  list active authenticated clients, consider rebuilding state after reconnecting
  to the management interface.
- **Across instances:** use shared ownership with instance/server routing so the
  process that owns the old CID performs the kill. A shared username map by itself
  is insufficient because CIDs are local to an OpenVPN server.

The feature should not claim global single-session enforcement unless the second
model is implemented.

### Regression tests

- Exercise an in-process SIGHUP reload and verify that ownership remains intact.
- If restart recovery is implemented, start with an established OpenVPN client,
  recreate the application client, rebuild ownership, and verify replacement.
- If enforcement remains local, add configuration documentation that states the
  scope explicitly.

## 7. Define which identities participate and how usernames are compared

- **Priority:** P3
- **Status:** Open design and documentation decision

### Authentication bypass

Clients accepted through `openvpn.bypass.common-names` call `AcceptClient`
directly in `internal/openvpn/client.go:60`. They are not stored in the duplicate
ownership map. As a result:

- two bypassed clients with the same common name are not handled by this feature;
- a bypass common name equal to an OAuth2-resolved username does not participate
  in replacement.

Decide whether the setting applies only to OAuth2-authenticated usernames or to
all accepted OpenVPN identities. If bypassed clients must participate, route their
acceptance through duplicate handling with a clearly defined username. Otherwise,
document the exclusion.

### Exact string comparison

`duplicateUsernameSessionKey` base64-encodes the username bytes without trimming,
case folding, or Unicode normalization in
`internal/oauth2/duplicate_username.go:30`. Consequently, all of these can be
different ownership keys:

- `alice` and `Alice`;
- `alice` and `alice `;
- visually identical Unicode strings with different normalization forms.

Exact comparison is safe and deterministic when the identity provider guarantees
a canonical username. It can fail to enforce the operator's intended identity
rules when upstream values are not canonical.

Normalization should normally occur at the identity boundary, before the username
is used for authorization, client configuration, logging, and duplicate ownership.
Applying normalization only to the duplicate key could make different subsystems
disagree about which user is connected. Document exact matching if normalization
is intentionally delegated to the identity provider or username expression.

### Regression tests

- Verify and document whether bypassed clients participate in replacement.
- Add explicit tests showing that username comparison is exact, or add tests for
  the selected canonicalization rules.
- Verify that canonicalization is applied consistently to interactive login,
  profile selection, silent reauthentication, and client configuration lookup.

## Cross-cutting completion criteria

The work is complete when all of the following hold:

- At most one live CID can own a tracked username within the documented enforcement
  scope.
- Reauthentication of the same CID never kills that CID.
- A changed username cannot leave an ownership record for the previous username.
- Ownership remains valid for the lifetime of an active OpenVPN client.
- Disconnect and replacement races are idempotent.
- Storage failures cannot silently accept an untracked client without an explicit,
  documented fail-open policy.
- Configuration rejects or documents combinations that cannot provide the stated
  guarantee.
- Tests cover interactive authentication, profile selection, silent
  reauthentication, concurrent authentication, disconnect races, and OpenVPN
  command errors.

After implementation, run the repository-required checks:

```shell
make fmt
make lint
make test
```
