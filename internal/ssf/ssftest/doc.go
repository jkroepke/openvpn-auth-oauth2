// Package ssftest provides an in-process OpenID Shared Signals Framework
// (SSF) 1.0 transmitter for Go tests, so the SSF receiver can be tested
// without a real identity provider such as Keycloak.
//
// New starts the transmitter on an httptest TLS server. It serves:
//
//   - the transmitter configuration metadata at the well-known location
//     derived from the issuer (see WithIssuerPath and WithMetadataLocation),
//   - a JWK Set with the public signing keys,
//   - the stream configuration endpoint, protected by a bearer token, which
//     returns the poll endpoint (delivery.endpoint_url) and the aud of each
//     stream,
//   - an RFC 8936 poll endpoint with ack, setErrs, maxEvents, moreAvailable
//     and optional long polling.
//
// Tests build Security Event Tokens with NewSET or NewSessionRevoked, sign
// them with Sign and queue them with Emit, or queue a hand-crafted token with
// EmitToken. Pending, Acked, SetErrs and PollRequests expose what the
// receiver did, and FailNextPoll and RotateKey exercise error handling and
// key rollover.
package ssftest
