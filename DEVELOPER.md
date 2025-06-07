# Developer Guide

This document provides a technical overview of the project and highlights the most important packages and concepts.

## Overview

`openvpn-auth-oauth2` is a Go application that acts as a management client for OpenVPN. It handles user authentication through OIDC/OAuth2. The README lists example OIDC providers and points to the installation and configuration guides.

The entry point is `main.go`, which starts either the daemon or the `state` helper program based on the first command-line argument.

## How It Works

1. When an OpenVPN client connects, the server notifies this application via the management interface (for example with `>CLIENT:CONNECT` or `>CLIENT:REAUTH`).
2. The application replies on the management interface with a `WEBAUTH` message that contains the authentication URL. The OpenVPN server forwards this message to the client, and it is the client's responsibility to launch a browser window and open that URL.
3. The browser is redirected to the OAuth2 provider where the user logs in.
4. After authentication, the provider calls the `/oauth2/callback` endpoint with an authorization code.
5. The application exchanges the code for tokens, stores the refresh token if present and informs the OpenVPN server to accept the client.
6. During session refresh, the stored refresh token allows a non-interactive login; otherwise the user is redirected through the same flow again.

For a step-by-step sequence diagram see `docs/Home.md`.

## Key Packages

1. **`internal/config`** – Loads configuration from files, environment variables and command-line flags. It defines structures for the HTTP server, logging, OAuth2 and OpenVPN settings.
2. **`internal/httpserver`** – Provides an HTTP server with optional TLS support. It can load certificates dynamically and performs graceful shutdown when required.
3. **`internal/httphandler`** – Registers HTTP routes such as `/oauth2/start` and `/oauth2/callback`, and serves static assets.
4. **`internal/oauth2`** – Implements OAuth2 logic. The `New` function creates the client and configures options like scopes and nonce generation. Sub-packages (`generic`, `github`, `google`) handle provider-specific behaviour.
5. **`internal/openvpn`** – Manages the connection to the OpenVPN management interface, parses events and sends commands to the server. It decides whether a client should be accepted or rejected.
6. **`internal/state`** – Generates and validates the OAuth2 `state` parameter. It stores information such as IP address, ports and OpenVPN IDs encrypted with AES.
7. **`internal/tokenstorage`** – Stores encrypted refresh tokens (for example in memory) so that a user can log in again without manual interaction.
8. **`internal/utils`** – Helper functions including common name transformation, HTTP transport with custom user-agent and filesystem helpers.

## Documentation

All Markdown files in `docs/` are mirrored in the GitHub wiki. The file `Home.md` explains the authentication sequence using a diagram. `Configuration.md` contains an extensive YAML configuration example and documents all command-line options and environment variables.

## What to Learn

- **Go basics** – The codebase uses Go modules and targets Go 1.24.
- **HTTP server & OIDC/OAuth2** – Understand how TLS is enabled, and how the OAuth2 flow works with nonce, PKCE and refresh tokens.
- **OpenVPN management interface** – Communication with the OpenVPN server happens over Unix or TCP sockets. Learn which commands and events are exchanged.
- **Configuration** – Behaviour is driven by YAML files or environment variables. See `config.example.yaml` or `Configuration.md` for examples.
- **State handling** – Secure handling of the OAuth2 `state` parameter is essential for protecting the login flow.

