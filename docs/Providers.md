# Providers

This page documents the setup at the OIDC provider.

## Microsoft Entra ID (formerly known as Azure AD)

<details>
<summary>Expand</summary>

### Register an app with Microsoft Entra ID

1. Sign in to your admin account on the tenant.
2. Navigate to the [App registrations](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps) page in the Entra ID admin center.
3. Click on the `New registration` button to start the process of registering a new application.
4. Enter a unique name for your application in the `Name` field.
5. In the `Supported account types` section, select the appropriate option based on your requirements. If unsure, leave the default value selected.
6. For the `Redirect URI`, select `Web` from the dropdown menu and input the public endpoint of your `openvpn-auth-oauth2` instance. For example, `https://openvpn-auth-oauth2.example.com/oauth2/callback`.
7. Click on the `Register` button to create the application.
8. Once the application is created, navigate to the `Certificates & secrets` section on the left-hand side menu.
9. In the `Client secrets` tab, click on `New client secret` to generate a new secret for your application.
10. Copy the generated client secret. This will be used as a configuration option for `openvpn-auth-oauth2`.
11. Navigate to the `Token configuration` section on the left-hand side menu.
12. Click on `Add optional claim` to add a new claim to your tokens.
13. In the right panel, select `ID` as the token type.
14. From the list of available claims, select `ipaddr`.
15. Click on `Add` to include this claim in your tokens.

References:

- https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app
- https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims

### Configuration

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OAUTH2_ISSUER=https://login.microsoftonline.com/$TENANT_ID/v2.0
CONFIG_OAUTH2_CLIENT_ID=<client_id>
CONFIG_OAUTH2_CLIENT_SECRET=<client_secret>
# The scopes openid profile are required, but configured by default.
# offline_access is required for non-interactive session refresh.
# CONFIG_OAUTH2_SCOPES=openid profile offline_access
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
oauth2:
  issuer: "https://login.microsoftonline.com/$TENANT_ID/v2.0"
  client:
    id: "<client_id>"
    secret: "<client_secret>"
  # The scopes openid profile are required, but configured by default.
  # offline_access is required for non-interactive session refresh.
  #scopes:
  #  - "openid"
  #  - "profile"
  #  - "offline_access"

```
</td></tr></tbody>
</table>


### Restrict auth to specific groups in your directory. (optional)

Restrict login based on groups can be configured inside the App Registration directly.
This is preferred.
Users get the notice from Azure that they aren’t part of the group, and the login is denied.

Reference: https://learn.microsoft.com/en-us/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users#assign-the-app-to-users-and-groups-to-restrict-access

To require multiple groups, define `CONFIG_OAUTH2_VALIDATE_GROUPS`.

</details>

## Google Cloud / Google Workspace

<details>
<summary>Expand</summary>

### Register an app on Google Cloud Console

1. Login as admin into your [Google Cloud Console](https://console.cloud.google.com/).
2. In the project Dashboard center pane, choose **"APIs & Services"**.
3. If necessary, complete the `OAuth consent screen` wizard. You will probably want to create an `Internal` application.
    * If you reuse an existing application, your users may already have given consent for the usage of this application,
      which may not include refresh tokens.
4. In the left Nav pane, choose **"Credentials"**.
5. In the center pane, choose **"OAuth consent screen"** tab. Fill in **"Product name shown to users"** and hit save.
6. In the center pane, choose **"Credentials"** tab.
    * Open the **"New credentials"** drop-down
    * Choose **"OAuth client ID"**
    * Choose **"Web application"**
    * Application name is freeform, choose something appropriate
    * Authorized redirect URIs is the location of oauth2/callback ex: https://yourdomain:9000/oauth2/callback
    * Choose "Create"
7. Take note of the Client ID and Client Secret.

### Restrict auth to specific Google Groups in your domain. (optional)

> **IMPORTANT**
>
> For `oauth2.validate.groups`, you have to set the IDs of the groups, not the names.

1. Navigate to the [Google Cloud Identity API](https://console.cloud.google.com/apis/api/cloudidentity.googleapis.com/) page and click on the "Enable API" button.
2. Access the [Google Admin Portal](https://admin.google.com/ac/groups) and locate the group that is required for the `openvpn-auth-oauth2` authorization.
3. The URL of the group page should follow this pattern: `https://admin.google.com/ac/groups/<ID>`. Replace `<ID>` with the ID of the group. Make sure to copy this ID for future use. If there are multiple groups, repeat this step for each one.
4. Insert the copied IDs into the `CONFIG_OAUTH2_VALIDATE_GROUPS` configuration setting in your `openvpn-auth-oauth2` setup.
5. **Optional**: If oauth2 scopes are set in the configuration, the `https://www.googleapis.com/auth/cloud-identity.groups.readonly` scope is required for group validation.

### Configuration

Set the following variables in your openvpn-auth-oauth2 configuration file:

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OAUTH2_PROVIDER=google
CONFIG_OAUTH2_ISSUER=https://accounts.google.com
CONFIG_OAUTH2_CLIENT_ID=162738495-xxxxx.apps.googleusercontent.com
CONFIG_OAUTH2_CLIENT_SECRET=GOCSPX-xxxxxxxx

# The scopes openid profile email are required, but configured by default.
# https://www.googleapis.com/auth/cloud-identity.groups.readonly is mandatory for group validation.
# Enabled by default, if scopes aren't set in the config.
#CONFIG_OAUTH2_SCOPES=openid profile email https://www.googleapis.com/auth/cloud-identity.groups.readonly
#CONFIG_OAUTH2_VALIDATE_GROUPS=03x8tuzt3hqdv5v
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
oauth2:
  provider: "google"
  issuer: "https://accounts.google.com"
  client:
    id: "162738495-xxxxx.apps.googleusercontent.com"
    secret: "GOCSPX-xxxxxxxx"
  # The scopes openid profile email are required, but configured by default.
  # https://www.googleapis.com/auth/cloud-identity.groups.readonly is mandatory for group validation.
  # Enabled by default, if scopes aren't set in the config.
  #scopes:
  #  - "openid"
  #  - "profile"
  #  - "email"
  #  - "https://www.googleapis.com/auth/cloud-identity.groups.readonly"
  validate:
    groups:
      - "03x8tuzt3hqdv5v"
```
</td></tr></tbody>
</table>

### Google consent screen always asking for permission grant

If `oauth2.refresh.enabled` is set to `true`, Google SSO will always ask for permission grant. On technical side,
this is because the `approval_prompt=force` is set on URL to obtain a refresh token. openvpn-auth-oauth2 requires a
refresh token to validate the user on re-auth.

To avoid this, you can set `oauth2.refresh.validate-user` to `false`. Read more about this in the [Configuration](Configuration.md#non-interactive-session-refresh) page.

</details>

## Keycloak

<details>
<summary>Expand</summary>

### Register an App with Keycloak

1. Sign in to your admin account on the Keycloak admin console.
2. Choose an existing realm or create a new one.
3. Create a new client:
    - Set the Client ID as `openvpn-auth-oauth2`.
    - Set the Client Type as `OpenID Connect`.
    - Name the client as `openvpn-auth-oauth2`.
4. In the capability configuration page, enable 'Client authentication' and 'Standard flow' for the Authentication flow. Make sure 'Authorization' is turned off.
5. In the login settings page, set the following values:
    - Root URL: `https://openvpn-auth-oauth2.example.com`
    - Valid Redirect URIs: `https://openvpn-auth-oauth2.example.com/oauth2/callback`
    - Web Origins: `https://openvpn-auth-oauth2.example.com`
    - Click 'Save'.
6. Navigate to the 'Credentials' tab and note down the Client ID and Client Secret.

### Configuration

Set the following variables in your `openvpn-auth-oauth2` configuration file:

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OAUTH2_ISSUER=https://<keycloak-domain>/auth/realms/<realm-name>
CONFIG_OAUTH2_CLIENT_ID=<client_id>
CONFIG_OAUTH2_CLIENT_SECRET=<client_secret>
# The scopes openid profile are required, but configured by default.
# offline_access is required for non-interactive session refresh.
# CONFIG_OAUTH2_SCOPES=openid profile offline_access
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
oauth2:
  issuer: "https://<keycloak-domain>/auth/realms/<realm-name>"
  client:
    id: "<client_id>"
    secret: "<client_secret>"
  # The scopes openid profile are required, but configured by default.
  # offline_access is required for non-interactive session refresh.
  #scopes:
  #  - "openid"
  #  - "profile"
  #  - "offline_access"

```
</td></tr></tbody>
</table>

### Role Mapping for openvpn-auth-oauth2 (optional)

openvpn-auth-oauth2 expects roles to be passed in the `roles` claim of the JWT token.
If you are using Keycloak, you can map the roles to the `roles` claim in the token. To do this, follow these steps:

1. Sign in to your admin account on the Keycloak admin console.
2. On the left-hand side menu, navigate to `Client scopes`.
3. Click on `Roles`.
4. In the `Mappers` tab, select `client roles`.
5. Set `Token Claim Name` from `resource_access.${client_id}.roles` to `roles`
6. Set `Add to ID token` to `ON`
7. Click `Save`
8. In the `Mappers` tab, select `realm roles`.
9. Set `Token Claim Name` from `resource_access.${client_id}.roles` to `roles`
10. Set `Add to ID token` to `ON`
11. Click `Save`

### Compare client OpenVPN and Web client IPs. (optional)

Currently, there is no known configuration to enrich the token with the client's IP address in Keycloak.
If you know how to do this, please contribute to the documentation.

</details>

## GitHub


<details>
<summary>Expand</summary>

### Caveats

A user must explicitly [request](https://help.github.com/articles/requesting-organization-approval-for-oauth-apps/) an
[organization](https://developer.github.com/v3/orgs/) give openvpn-auth-oauth2
[resource access](https://help.github.com/articles/approving-oauth-apps-for-your-organization/).
openvpn-auth-oauth2 will not have the correct permissions to determine if the user is in that organization otherwise, and the user will
not be able to log in. This request mechanism is a feature of the GitHub API.

### Register the application in the identity provider

In GitHub, [register](https://github.com/settings/developers) a new application. The callback address should be the /oauth2/callback endpoint of your
openvpn-auth-oauth2 URL (e.g. https://login.example.com/oauth2/callback).

After registering the app, you will receive an OAuth2 client ID and secret. These values will be inputted into the configuration below.

### Configuration

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OAUTH2_PROVIDER=github
CONFIG_OAUTH2_ISSUER=https://github.com
CONFIG_OAUTH2_CLIENT_ID=<client_id>
CONFIG_OAUTH2_CLIENT_SECRET=<client_secret>
CONFIG_OAUTH2_VALIDATE_GROUPS=your_github_org_name
CONFIG_OAUTH2_VALIDATE_ROLES=your_github_org_name:team_name
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
oauth2:
  provider: "github"
  issuer: "https://github.com"
  client:
    id: "<client_id>"
    secret: "<client_secret>"
  validate:
    groups: "your_github_org_name"
    roles: "your_github_org_name:team_name"
```
</td></tr></tbody>
</table>

</details>

## GitLab


<details>
<summary>Expand</summary>

Supported: Self-Managed GitLab, GitLab.com

### Register an app in GitLab

To use GitLab as an OpenID Connect provider, you need to register an application in your GitLab account.
This will provide you with a client ID and client secret that you will use in the configuration.
Supported apps:

* [User owned applications](https://docs.gitlab.com/integration/oauth_provider/#create-a-user-owned-application).
* [Group owned applications](https://docs.gitlab.com/integration/oauth_provider/#create-a-group-owned-application).
* [Instance-wide applications](https://docs.gitlab.com/integration/oauth_provider/#create-an-instance-wide-application).

If you are using Self-Managed GitLab, your instance must have enabled HTTPS.

### Configuration

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OAUTH2_ISSUER=https://gitlab.com/
CONFIG_OAUTH2_SCOPES=openid profile email
CONFIG_OAUTH2_USER__INFO=true
CONFIG_OAUTH2_CLIENT_ID=<client_id>
CONFIG_OAUTH2_CLIENT_SECRET=<client_secret>
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
oauth2:
  issuer: "https://gitlab.com/"
  scopes:
    - "openid"
    - "profile"
    - "email"
  client:
    id: "<client_id>"
    secret: "<client_secret>"
  user-info: true
```
</td></tr></tbody>
</table>

</details>

## Digitalocean


<details>
<summary>Expand</summary>

### Register an application in Digitalocean

Developers must [register their application](https://cloud.digitalocean.com/account/api/applications/new) to use OAuth.
A registered application is assigned a client ID and client secret.
The client secret should be kept confidential,
and only used between the application and the DigitalOcean authorization server https://cloud.digitalocean.com/v1/oauth.

### Configuration

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OAUTH2_ISSUER=https://cloud.digitalocean.com/
CONFIG_OAUTH2_SCOPES=read
CONFIG_OAUTH2_CLIENT_ID=<client_id>
CONFIG_OAUTH2_CLIENT_SECRET=<client_secret>
CONFIG_OAUTH2_ENDPOINT_TOKEN=https://cloud.digitalocean.com/v1/oauth/token
CONFIG_OAUTH2_ENDPOINT_AUTH=https://cloud.digitalocean.com/v1/oauth/authorize
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
oauth2:
  issuer: "https://cloud.digitalocean.com/"
  scopes:
    - "read"
  client:
    id: "<client_id>"
    secret: "<client_secret>"
  endpoints:
    token: "https://cloud.digitalocean.com/v1/oauth/token"
    auth: "https://cloud.digitalocean.com/v1/oauth/authorize"
```
</td></tr></tbody>
</table>

</details>

## Zitadel

<details>
<summary>Expand</summary>

### Register an application in Zitadel

1. Create a project in Zitadel
2. Create a new application in a project
3. Enter name and choose a web type
4. Authentication method: POST
5. Redirect URL: http://<vpn>:9000/oauth2/callback
6. Save Client ID and Client Secret to use below

After creating application, on page URLs you can find all links that you need.

### Configuration

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OAUTH2_ISSUER=https://company.zitadel.cloud
CONFIG_OAUTH2_CLIENT_ID=<client_id>
CONFIG_OAUTH2_CLIENT_SECRET=<client_secret>
# The scopes openid profile email are required, but configured by default.
# offline_access is required for non-interactive session refresh.
#CONFIG_OAUTH2_SCOPES=openid profile email offline_access
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
oauth2:
  issuer: "https://company.zitadel.cloud"
  client:
    id: "<client_id>"
    secret: "<client_secret>"
  # The scopes openid profile are required, but configured by default.
  # offline_access is required for non-interactive session refresh.
  #scopes:
  #  - "openid"
  #  - "profile"
  #  - "email"
  #  - "offline_access"
```
</td></tr></tbody>
</table>

</details>

## Authentik

<details>
<summary>Expand</summary>

### Register an application in Authentik

1. Sign in to your Authentik admin interface
2. Navigate to **Applications** → **Providers**
3. Click **Create** and select **OAuth2/OpenID Provider**
4. Configure the provider:
   - **Name**: `openvpn-auth-oauth2`
   - **Client Type**: `confidential`
   - **Redirect URIs**: `https://openvpn-auth-oauth2.example.com/oauth2/callback`
   - **Signing Key**: Select an appropriate certificate
   - **Subject Mode**: Based on the User's hashed ID
   - **Issuer Mode**: Each provider has a different issuer, based on the application slug
5. Under **Advanced protocol settings**, add `offline_access` to the **Scopes** list (defaults are typically email, openid, and profile). This is only needed if you intend to use [non-interactive session refresh](Non-interactive%20session%20refresh.md)
6. Save and note the **Client ID** and **Client Secret**
7. Create an Application:
   - Navigate to **Applications** → **Applications**
   - Click **Create**
   - **Name**: `OpenVPN OAuth2`
   - **Slug**: `openvpn-oauth2`
   - **Provider**: Select the provider created above
8. Configure group/user access as needed in the **Policy Bindings** tab

### Configuration

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OAUTH2_ISSUER=https://auth.example.com/application/o/openvpn-oauth2/
CONFIG_OAUTH2_CLIENT_ID=<client_id>
CONFIG_OAUTH2_CLIENT_SECRET=<client_secret>
CONFIG_OAUTH2_REFRESH__NONCE=empty
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
oauth2:
  provider: "authentik"
  issuer: "https://auth.example.com/application/o/openvpn-oauth2/"
  client:
    id: "<client_id>"
    secret: "<client_secret>"
  refresh-nonce: "empty"
```
</td></tr></tbody>
</table>

</details>
