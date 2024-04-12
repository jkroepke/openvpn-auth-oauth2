# Providers

This page documents the setup at the OIDC provider.

## Microsoft Entra ID (formerly known as Azure AD)

### Register an app with Microsoft Entra ID

1. Sign in to your admin account on the tenant.
2. Navigate to the [App registrations](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps) page in the Azure AD admin center.
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

```ini
CONFIG_OAUTH2_ISSUER=https://login.microsoftonline.com/$TENANT_ID/v2.0
CONFIG_OAUTH2_CLIENT_ID=$CLIENT_ID
CONFIG_OAUTH2_CLIENT_SECRET=$CLIENT_SECRET
```


### Restrict auth to specific groups in your directory. (optional)

Restrict login based on groups can be configured inside the App Registration directly. This is generally prefered, since users get the notice from Azure that they are not part of the group and the login would be denied.

Referece: https://learn.microsoft.com/en-us/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users#assign-the-app-to-users-and-groups-to-restrict-access

How require multiple groups, check you could define `CONFIG_OAUTH2_VALIDATE_GROUPS`.

## Google Cloud / Google Workspace

### Register an app on google cloud console

1. Login as admin into your [Google console](https://console.cloud.google.com/).
2. In the project Dashboard center pane, choose **"APIs & Services"**.
3. If necessary, complete the `OAuth consent screen` wizard. You will probably want to create an `Internal` application.
   - If you reuse an existing application, your users may already have given consent for the usage of this application,
     which may not include refresh tokens.
4. In the left Nav pane, choose **"Credentials"**.
5. In the center pane, choose **"OAuth consent screen"** tab. Fill in **"Product name shown to users"** and hit save.
6. In the center pane, choose **"Credentials"** tab.
   * Open the "New credentials"** drop down
   * Choose **"OAuth client ID"**
   * Choose **"Web application"**
   * Application name is freeform, choose something appropriate
   * Authorized redirect URIs is the location of oauth2/callback ex: https://yourdomain:9000/oauth2/callback
   * Choose "Create"
7. Take note of the Client ID and Client Secret.

### Restrict auth to specific Google Groups in your domain. (optional)

1. Navigate to the [Google Cloud Identity API](https://console.cloud.google.com/apis/api/cloudidentity.googleapis.com/) page and click on the "Enable API" button.
2. Access the [Google Admin Portal](https://admin.google.com/ac/groups) and locate the group that is required for the `openvpn-auth-oauth2` authorization.
3. The URL of the group page should follow this pattern: `https://admin.google.com/ac/groups/<ID>`. Replace `<ID>` with the actual ID of the group. Make sure to copy this ID for future use. If there are multiple groups, repeat this step for each one.
4. Insert the copied ID(s) into the `CONFIG_OAUTH2_VALIDATE_GROUPS` configuration setting in your `openvpn-auth-oauth2` setup.


### Configuration

Set the following variables in your openvpn-auth-oauth2 configuration file:

```ini
CONFIG_OAUTH2_PROVIDER=google
CONFIG_OAUTH2_ISSUER=https://accounts.google.com
CONFIG_OAUTH2_CLIENT_ID=162738495-xxxxx.apps.googleusercontent.com
CONFIG_OAUTH2_CLIENT_SECRET=GOCSPX-xxxxxxxx

# CONFIG_OAUTH2_VALIDATE_GROUPS=03x8tuzt3hqdv5v
```

## Keycloak

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

```ini
CONFIG_OAUTH2_ISSUER=https://<keycloak-domain>/auth/realms/<realm-name>
CONFIG_OAUTH2_CLIENT_ID=openvpn-auth-oauth2
CONFIG_OAUTH2_CLIENT_SECRET=<client-secret>
```

### Compare client OpenVPN and Web client IPs. (optional)

Currently, there is no known configuration to enrich the token with the client's IP address in Keycloak.
If you know how to do this, please contribute to the documentation.

## GitHub

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

```ini
CONFIG_OAUTH2_PROVIDER=github
CONFIG_OAUTH2_ISSUER=https://github.com
CONFIG_OAUTH2_CLIENT_ID=$CLIENT_ID
CONFIG_OAUTH2_CLIENT_SECRET=$CLIENT_SECRET
CONFIG_OAUTH2_VALIDATE_GROUPS=org
CONFIG_OAUTH2_VALIDATE_ROLES=org:team
```

## Digitalocean

### Register an application in Digitalocean

Developers must [register their application](https://cloud.digitalocean.com/account/api/applications/new) to use OAuth.
A registered application is assigned a client ID and client secret.
The client secret should be kept confidential,
and only used between the application and the DigitalOcean authorization server https://cloud.digitalocean.com/v1/oauth.

### Configuration

```ini
CONFIG_OAUTH2_ISSUER=https://cloud.digitalocean.com/
CONFIG_OAUTH2_SCOPES=read
CONFIG_OAUTH2_ENDPOINT_TOKEN=https://cloud.digitalocean.com/v1/oauth/token
CONFIG_OAUTH2_ENDPOINT_AUTH=https://cloud.digitalocean.com/v1/oauth/authorize
```

## Zitadel

### Register an application in Zitadel

1. Create a project in Zitadel
2. Create a new application in a project
3. Enter name and choose a web type
4. Authentication method: POST
5. Redirect URL: http://<vpn>:9000/oauth2/callback
6. Save Client ID and Client Secret to use below

After creating application, on page URLs you can find all links that you need.

### Configuration

```ini
CONFIG_HTTP_BASEURL=http://<vpn>:9000/
CONFIG_HTTP_LISTEN=:9000
CONFIG_HTTP_SECRET=1jd93h5b6s82lf03jh5b2hf9
CONFIG_OPENVPN_ADDR=unix:///run/openvpn/server.sock
CONFIG_OPENVPN_PASSWORD=<password from /etc/openvpn/password.txt>
CONFIG_OAUTH2_ISSUER=https://company.zitadel.cloud
CONFIG_OAUTH2_SCOPES=openid profile email offline_access
CONFIG_OAUTH2_CLIENT_ID=<client_id>
CONFIG_OAUTH2_CLIENT_SECRET=<client_secret>
```
