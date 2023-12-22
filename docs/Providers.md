# Providers

This pages documents the setup at the OIDC provider.

## Azure AD
### Register an app with AAD

1. Login as admin into tenant
2. Open [App registrations](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps) in Azure AD admin center
3. Click new registration
4. Pick a name, chose a "Supported account types"-option. Leave the default value, if you are not sure.
5. For redirect uri, choice Web and enter the public endpoint of `openvpn-auth-oauth2`, for example `https://openvpn-auth-oauth2.example.com/oauth2/callback`.
6. Click register.
7. Copy the tenant-id and client-id. You need the both as configuration option for `openvpn-auth-oauth2`.
8. After creation, select `Certificates & secrets` on the left side.
9. Select the tab `Client secrets` and create a new client secret.
10. Copy the client-secret. Need it as configuration option for `openvpn-auth-oauth2`.
11. Then, select Token configuration on the left side.
12. Add optional claim
13. On the right panel, select `ID` as token type
14. Select `ipaddr` from the list of claims.
15. Select Add.

### Configuration

- `CONFIG_OAUTH2_ISSUER=https://login.microsoftonline.com/$TENANT_ID/v2.0`
- `CONFIG_OAUTH2_CLIENT_ID=$CLIENT_ID`
- `CONFIG_OAUTH2_CLIENT_SECRET=$CLIENT_SECRET`

References:
- https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app
- https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims

## Google Cloud / Google Workspace

### Register an app on google cloud console

1. Login as admin into your google console from here https://console.cloud.google.com/
2. click on Create a new project or select an existing project
3. then "API & Services", then "Credentials" (left column)
4. click "create credentials" (button at the top-middle) then type "OAuth Client ID" (in the dropdown)
5. Choose a name for your app like "openvpn connection"
6. in the "Authorized Redirect URIs" add one and set it to "https://yourdomain/oauth2/callback" (yourdomain would be the domain where a proxy is redirecting to your openvpn-auth-oauth2 daemon, typically on port 9000) 
7. you'll get your client id and client secret from google, copy them somewhere safe
8. use those in the config as shown below

### Configuration

Set the following variables in your openvpn-auth-oauth2 configuration file: 

- `CONFIG_OAUTH2_ISSUER=https://accounts.google.com/.well-known/openid-configuration`
- `CONFIG_OAUTH2_CLIENT_ID=162738495-xxxxx.apps.googleusercontent.com`
- `CONFIG_OAUTH2_CLIENT_SECRET=GOCSPX-xxxxxxxx`

## GitHub
### Caveats
A user must explicitly [request](https://help.github.com/articles/requesting-organization-approval-for-oauth-apps/) an
[organization](https://developer.github.com/v3/orgs/) give openvpn-auth-oauth2
[resource access](https://help.github.com/articles/approving-oauth-apps-for-your-organization/).
openvpn-auth-oauth2 will not have the correct permissions to determine if the user is in that organization otherwise, and the user will
not be able to log in. This request mechanism is a feature of the GitHub API.

### Register the application in the identity provider¶

In GitHub, [register](https://github.com/settings/developers) a new application. The callback address should be the /oauth2/callback endpoint of your
openvpn-auth-oauth2 URL (e.g. https://login.example.com/oauth2/callback).

After registering the app, you will receive an OAuth2 client ID and secret. These values will be inputted into the configuration below.

### Configuration

- `CONFIG_OAUTH2_PROVIDER=github`
- `CONFIG_OAUTH2_ISSUER=https://github.com`
- `CONFIG_OAUTH2_CLIENT_ID=$CLIENT_ID`
- `CONFIG_OAUTH2_CLIENT_SECRET=$CLIENT_SECRET`
- `CONFIG_OAUTH2_VALIDATE_GROUPS=org`
- `CONFIG_OAUTH2_VALIDATE_ROLES=org:team`


## Digitalocean
### Register an application in Digitalocean

Developers must [register their application](https://cloud.digitalocean.com/account/api/applications/new) to use OAuth.
A registered application is assigned a client ID and client secret.
The client secret should be kept confidential,
and only used between the application and the DigitalOcean authorization server https://cloud.digitalocean.com/v1/oauth.

### Configuration

- `CONFIG_OAUTH2_ISSUER=https://cloud.digitalocean.com/`
- `CONFIG_OAUTH2_SCOPES=read`
- `CONFIG_OAUTH2_ENDPOINT_TOKEN=https://cloud.digitalocean.com/v1/oauth/token`
- `CONFIG_OAUTH2_ENDPOINT_AUTH=https://cloud.digitalocean.com/v1/oauth/authorize`

## Zitadel
### Register an application in zitadel
1. Create project in Zitadel
2. Create new application in project
3. Enter name and choose web type
4. Authentication method - POST
5. Redirect url - http://<vpn>:9000/oauth2/callback
6. Save Client ID and Client Secret to use below

After created application, on page URLs you can find all links which you need.

### Configuration

- `CONFIG_HTTP_BASEURL=http://<vpn>:9000/`
- `CONFIG_HTTP_LISTEN=:9000`
- `CONFIG_HTTP_SECRET=1jd93h5b6s82lf03jh5b2hf9`
- `CONFIG_OPENVPN_ADDR=unix:///run/openvpn/server.sock`
- `CONFIG_OPENVPN_PASSWORD=<password from /etc/openvpn/password.txt>`
- `CONFIG_OAUTH2_ISSUER=https://company.zitadel.cloud`
- `CONFIG_OAUTH2_SCOPES=openid profile email offline_access`
- `CONFIG_OAUTH2_CLIENT_ID=<client_id>`
- `CONFIG_OAUTH2_CLIENT_SECRET=<client_secret>`
