# Providers

This page documents the setup at the OIDC provider.

## Microsoft Entra ID (formerly known as Azure AD)

### Register an app with Microsoft Entra ID

1. Login as admin into tenant
2. Open [App registrations](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps) in an Azure AD admin center
3. Click new registration
4. Pick a name, choose a "Supported account types"-option. Leave the default value if you are not sure.
5. For redirect uri, choice Web and enter the public endpoint of `openvpn-auth-oauth2`, for
   example `https://openvpn-auth-oauth2.example.com/oauth2/callback`.
6. Click register.
7. Copy the tenant-id and client-id. You need it both as configuration option for `openvpn-auth-oauth2`.
8. After creation, select `Certificates & secrets` on the left side.
9. Select the tab `Client secrets` and create a new client secret.
10. Copy the client-secret. Need it as a configuration option for `openvpn-auth-oauth2`.
11. Then, select Token configuration on the left side.
12. Add optional claim
13. On the right panel, select `ID` as a token type
14. Select `ipaddr` from the list of claims.
15. Select Add.

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

1. Login as admin into your Google console from here https://console.cloud.google.com/
2. Create a new project: https://console.developers.google.com/project
3. Choose the new project from the top right project dropdown (only if another project is selected)
4. In the project Dashboard center pane, choose **"APIs & Services"**
5. In the left Nav pane, choose **"Credentials"**
6. In the center pane, choose **"OAuth consent screen"** tab. Fill in **"Product name shown to users"** and hit save.
7. In the center pane, choose **"Credentials"** tab.
   * Open the "New credentials"** drop down
   * Choose **"OAuth client ID"**
   * Choose **"Web application"**
   * Application name is freeform, choose something appropriate
   * Authorized redirect URIs is the location of oauth2/callback ex: https://yourdomain/oauth2/callback
   * Choose "Create"
8. Take note of the Client ID and Client Secret

### Restrict auth to specific Google Groups in your domain. (optional)

To allow openvpn-auth-oauth2 to fetch group information from Google,
you will need to configure a service account for openvpn-auth-oauth2 to use.
This account needs Domain-Wide Delegation and permission
to access the `https://www.googleapis.com/auth/admin.directory.group.readonly` API scope.

1. Create a [service account](https://developers.google.com/identity/protocols/OAuth2ServiceAccount) and download
   the json file
   if you're not using [Application Default Credentials / Workload Identity / Workload Identity Federation (recommended)](https://oauth2-proxy.github.io/oauth2-proxy/configuration/oauth_provider#using-application-default-credentials-adc--workload-identity--workload-identity-federation-recommended).
   This needs storing in a location accessible by `openvpn-auth-oauth2`
   and you will set the `provider.google.service-account-config` to point at it.
2. Make note of the Client ID for a future step.
3. Under **"APIs & Auth"**, choose APIs.
4. Click on [Admin SDK API](https://console.developers.google.com/apis/library/admin.googleapis.com/) and then Enable API.
5. Follow the steps on https://developers.google.com/admin-sdk/directory/v1/guides/delegation#delegate_domain-wide_authority_to_your_service_account
   and give the client id from step 2 the following oauth scopes:
   ```
   https://www.googleapis.com/auth/admin.directory.group.readonly
   ```
6. Follow the steps on https://support.google.com/a/answer/60757 to enable Admin API access.
7. Permit access to the Admin SDK API for the service account
   * **Assign a role to a service account**
     1. In the Google Admin console, go [**Account** > **Admin roles**](https://admin.google.com/ac/roles) page.
     2. Point to the role that you want to assign (e.g. Groups reader), and then click **Assign admin**
     3. Click **Assign service accounts**
     4. Enter the email address of the service account.
     5. Click **Add > Assign role**.

   * **Admin impersonation**

     Create or choose an existing administrative email address on the Gmail domain
     to assign to the `providers.google.admin-emails` flag.
     This email will be impersonated by this client to make calls to the Admin SDK.
   
8. Create or choose an existing email group and set that email to the `oauth2.validate.groups` flag.
   You can pass multiple instances of this flag with different groups,
   and the user will be checked against all the provided groups.
9. Lock down the permissions on the json file downloaded from step 1
   so only `openvpn-auth-oauth2` is able to read the file
   and set the path to the file in the `provider.google.service-account-config=file://<path-to-json>` flag.

### Configuration

Set the following variables in your openvpn-auth-oauth2 configuration file:

```ini
CONFIG_OAUTH2_PROVIDER=google
CONFIG_OAUTH2_ISSUER=https://accounts.google.com
CONFIG_OAUTH2_CLIENT_ID=162738495-xxxxx.apps.googleusercontent.com
CONFIG_OAUTH2_CLIENT_SECRET=GOCSPX-xxxxxxxx
CONFIG_PROVIDER_GOOGLE_SERVICE__ACCOUNT__CONFIG=file://<path-to-json>
```

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
