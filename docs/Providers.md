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
   - If you reuse an existing application, your users may already have given consent for the usage of this application, which may not include refresh tokens. If this is the case, add `CONFIG_OAUTH2_AUTHORIZE__PARAMS="prompt=consent"` to your configuration.
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

To allow openvpn-auth-oauth2 to fetch group information from Google,
you will need to configure a service account for openvpn-auth-oauth2 to use.
This account needs Domain-Wide Delegation and permission
to access the `https://www.googleapis.com/auth/admin.directory.group.readonly` API scope.

1. Create a [service account](https://developers.google.com/identity/protocols/OAuth2ServiceAccount) and
   - if you are using [Application Default Credentials](https://oauth2-proxy.github.io/oauth2-proxy/configuration/oauth_provider#using-application-default-credentials-adc--workload-identity--workload-identity-federation-recommended) (recommended), make sure to assign the Service Account with the `Service Account Token Creator` role.
   - if you are not using Application Default Credentials,
     you will need to create a new key (under **KEYS**) and after that download the Service Account JSON.
     This needs storing in a location accessible by `openvpn-auth-oauth2`
     and you will set the `provider.google.service-account-config` to point at it.
   
2. Make note of the `Unique ID` for a future step.
3. Under **"APIs & Auth"**, choose APIs.
4. Click on [Admin SDK API](https://console.developers.google.com/apis/library/admin.googleapis.com/) and then Enable API.
5. Follow the steps on https://developers.google.com/admin-sdk/directory/v1/guides/delegation#delegate_domain-wide_authority_to_your_service_account
   and give the Unique ID (as Client ID) from step 2 the following oauth scopes:
   ```
   https://www.googleapis.com/auth/admin.directory.group.readonly
   ```
6. Follow the steps on https://support.google.com/a/answer/60757 to enable Admin API access.
7. Permit access to the Admin SDK API for the service account.
   
   **Only one of the following is required:**
   * **Assign a role to a service account (preferred)**
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
9. If not using Application Default Credentials, Lock down the permissions on the json file downloaded from step 1
   so only `openvpn-auth-oauth2` is able to read the file
   and set the path to the file in the `provider.google.service-account-config=file://<path-to-json>` flag.

#### Using Application Default Credentials (ADC) / Workload Identity / Workload Identity Federation (recommended)

openvpn-auth-oauth2 can make use of [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials)
if `provider.google.service-account-config` is unset.

When deployed within GCP, this means that it can automatically use the service account attached to the resource. 
When deployed to GKE, ADC can be leveraged through a feature called Workload Identity. 
Follow Google's [guide](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
to set up Workload Identity.
When deployed outside GCP,
[Workload Identity Federation](https://cloud.google.com/docs/authentication/provide-credentials-adc#wlif) might be an option.

Google Directory API requires a service account to access the group information.
If Workload Identity is used, `provider.google.impersonate-account` should be set to the full email address of the service account used (`service-account-name@<project_id>.iam.gserviceaccount.com`).

Reference:
- https://cloud.google.com/iam/docs/service-account-impersonation

### Configuration

Set the following variables in your openvpn-auth-oauth2 configuration file:

```ini
CONFIG_OAUTH2_PROVIDER=google
CONFIG_OAUTH2_ISSUER=https://accounts.google.com
CONFIG_OAUTH2_CLIENT_ID=162738495-xxxxx.apps.googleusercontent.com
CONFIG_OAUTH2_CLIENT_SECRET=GOCSPX-xxxxxxxx
# If using ADC
CONFIG_PROVIDER_GOOGLE_IMPERSONATE__ACCOUNT=service-account-name@<project_id>.iam.gserviceaccount.com
# If not using ADC
CONFIG_PROVIDER_GOOGLE_SERVICE__ACCOUNT__CONFIG=file://<path-to-json>
# If Group Read role not assigned in Admin console.
# CONFIG_PROVIDER_GOOGLE_ADMIN__EMAIL=admin@example.com
```

## Keycloak

### Register an app as client with Keycloak

1. Login as admin into your Keycloak admin console
2. Create a new realm or use an existing one
3. Create a new client
   - Client ID: `openvpn-auth-oauth2`
   - Client Type: `OpenID Connect`
   - Name: `openvpn-auth-oauth2`
4. On the capability config page, set the following values:
   - Client authentication: On
   - Authorization: Off
   - Authentication flow: `Standard flow` only
5. On the login settings page, set the following values:
   - Root URL: `https://openvpn-auth-oauth2.example.com`
   - Valid Redirect URIs: `https://openvpn-auth-oauth2.example.com/oauth2/callback`
   - Web Origins: `https://openvpn-auth-oauth2.example.com`
   - Save
6. On the credential tab, take note of the Client ID and Client Secret.

### Configuration

Set the following variables in your openvpn-auth-oauth2 configuration file:

```ini
CONFIG_OAUTH2_ISSUER=https://<keycloak-domain>/auth/realms/<realm-name>
CONFIG_OAUTH2_CLIENT_ID=openvpn-auth-oauth2
CONFIG_OAUTH2_CLIENT_SECRET=<client-secret>
```

### Compare client OpenVPN and Web client IPs. (optional)

There is no known configuration to enrich the token with the client's IP address. 
If you know how to do this, please let us know.

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
