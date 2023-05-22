# Providers

This pages documenets the setup at the OIDC provider.

## Azure AD

### Register an app with AAD

1. Login as admin into tenant
2. Open [App registrations](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps) in Azure AD admin center
3. Click new registration
4. Pick a name, chose a "Supported account types"-option. Leave the default value, if you are not sure.
5. Let the redirect uri blank and click register.
6. Copy the tenant-id and client-id. You need the both as configuration option for `openvpn-auth-oauth2`.
7. After creation, select Token configuration on the left side.
8. Add optional claim
9. On the right panel, select `ID` as token type
10. Select `ipaddr` from the list of claims.
11. Select Add.

References:
- https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app
- https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims
