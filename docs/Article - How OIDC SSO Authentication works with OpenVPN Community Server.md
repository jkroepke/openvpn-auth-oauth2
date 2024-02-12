# Introduction

[OpenID Connect (OIDC)](https://auth0.com/intro-to-iam/what-is-openid-connect-oidc) is a powerful identity layer built on top of the OAuth 2.0 protocol. It enables clients to verify the identity of an end-user based on the authentication performed by an authorization server. Single Sign-On (SSO) is a user authentication service that allows a user to use one set of login credentials to access multiple applications.

In the realm of secure and seamless user authentication, the [`openvpn-auth-oauth2`](https://github.com/jkroepke/openvpn-auth-oauth2) plugin emerges as a game-changer. It integrates OpenVPN Community Server with any OIDC provider, leveraging the robustness of OIDC and the convenience of SSO. This powerful combination not only simplifies the authentication process but also significantly enhances the security of your applications.

This article will guide you through the intricacies of how OIDC SSO authentication works with OpenVPN Community Server using the `openvpn-auth-oauth2` plugin. We will delve into the technical details of the OIDC SSO authentication process, its benefits, and how it integrates with OpenVPN Community Server. This comprehensive guide aims to empower developers and system administrators to effectively implement and manage secure access to their applications using `openvpn-auth-oauth2`.

# The Authentication Process

The authentication process using OIDC SSO with OpenVPN Community Server, specifically leveraging the [`openvpn-auth-oauth2`](https://github.com/jkroepke/openvpn-auth-oauth2) plugin and the OpenVPN [webauth protocol](https://github.com/OpenVPN/openvpn3/blob/cb9ce3d71c1cc485aa17ff7d1f53c56e97116e04/doc/webauth.md), unfolds as follows:

1. **Initiation of User Authentication**: When a user attempts to access a resource on the OpenVPN Community Server and is not already authenticated, the server, utilizing the `openvpn-auth-oauth2` plugin, redirects the user to the OIDC provider. This redirection is facilitated by the OpenVPN webauth protocol.

2. **Interaction with OIDC Provider**: The user is then required to authenticate with the OIDC provider. This could involve various methods such as entering credentials, using a biometric scanner, or any other method that the OIDC provider supports.

3. **Issuance of Tokens**: Post successful authentication, the OIDC provider issues an ID token and an access token. The ID token contains claims about the authentication event and the user. The access token is used to authorize access to resources.

4. **Validation of Tokens**: The OpenVPN Community Server, with the assistance of the `openvpn-auth-oauth2` plugin, validates the ID token and access token. This step is crucial to ensure that the tokens are authentic and have been issued by a trusted OIDC provider.

5. **Granting User Access**: If the tokens are validated successfully, the OpenVPN Community Server grants the user access to the requested resource. This access is granted in accordance with the OpenVPN webauth protocol.

This process not only verifies the identity of the user (authentication) but also ensures they have the appropriate permissions to access the requested resource (authorization). The user experience is seamless as they only need to authenticate once to access multiple applications. The `openvpn-auth-oauth2` plugin and the OpenVPN webauth protocol are instrumental in this process, enabling the interaction between the OpenVPN Community Server and the OIDC provider.

# Setting up `openvpn-auth-oauth2` with your Identity Provider (IdP)

To set up the `openvpn-auth-oauth2` plugin with your Identity Provider (IdP), you need to follow a series of steps. These steps may vary slightly depending on the specific IdP you are using. However, the general process is as follows:

1. **Install the `openvpn-auth-oauth2` Plugin**: The first step is to install the `openvpn-auth-oauth2` plugin on your OpenVPN Community Server. You can find the installation instructions in the [GitHub repository](https://github.com/jkroepke/openvpn-auth-oauth2).

2. **Register Your Application with the IdP**: Next, you need to register your application with your IdP. This process involves providing some basic information about your application, such as its name and the URLs it will use for redirection after authentication. The IdP will provide you with a client ID and a client secret, which you will need in the next step.

3. **Configure the `openvpn-auth-oauth2` Plugin with your IdP**: Now, you need to configure the `openvpn-auth-oauth2` plugin with the details of your IdP and the client ID and client secret you received in the previous step. The configuration process is detailed in the [GitHub repository's wiki](https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Providers). This page provides specific instructions for various IdPs such as Google, Microsoft, and others.

4. **Test the Setup**: Finally, you should test the setup to ensure everything is working correctly. You can do this by attempting to access a resource on your OpenVPN Community Server. If the setup is correct, you should be redirected to your IdP for authentication.

Remember, the exact steps may vary depending on your specific IdP and the configuration of your OpenVPN Community Server. Always refer to the documentation provided by your IdP and the `openvpn-auth-oauth2` [GitHub repository's wiki](https://github.com/jkroepke/openvpn-auth-oauth2/wiki) for the most accurate and up-to-date information.

# Restricting Access for Specific Users and Groups with OpenVPN and OIDC

In an environment where you have multiple users and groups, it's often necessary to restrict access to certain resources based on user identity or group membership. This can be achieved using OpenVPN Community Server in conjunction with an OpenID Connect (OIDC) provider and the `openvpn-auth-oauth2` plugin.

Before you start, make sure you have the following:

- An OpenVPN Community Server set up and running.
- The `openvpn-auth-oauth2` plugin installed on your OpenVPN Community Server.
- An OIDC provider that supports group claims in the ID token.

You need to configure the `openvpn-auth-oauth2` plugin to validate group claims. This can be done by setting the `oauth2.validate.groups` configuration property.

In your `openvpn-auth-oauth2` configuration file, add the following lines:

```ini
CONFIG_OAUTH2_VALIDATE_GROUPS=group1,group2
```

Replace `group1,group2` with a comma-separated list of the groups that should have access to the VPN.

# Authentication Context Processing

The Authentication Context or `acr` ([Authentication Context Class Reference](https://openid.net/specs/openid-connect-eap-acr-values-1_0-ID1.html)) is a string used in OpenID Connect requests to specify the desired level of security for the authentication process. It allows the client to request certain authentication methods or processes to be applied when the user is logging in.

In the context of `openvpn-auth-oauth2`, the `acr` can be used to enforce certain authentication requirements. For example, you might want to require multi-factor authentication (MFA) for all users accessing your OpenVPN Community Server.

To configure `acr` validation, you need to set the `oauth2.validate.acr` configuration property in your `openvpn-auth-oauth2` configuration file. Here's an example:

```ini
CONFIG_OAUTH2_VALIDATE_ACR=phr
```

In this example, `phr` is the `acr` value that represents a specific authentication method. `phr` stands for Phishing Resistant. It's a term used in the context of multi-factor authentication (MFA). Phishing-resistant mechanisms are designed to resist phishing and other fraudulent attempts to steal user credentials. This could be a hardware device that requires a user to physically interact with it, or a biometric authentication method. When used in the `acr` (Authentication Context Class Reference) in OpenID Connect, it indicates that the authentication process should involve a phishing-resistant method.

When a user attempts to authenticate, the `openvpn-auth-oauth2` plugin will check the `acr` value in the ID token issued by the OIDC provider. If the `acr` value matches the one specified in the configuration (`phr` in this example), the authentication process will proceed. If not, the authentication process will fail, and the user will not be granted access.

This feature provides an additional layer of security by allowing you to enforce specific authentication requirements. However, it should be used in conjunction with other security measures for a comprehensive security strategy.

It's important to note that the OIDC provider you're using needs to support the `acr` values you want to enforce. In this case, the OIDC provider should support the `phr` value for phishing-resistant authentication. Always refer to your OIDC provider's documentation to understand what `acr` values they support.

# What are the benefits of using the openvpn-auth-oauth2 plugin for authentication with the OpenVPN Community Server?

The `openvpn-auth-oauth2` plugin offers several benefits when used for authentication with the OpenVPN Community Server:

1. **Integration with OIDC Providers**: The plugin allows OpenVPN Community Server to integrate with any OpenID Connect (OIDC) provider. This means you can leverage the authentication mechanisms provided by these OIDC providers, such as Google, Microsoft, or any other OIDC compliant provider.

2. **Single Sign-On (SSO)**: With the `openvpn-auth-oauth2` plugin, you can implement Single Sign-On (SSO) across multiple applications. This means users only need to authenticate once to access multiple applications, improving the user experience.

3. **Token Validation**: The plugin validates the ID token and access token issued by the OIDC provider. This ensures that the tokens are genuine and were issued by a trusted OIDC provider, enhancing the security of your application.

4. **Flexibility**: The `openvpn-auth-oauth2` plugin provides flexibility as it can be used with different OIDC providers and can support different types of user authentication methods supported by the OIDC provider.

5. **Scalability**: By delegating authentication to an OIDC provider, the plugin allows the OpenVPN Community Server to scale more effectively. The server can focus on its core functionality, while the OIDC provider handles the potentially resource-intensive process of user authentication.

6. **Security**: Using the `openvpn-auth-oauth2` plugin for authentication can improve the security of your application. OIDC providers often have robust security measures in place, including multi-factor authentication, anomaly detection, and secure handling of user credentials. By integrating with an OIDC provider, you can leverage these security measures for your application.