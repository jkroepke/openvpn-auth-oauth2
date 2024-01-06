# Debugging Errors

## named cookie not present

Debugging this issue is a bit hard. At least here is a step by step guide to debug the cookie handling on the browser.

I assume, you are using a Chrome-based Browser.

### Requirements

- Before connecting to OpenVPN server, open a browser locally. On the new tab page, do right-click, inspect.
  The browser console appears. Important: click on the Network tab and ensure that "preserve log" is enabled.
  ![](./img/debugging-error-cookie-network-tab.png)

- Ideally, you aren't logged on Azure with your main browser, otherwise you are not intercept the flow.

- Ensure, you have access to OpenVPN server logs in real-time. Tip: If you are using `journalctl`, use the option `--no-pager`.
  This prevents that large links are truncated.

### Debugging Steps

1. Initiate connection to OpenVPN server, close the browser opened by OpenVPN client.
2. Goto OpenVPN server logs, grab the line with `INFO_PRE,WEB_AUTH` and copy the link with the full state.
3. Paste the link on the tab where the browser console is opened.
4. Continue the auth flow.
5. On the access-denied screen, check the Browser Console for any errors.
6. Then goto the Network tab again. There is a request with `/oauth2/start` or just `start`.
   Click on Cookies and check if the response cookie is present.
   Example Screenshot:
   ![](./img/debugging-error-cookie-start.png)
7. Then goto the Network tab again. There is a request with `/oauth2/callback` or just `callback`.
   Click on Cookies and check if the request cookie is present.
   Example Screenshot:
   ![](./img/debugging-error-cookie-callback.png)


