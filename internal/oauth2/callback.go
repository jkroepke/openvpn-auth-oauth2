package oauth2

// language=html.
const callbackHTML = `
<!doctype html>
<html>
<head><title>Login successfully</title></head>
<body>
<h1>You have logged into OpenVPN!</h1>
<h2>You can close this window now.</h2>
<script>setTimeout("window.close()",30000)</script>
</body>
</html>
`
