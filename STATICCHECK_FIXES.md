# Staticcheck QF1001 Fixes - De Morgan's Law Applied

## Issue
Staticcheck reported QF1001 warnings suggesting to apply De Morgan's law to simplify complex boolean expressions in three locations.

## De Morgan's Law
The negation of a disjunction (OR) is equivalent to the conjunction (AND) of the negations:
```
!(A || B) === (!A && !B)
```

In our case:
```
!(url == nil || (url.Scheme == "" && url.Host == ""))
```
becomes:
```
url != nil && (url.Scheme != "" || url.Host != "")
```

## Changes Made

### 1. Added Helper Function (validate.go)
Created `isURLNotEmpty()` helper function to check if a URL is not nil and has at least scheme or host set:

```go
// isURLNotEmpty checks if a URL is not nil and has at least scheme or host set.
func isURLNotEmpty(uri *url.URL) bool {
    return uri != nil && (uri.Scheme != "" || uri.Host != "")
}
```

### 2. Fixed validate.go (Lines 135-136)

**Before:**
```go
if !(conf.OAuth2.Endpoints.Auth == nil || (conf.OAuth2.Endpoints.Auth.Scheme == "" && conf.OAuth2.Endpoints.Auth.Host == "")) &&
    !(conf.OAuth2.Endpoints.Token == nil || (conf.OAuth2.Endpoints.Token.Scheme == "" && conf.OAuth2.Endpoints.Token.Host == "")) {
    if conf.OAuth2.UserInfo {
        return errors.New("oauth2.userinfo: cannot be used if oauth2.endpoint.auth and oauth2.endpoint.token is set")
    }
}
```

**After:**
```go
if isURLNotEmpty(conf.OAuth2.Endpoints.Auth) && isURLNotEmpty(conf.OAuth2.Endpoints.Token) {
    if conf.OAuth2.UserInfo {
        return errors.New("oauth2.userinfo: cannot be used if oauth2.endpoint.auth and oauth2.endpoint.token is set")
    }
}
```

### 3. Fixed provider.go (Line 116)

**Before:**
```go
if !(conf.OAuth2.Endpoints.Discovery == nil || (conf.OAuth2.Endpoints.Discovery.Scheme == "" && conf.OAuth2.Endpoints.Discovery.Host == "")) {
    logger.LogAttrs(ctx, slog.LevelInfo, fmt.Sprintf(
        "discover oidc auto configuration with provider %s for issuer %s with custom discovery url %s",
        provider.GetName(), conf.OAuth2.Issuer.String(), conf.OAuth2.Endpoints.Discovery.String(),
    ))
    options = append(options, rp.WithCustomDiscoveryUrl(conf.OAuth2.Endpoints.Discovery.String()))
} else {
    // ...
}
```

**After:**
```go
discoveryURL := conf.OAuth2.Endpoints.Discovery
if discoveryURL != nil && (discoveryURL.Scheme != "" || discoveryURL.Host != "") {
    logger.LogAttrs(ctx, slog.LevelInfo, fmt.Sprintf(
        "discover oidc auto configuration with provider %s for issuer %s with custom discovery url %s",
        provider.GetName(), conf.OAuth2.Issuer.String(), conf.OAuth2.Endpoints.Discovery.String(),
    ))
    options = append(options, rp.WithCustomDiscoveryUrl(conf.OAuth2.Endpoints.Discovery.String()))
} else {
    // ...
}
```

## Benefits

1. **More Readable**: The simplified expressions are easier to understand
2. **Reusable**: The `isURLNotEmpty()` helper can be used elsewhere in the codebase
3. **Consistent**: All URL empty/non-empty checks now use the same logic
4. **Lint Clean**: All staticcheck QF1001 warnings resolved

## Verification

✅ All modified files compile successfully
✅ No linting errors remain
✅ Entire project builds without errors
✅ Logic is equivalent (De Morgan's law guarantees this)

## Files Modified

- `internal/config/validate.go` - Added helper function and simplified two expressions
- `internal/oauth2/provider.go` - Simplified one expression
