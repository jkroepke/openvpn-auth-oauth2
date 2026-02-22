# Encryption and Cryptography

## Overview

openvpn-auth-oauth2 uses encryption to protect sensitive data that is transmitted to OpenVPN clients. This prevents client-side modification of tokens and session state.

Since OpenVPN clients have a strict limit of 245 ASCII characters for data transmission, we use **Salsa20 stream cipher with HMAC-SHA256 authentication** - a combination that provides strong security with minimal overhead.

## Encryption Algorithm: Salsa20 + HMAC-SHA256

### Why Salsa20?

**Salsa20** is a modern stream cipher that offers:
- ✅ **Minimal overhead**: Only 8-byte nonce (vs 12-16 bytes for AEAD ciphers)
- ✅ **Stream cipher**: Produces ciphertext of exactly the same size as plaintext
- ✅ **Proven security**: Well-analyzed cryptographic algorithm
- ✅ **Encrypt-then-MAC**: Combined with HMAC-SHA256 for authentication

### Compared to Alternatives

| Algorithm | Nonce | Auth | Overhead | Plaintext Capacity |
|-----------|-------|------|----------|-------------------|
| **Salsa20 + HMAC-SHA256** | 8 bytes | ✅ Yes | **24 bytes** | **~221 characters** |
| AES-GCM | 12 bytes | ✅ Yes | 28 bytes | ~217 characters |
| ChaCha20-Poly1305 | 12 bytes | ✅ Yes | 28 bytes | ~217 characters |
| AES-CFB (deprecated) | 16 bytes | ❌ No | 16 bytes | ~229 characters |

## Data Structure

The encrypted data is structured as follows:

```
[Nonce (8 bytes)] + [Ciphertext (variable)] + [HMAC Tag (16 bytes)]
```

### Encryption Process (Encrypt-then-MAC)

1. Generate random 8-byte nonce
2. Encrypt plaintext using Salsa20 with the derived key
3. Calculate HMAC-SHA256 over [nonce + ciphertext]
4. Append HMAC tag to result

### Decryption Process

1. Extract nonce (first 8 bytes)
2. Extract ciphertext (middle bytes)
3. Extract HMAC tag (last 16 bytes)
4. **Verify** HMAC-SHA256 before decryption (constant-time comparison)
5. If HMAC is valid, decrypt ciphertext using Salsa20
6. Return plaintext

## Secret Key Derivation

User-provided secret keys of any length are automatically derived to 32 bytes using **SHA256**:

```go
key := sha256.Sum256([]byte(userProvidedSecret))
```

This means:
- ✅ Secrets can be any length (short or long)
- ✅ Consistent 32-byte key for Salsa20
- ✅ No weak key sizes possible

## Security Properties

### Confidentiality
- **Salsa20** provides stream cipher encryption
- Each encryption uses a fresh random 8-byte nonce
- Key derivation using SHA256 ensures uniform key distribution

### Integrity & Authenticity
- **HMAC-SHA256** protects against tampering
- Constant-time comparison prevents timing attacks
- Combines with encryption to protect entire message

### Protection Against Attacks
- ✅ **Replay attacks**: Fresh nonce prevents duplicate ciphertexts
- ✅ **Tampering**: HMAC-SHA256 detects any bit modifications
- ✅ **Key derivation**: SHA256 prevents weak key attacks
- ✅ **Timing attacks**: Constant-time HMAC verification

## Where Encryption is Used

### 1. OAuth2 Refresh Token Storage (`--oauth2.refresh.secret`)

When OAuth2 refresh is enabled (`--oauth2.refresh.enabled`), tokens are stored in memory with encryption:
- Tokens are encrypted before storage
- Automatically decrypted when needed for token refresh
- Protects against memory dumps of running process

**Configuration:**
```yaml
oauth2:
  refresh:
    enabled: true
    secret: "your-secret-key-here"
    expires: 8h
```

### 2. HTTP State Cookie Encryption (`--http.secret`)

State parameters passed through OAuth2 flows are encrypted:
- Prevents CSRF and state tampering attacks
- Protects user session information
- OpenVPN session ID, username, and IP address are encrypted

**Configuration:**
```yaml
http:
  secret: "your-secret-key-here"
```

## Configuration Guidelines

### Secret Key Requirements

- **Minimum length**: Any length is supported (internally derived to 32 bytes)
- **Recommended length**: 32 characters or longer
- **Format**: Must be a valid string (no special length restrictions like AES)
- **Storage**: Use environment variables or secure file references

### Examples

**Using environment variable:**
```bash
export CONFIG_HTTP_SECRET="your-random-secret-here"
```

**Using config file:**
```yaml
http:
  secret: "your-random-secret-here"

oauth2:
  refresh:
    secret: "another-random-secret-here"
```

**Reading from secure file:**
```yaml
http:
  secret: "file:///etc/openvpn-auth-oauth2/secrets/http.secret"
```

### Secret Generation

Generate cryptographically secure secrets using:

```bash
# Using OpenSSL
openssl rand -base64 32

# Using /dev/urandom
head -c 32 /dev/urandom | base64

# Using Go
go run -c "fmt.Println(base64.StdEncoding.EncodeToString(make([]byte, 32)))"
```

## Migration from Previous Encryption

### Previous Implementation (AES-CFB)

Earlier versions used **AES-CFB** for encryption:
- ❌ No authentication (HMAC)
- ❌ Could not detect tampering
- ❌ Deprecated due to lack of authenticity

### Migration to Salsa20

The migration from AES-CFB to Salsa20+HMAC is **transparent** to users:
- All existing secrets continue to work
- New encryptions use Salsa20+HMAC
- Old AES-CFB encrypted data cannot be read (expected behavior)
- Refresh tokens will need to be re-issued on first use after migration

## Performance Considerations

### Overhead Analysis

With a typical 111-byte payload (JWT token):

| Algorithm | Encrypted Size | Base64 Size | Available Space (245 limit) |
|-----------|----------------|-------------|---------------------------|
| Salsa20 + HMAC | 135 bytes | 180 chars | **65 characters** |
| AES-GCM | 139 bytes | 188 chars | 57 characters |
| AES-CFB | 127 bytes | 172 chars | 73 characters |

**Result**: Salsa20 + HMAC provides nearly the same capacity as AES-CFB while adding essential authentication.

### Speed

- **Salsa20**: Very fast stream cipher (suitable for high-throughput)
- **HMAC-SHA256**: Also very fast
- **Combined overhead**: Minimal per encryption/decryption operation

## Further Reading

- [Salsa20 Specification](https://cr.yp.to/snuffle/spec.pdf)
- [HMAC RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104)
- [OWASP: Authenticated Encryption](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
