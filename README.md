# its

Small HMAC-SHA256 helpers for signing strings with an expiration timestamp.
Requires Python 3.15 and uses only the standard library. Tokens are signed,
not encrypted: their contents are readable.

```python
import secrets
import time

from its import salt_key, sign, unsign

# Generate once, keep secret, and reuse to verify existing tokens.
secret_key = secrets.token_bytes(32)

# Derive a separate signing key for each purpose.
key = salt_key(key=secret_key, salt=b"password-reset")

token = sign(
    key=key,
    msg="user:123",
    expiration_timestamp=int(time.time()) + 3600,
)
```

For simple success/failure handling, match `"OK"` or capture the `"ERR"` reason.
Verify with the same key and salt, using the current Unix time in seconds:

```python
match unsign(key=key, value=token, current_time=int(time.time())):
    case ("OK", message):
        print("Verified:", message)
    case ("ERR", reason):
        print("Invalid or expired token:", reason)
```

For exhaustive handling, list every result explicitly:

```python
match unsign(key=key, value=token, current_time=int(time.time())):
    case ("OK", message):
        print("Verified:", message)
    case ("ERR", "SIGNATURE MISSING"):
        print("Missing signature")
    case ("ERR", "SIGNATURE INVALID"):
        print("Invalid signature")
    case ("ERR", "EXPIRATION MISSING"):
        print("Missing expiration")
    case ("ERR", "EXPIRATION NOT INTEGER"):
        print("Expiration must be an integer")
    case ("ERR", "EXPIRATION NOT CANONICAL"):
        print("Expiration has a noncanonical representation")
    case ("ERR", "EXPIRED"):
        print("Token expired")
    case ("ERR", "MESSAGE INVALID BASE64"):
        print("Invalid base64 message")
    case ("ERR", "MESSAGE INVALID UTF8"):
        print("Invalid UTF-8 message")
```

`unsign` deliberately returns tagged tuples: `("OK", message)` or
`("ERR", reason)`. Pyright infers the possible tuple variants, including their
literal string tags, directly from the function's return statements.

The repository enables Pyright's strict mode, which includes
[`reportMatchNotExhaustive`](https://github.com/microsoft/pyright/blob/main/docs/configuration.md#reportMatchNotExhaustive).
In the exhaustive example, if you leave out a case, or add a new error result
to `unsign` without updating the match, Pyright reports the unhandled variant.
This is a static check; Python itself does not require exhaustive matches.

The simple example's `case ("ERR", reason):` accepts any future error reason,
so Pyright cannot flag missing handling for new reasons. List each reason
explicitly when you want that check.

Run the type checker and tests from the repository directory:

```sh
pyright
python3.15 test_its.py
```
