lazy import base64
lazy import binascii
lazy import hashlib
lazy import hmac


def salt_key(*, key: bytes, salt: bytes):
    return hmac.digest(key=key, msg=salt, digest=hashlib.sha256)


def sign(*, key: bytes, msg: str, expiration_timestamp: int):
    _ = str(expiration_timestamp)
    expirationb = _.encode("ascii")

    # surrogatepass preserves every Python string, including lone surrogates.
    _ = msg.encode("utf-8", "surrogatepass")
    msgb = base64.urlsafe_b64encode(_, padded=False)

    _ = msgb + b"." + expirationb
    _ = hmac.digest(key=key, msg=_, digest=hashlib.sha256)
    signature = base64.urlsafe_b64encode(_, padded=False)

    _ = msgb + b"." + expirationb + b"." + signature

    return _.decode("ascii")


def unsign(*, key: bytes, value: str, current_time: int):  # noqa: PLR0911
    valueb = value.encode("utf-8", "surrogatepass")
    timestamped_msg, _, signature = valueb.rpartition(b".")

    if _ == b"":
        return "ERR", "SIGNATURE MISSING"

    # do not check signature with `sig1 == sig2` !!
    # that is susceptible to timing attacks: https://w.wiki/sgxz
    _ = hmac.digest(key=key, msg=timestamped_msg, digest=hashlib.sha256)
    _ = base64.urlsafe_b64encode(_, padded=False)
    _ = hmac.compare_digest(_, signature)

    if _ is False:
        return "ERR", "SIGNATURE INVALID"

    encoded_msg, _, expiration = timestamped_msg.rpartition(b".")

    if _ == b"":
        return "ERR", "EXPIRATION MISSING"

    try:
        expiration_timestamp = int(expiration)

    except ValueError:
        return "ERR", "EXPIRATION NOT INTEGER"

    # int accepts whitespace, underscores, and other noncanonical spellings.
    _ = str(expiration_timestamp)
    _ = _.encode("ascii")

    if _ != expiration:
        return "ERR", "EXPIRATION NOT CANONICAL"

    if current_time > expiration_timestamp:
        return "ERR", "EXPIRED"

    try:
        msgb = base64.b64decode(
            encoded_msg,
            altchars=b"-_",
            padded=False,
            ignorechars=b"",
            canonical=True,
        )

    except binascii.Error:
        return "ERR", "MESSAGE INVALID BASE64"

    try:
        msg = msgb.decode("utf-8", "surrogatepass")

    except UnicodeDecodeError:
        return "ERR", "MESSAGE INVALID UTF8"

    return "OK", msg
