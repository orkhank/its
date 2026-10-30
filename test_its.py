# pyright: reportPrivateUsage=false
# ruff: noqa: S101, PLC0415


def _test_salt_key__matches_itsdangerous_hmac_key_derivation():
    from its import salt_key

    our_result = salt_key(key=b"key", salt=b"salt")

    # got this result via the following:
    # >>> import hashlib, itsdangerous
    # >>> itsdangerous.Signer(
    # >>>     secret_key=b"key",
    # >>>     salt=b"salt",
    # >>>     digest_method=hashlib.sha256,
    # >>>     key_derivation="hmac",
    # >>> ).derive_key()
    itsdangerous_result = b"\x07\xc2e\x14h\\\t.\x12\x1b\xa0\xc6SRrb\x8e\x1b4_*\x1a\x94\xc3\xe3\x84\x97b\xd6\x19\x00*"  # noqa: E501

    assert our_result == itsdangerous_result


def _test_sign_unsign__positive_expiration():
    from its import sign, unsign

    msg = "value"
    expiration = 10
    expected = "dmFsdWU.10.iV0mTJ2SfOmE6GorpUrw7WwZodZX1IpNOiG6D6C6lBw"
    assert (
        sign(key=b"key", msg=msg, expiration_timestamp=expiration) == expected
    )
    assert unsign(current_time=expiration, key=b"key", value=expected) == (
        "OK",
        msg,
    )


def _test_sign_unsign__empty_message_zero_expiration():
    from its import sign, unsign

    msg = ""
    expiration = 0
    expected = ".0.-BRjDLGQFNAQUcOq12Oiy9gWEZ7buLcnIdDWOPBqnwM"
    assert (
        sign(key=b"key", msg=msg, expiration_timestamp=expiration) == expected
    )
    assert unsign(current_time=expiration, key=b"key", value=expected) == (
        "OK",
        msg,
    )


def _test_sign_unsign__ascii_message_large_positive_expiration():
    from its import sign, unsign

    msg = "value"
    expiration = 10**100
    expected = (
        "dmFsdWU.1000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000.MDuJ5tz27cfcQrGoPGDMp7H3-ibM"
        "BnqrcPkskH0mX4o"
    )
    assert (
        sign(key=b"key", msg=msg, expiration_timestamp=expiration) == expected
    )
    assert unsign(current_time=expiration, key=b"key", value=expected) == (
        "OK",
        msg,
    )


def _test_sign_unsign__ascii_message_large_negative_expiration():
    from its import sign, unsign

    msg = "value"
    expiration = -(10**100)
    expected = (
        "dmFsdWU.-100000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000.fsYBETY-baXAXiLc83VshJvShvc"
        "HKcehADFBB6NKyvc"
    )
    assert (
        sign(key=b"key", msg=msg, expiration_timestamp=expiration) == expected
    )
    assert unsign(current_time=expiration, key=b"key", value=expected) == (
        "OK",
        msg,
    )


def _test_sign_unsign__unicode_zero_expiration():
    from its import sign, unsign

    msg = "İstanbul 😀"
    expiration = 0
    expected = (
        "xLBzdGFuYnVsIPCfmIA.0.FBEqsHGc3AF2b3hLaYhD_y1yZGVWLG5gGbsQ5tZkrAE"
    )
    assert (
        sign(key=b"key", msg=msg, expiration_timestamp=expiration) == expected
    )
    assert unsign(current_time=expiration, key=b"key", value=expected) == (
        "OK",
        msg,
    )


def _test_sign_unsign__high_surrogate_zero_expiration():
    from its import sign, unsign

    msg = "\ud800"
    expiration = 0
    expected = "7aCA.0.e1v9c9FTDrsiNCPmfm_0jysYiUnm_Oj-7LXGmfXOl6U"
    assert (
        sign(key=b"key", msg=msg, expiration_timestamp=expiration) == expected
    )
    assert unsign(current_time=expiration, key=b"key", value=expected) == (
        "OK",
        msg,
    )


def _test_sign_unsign__non_bmp_zero_expiration():
    from its import sign, unsign

    msg = "𐀀"
    expiration = 0
    expected = "8JCAgA.0.ebZzER9YycC2CXuuRyNuFUsRzJNs8NQ2kvXm80bREOg"
    assert (
        sign(key=b"key", msg=msg, expiration_timestamp=expiration) == expected
    )
    assert unsign(current_time=expiration, key=b"key", value=expected) == (
        "OK",
        msg,
    )


def _test_sign_unsign__all_python_code_points():
    from its import sign, unsign

    # Includes controls, lone surrogates, surrogate pairs, and non-BMP text.
    msg = "".join(map(chr, range(0x110000)))
    token = sign(key=b"key", msg=msg, expiration_timestamp=10)
    assert token.isascii()
    assert unsign(current_time=0, key=b"key", value=token) == ("OK", msg)


def _test_unsign__accepts_empty_key():
    from its import unsign

    value = "dmFsdWU.10.yFjjYsdJ4_1yPLpcZaiveUn5Udf825OskPuvnA-bAoI"
    assert unsign(key=b"", value=value, current_time=0) == ("OK", "value")


def _test_unsign__rejects_wrong_key():
    from its import unsign

    value = "dmFsdWU.10.iV0mTJ2SfOmE6GorpUrw7WwZodZX1IpNOiG6D6C6lBw"
    assert unsign(key=b"wrong", value=value, current_time=0) == (
        "ERR",
        "SIGNATURE INVALID",
    )


def _test_unsign__rejects_tampered_message():
    from its import unsign

    value = "dGFtcGVyZWQ.10.iV0mTJ2SfOmE6GorpUrw7WwZodZX1IpNOiG6D6C6lBw"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "SIGNATURE INVALID",
    )


def _test_unsign__rejects_tampered_expiration():
    from its import unsign

    value = "dmFsdWU.20.iV0mTJ2SfOmE6GorpUrw7WwZodZX1IpNOiG6D6C6lBw"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "SIGNATURE INVALID",
    )


def _test_unsign__rejects_tampered_signature():
    from its import unsign

    value = "dmFsdWU.10.iV0mTJ2SfOmE6GorpUrw7WwZodZX1IpNOiG6D6C6lBA"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "SIGNATURE INVALID",
    )


def _test_unsign__rejects_empty_token():
    from its import unsign

    value = ""
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "SIGNATURE MISSING",
    )


def _test_unsign__rejects_lone_surrogate_without_signature():
    from its import unsign

    value = "\ud800"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "SIGNATURE MISSING",
    )


def _test_unsign__rejects_empty_signature():
    from its import unsign

    value = "dmFsdWU.10."
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "SIGNATURE INVALID",
    )


def _test_unsign__rejects_surrogate_signature():
    from its import unsign

    value = "dmFsdWU.10.\udfff"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "SIGNATURE INVALID",
    )


def _test_unsign__rejects_signed_surrogate_message():
    from its import unsign

    value = "\ud800.10.ehHlLpAYj0hlgqY_FyvQdB_bXNn1WQ_rwCQTeC89VTA"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "MESSAGE INVALID BASE64",
    )


def _test_unsign__rejects_signed_payload_without_expiration():
    from its import unsign

    value = "value.kPv88V50o2uJ29sqch2a7P_f3dxcg-J_dZJZT3GTJIE"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "EXPIRATION MISSING",
    )


def _test_unsign__rejects_empty_expiration():
    from its import unsign

    value = "dmFsdWU..R4-nbbKO2i9Q7Qp3RwO59H_eoLV_6ciy12OoyJoAUrQ"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "EXPIRATION NOT INTEGER",
    )


def _test_unsign__rejects_text_expiration():
    from its import unsign

    value = "dmFsdWU.pwned._7p0eo-YOBp6bR_RLmXkJsn0T_ybAXtChdlDDjLJmXI"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "EXPIRATION NOT INTEGER",
    )


def _test_unsign__rejects_non_ascii_digit_expiration():
    from its import unsign

    value = "dmFsdWU.\u0661.Hu1sMJTOLzvwCIUt-3TQyzFbalDPd_-LqHAK05_4rMk"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "EXPIRATION NOT INTEGER",
    )


def _test_unsign__rejects_underscores_in_expiration():
    from its import unsign

    value = "dmFsdWU.1_000.1wgCbk3s2lQCXH1FkMWGmQGaMz7DqQ17Rh6G2El8uxA"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "EXPIRATION NOT CANONICAL",
    )


def _test_unsign__rejects_positive_sign_in_expiration():
    from its import unsign

    value = "dmFsdWU.+1.V2ENmm325pXuh6n7-QRfVvHGel1q2sRMq0L3zvdV75M"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "EXPIRATION NOT CANONICAL",
    )


def _test_unsign__rejects_leading_space_in_expiration():
    from its import unsign

    value = "dmFsdWU. 1.wFlmNu0yrkGYSqZV7L7njpfEcrLVEZS0_xUhsmUh4OE"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "EXPIRATION NOT CANONICAL",
    )


def _test_unsign__rejects_leading_zero_in_expiration():
    from its import unsign

    value = "dmFsdWU.01.qywvQORX2TJN12lU5tMCGrSSkdSbhZCAezjcojb1aZo"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "EXPIRATION NOT CANONICAL",
    )


def _test_unsign__rejects_negative_zero_expiration():
    from its import unsign

    value = "dmFsdWU.-0.37N_yOOAFxlMalyPOBQIZ1jMPUzZRTvgj_Nx3L9_6XA"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "EXPIRATION NOT CANONICAL",
    )


def _test_unsign__authenticates_before_parsing_expiration():
    from its import unsign

    value = "value.not-an-integer.invalid"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "SIGNATURE INVALID",
    )


def _test_unsign__rejects_timestamp_beyond_integer_conversion_limit():
    import contextlib
    import sys

    from its import unsign

    limit = sys.get_int_max_str_digits()
    with contextlib.ExitStack() as cleanup:
        _ = cleanup.callback(sys.set_int_max_str_digits, limit)
        sys.set_int_max_str_digits(sys.int_info.str_digits_check_threshold)

        value = (
            "dmFsdWU.999999999999999999999999999999999999999999999999999999999"
            "99999999999999999999999999999999999999999999999999999999999999999"
            "99999999999999999999999999999999999999999999999999999999999999999"
            "99999999999999999999999999999999999999999999999999999999999999999"
            "99999999999999999999999999999999999999999999999999999999999999999"
            "99999999999999999999999999999999999999999999999999999999999999999"
            "99999999999999999999999999999999999999999999999999999999999999999"
            "99999999999999999999999999999999999999999999999999999999999999999"
            "99999999999999999999999999999999999999999999999999999999999999999"
            "9999999999999999999999999999999999999999999999999999999999999999."
            "MGlnr8tNJWnTJF72S7ZOEvsGLq9NGDuwESHujMO_b1g"
        )
        assert unsign(current_time=0, key=b"key", value=value) == (
            "ERR",
            "EXPIRATION NOT INTEGER",
        )


def _test_unsign__before_expiration():
    from its import unsign

    value = "dmFsdWU.10.iV0mTJ2SfOmE6GorpUrw7WwZodZX1IpNOiG6D6C6lBw"
    assert unsign(key=b"key", value=value, current_time=9) == ("OK", "value")


def _test_unsign__after_expiration():
    from its import unsign

    value = "dmFsdWU.10.iV0mTJ2SfOmE6GorpUrw7WwZodZX1IpNOiG6D6C6lBw"
    assert unsign(key=b"key", value=value, current_time=11) == (
        "ERR",
        "EXPIRED",
    )


def _test_unsign__rejects_expired_token():
    from its import unsign

    value = "dmFsdWU.-1.wvBB-OPf1xG28Ebt208mYwOpwDbkHW4tDUVYTciU7wI"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "EXPIRED",
    )


def _test_unsign__checks_expiration_before_decoding_message():
    from its import unsign

    value = "!.10.D6J0bW68Fx9T0-E0KOaHC9dHLCeulX5ccYd_7IF90DA"
    assert unsign(key=b"key", value=value, current_time=11) == (
        "ERR",
        "EXPIRED",
    )


def _test_unsign__authenticates_expired_token_before_checking_expiration():
    from its import unsign

    value = "dmFsdWU.-1.wvBB-OPf1xG28Ebt208mYwOpwDbkHW4tDUVYTciU7wI"
    assert unsign(key=b"wrong", value=value, current_time=0) == (
        "ERR",
        "SIGNATURE INVALID",
    )


def _test_unsign__rejects_invalid_base64_character():
    from its import unsign

    value = "!.10.D6J0bW68Fx9T0-E0KOaHC9dHLCeulX5ccYd_7IF90DA"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "MESSAGE INVALID BASE64",
    )


def _test_unsign__rejects_truncated_base64():
    from its import unsign

    value = "Z.10.marxSN-gbL6SgNZY5qft6w_T7ykBbnjK9McQkT35R3Q"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "MESSAGE INVALID BASE64",
    )


def _test_unsign__rejects_padded_base64():
    from its import unsign

    value = "dmFsdWU=.10.jwNATNIROH2GfU9PLDXJm66H6yfMQKFYLXGE3eaW6cs"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "MESSAGE INVALID BASE64",
    )


def _test_unsign__rejects_noncanonical_base64():
    from its import unsign

    value = "dmFsdWV.10.lzbESEUj9P-SuBZHa8ma089glg00eexny54xhukwXy4"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "MESSAGE INVALID BASE64",
    )


def _test_unsign__rejects_newline_in_base64():
    from its import unsign

    value = "dmFsdWU\n.10.V7as1TwaGuQUfZNgMUJPFhNLjo5f9UZ5BVCMYc_S8mg"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "MESSAGE INVALID BASE64",
    )


def _test_unsign__rejects_standard_base64_alphabet():
    from its import unsign

    value = "/w.10.rB61J1nlt8Q9f1ahHL6svg2pMthjTYzHCsLj9vhg1w8"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "MESSAGE INVALID BASE64",
    )


def _test_unsign__rejects_separator_in_base64():
    from its import unsign

    value = "AA.AA.10.MjU9LG-kXOrPp7Y9Zr8_IcapEkYzr903GXBwl141xzc"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "MESSAGE INVALID BASE64",
    )


def _test_unsign__rejects_invalid_utf8_leading_byte():
    from its import unsign

    value = "_w.10.IFkn2d7Mt3u1b0ppZJ35466MLml13Rv4n-Fzj9w8kt0"
    assert unsign(key=b"key", value=value, current_time=0) == (
        "ERR",
        "MESSAGE INVALID UTF8",
    )


def main():
    _test_salt_key__matches_itsdangerous_hmac_key_derivation()
    _test_sign_unsign__all_python_code_points()
    _test_sign_unsign__ascii_message_large_negative_expiration()
    _test_sign_unsign__ascii_message_large_positive_expiration()
    _test_sign_unsign__empty_message_zero_expiration()
    _test_sign_unsign__high_surrogate_zero_expiration()
    _test_sign_unsign__non_bmp_zero_expiration()
    _test_sign_unsign__positive_expiration()
    _test_sign_unsign__unicode_zero_expiration()
    _test_unsign__accepts_empty_key()
    _test_unsign__after_expiration()
    _test_unsign__authenticates_before_parsing_expiration()
    _test_unsign__authenticates_expired_token_before_checking_expiration()
    _test_unsign__before_expiration()
    _test_unsign__checks_expiration_before_decoding_message()
    _test_unsign__rejects_empty_expiration()
    _test_unsign__rejects_empty_signature()
    _test_unsign__rejects_empty_token()
    _test_unsign__rejects_expired_token()
    _test_unsign__rejects_invalid_base64_character()
    _test_unsign__rejects_invalid_utf8_leading_byte()
    _test_unsign__rejects_leading_space_in_expiration()
    _test_unsign__rejects_leading_zero_in_expiration()
    _test_unsign__rejects_lone_surrogate_without_signature()
    _test_unsign__rejects_negative_zero_expiration()
    _test_unsign__rejects_newline_in_base64()
    _test_unsign__rejects_non_ascii_digit_expiration()
    _test_unsign__rejects_noncanonical_base64()
    _test_unsign__rejects_padded_base64()
    _test_unsign__rejects_positive_sign_in_expiration()
    _test_unsign__rejects_separator_in_base64()
    _test_unsign__rejects_signed_payload_without_expiration()
    _test_unsign__rejects_signed_surrogate_message()
    _test_unsign__rejects_standard_base64_alphabet()
    _test_unsign__rejects_surrogate_signature()
    _test_unsign__rejects_tampered_expiration()
    _test_unsign__rejects_tampered_message()
    _test_unsign__rejects_tampered_signature()
    _test_unsign__rejects_text_expiration()
    _test_unsign__rejects_timestamp_beyond_integer_conversion_limit()
    _test_unsign__rejects_truncated_base64()
    _test_unsign__rejects_underscores_in_expiration()
    _test_unsign__rejects_wrong_key()

    print("PASSED")  # noqa: T201


if __name__ == "__main__":
    main()
