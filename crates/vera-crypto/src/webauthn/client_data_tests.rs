//! Client data rules: each case is signed, so only the client data fails.

use super::*;

#[test]
fn chrome_and_platform_client_data_verify() {
    for members in [
        r#","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex""#,
        "",
        r#","androidPackageName":"com.example.app","n":-1.5e+3,"t":true,"z":null"#,
    ] {
        with_client_data(&client_data(members)).unwrap_or_else(|e| panic!("{members}: {e}"));
    }
    let native = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"android:apk-key-hash:AbCdEf0123456789-_"}}"#,
        challenge(&DIGEST)
    );
    with_client_data(native.as_bytes()).unwrap();
}

#[test]
fn values_compare_after_unescaping_and_whitespace_surrounds_tokens() {
    let escaped = format!(
        " \r\n\t{{ \"typ\\u0065\" : \"webauthn\\u002eget\" , \"challenge\":\"{}\\u{}\", \"origin\":\"https:\\/\\/app.example\\ud83d\\ude00\"}} \n",
        &challenge(&DIGEST)[..42],
        format_args!("{:04X}", u32::from(challenge(&DIGEST).as_bytes()[42])),
    );
    with_client_data(escaped.as_bytes()).unwrap();
}

#[test]
fn cross_origin_and_embedded_ceremonies_are_refused() {
    for members in [
        r#","crossOrigin":true"#,
        r#","crossOrigin":null"#,
        r#","crossOrigin":"false""#,
        r#","topOrigin":"https://other.example""#,
        r#","crossOrigin":false,"topOrigin":"https://app.example""#,
    ] {
        assert_eq!(
            with_client_data(&client_data(members)),
            Err(WebauthnError::CrossOrigin),
            "{members}"
        );
    }
}

#[test]
fn a_repeated_member_is_refused_known_or_unknown() {
    let refused = Err(WebauthnError::ClientData("repeats a member"));
    for members in [
        r#","type":"webauthn.get""#,
        r#","challenge":"x""#,
        r#","origin":"https://app.example""#,
        r#","crossOrigin":false,"crossOrigin":false"#,
        r#","extra":1,"extra":1"#,
        r#","extra":1,"ext\u0072a":2"#,
        r#","typ\u0065":"webauthn.get""#,
    ] {
        assert_eq!(
            with_client_data(&client_data(members)),
            refused,
            "{members}"
        );
    }
}

#[test]
fn member_values_are_scalars() {
    for members in [r#","extra":{}"#, r#","extra":{"a":1}"#, r#","extra":[]"#] {
        assert_eq!(
            with_client_data(&client_data(members)),
            Err(WebauthnError::ClientData("member values must be scalars")),
            "{members}"
        );
    }
    let c = challenge(&DIGEST);
    for data in [
        format!(r#"{{"type":1,"challenge":"{c}","origin":"o"}}"#),
        r#"{"type":"webauthn.get","challenge":null,"origin":"o"}"#.to_owned(),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":false}}"#),
    ] {
        assert_eq!(
            with_client_data(data.as_bytes()),
            Err(WebauthnError::ClientData(
                "type, challenge and origin must be strings"
            )),
            "{data}"
        );
    }
}

#[test]
fn required_members_must_appear() {
    let c = challenge(&DIGEST);
    for data in [
        format!(r#"{{"challenge":"{c}","origin":"o"}}"#),
        r#"{"type":"webauthn.get","origin":"o"}"#.to_owned(),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}"}}"#),
    ] {
        assert_eq!(
            with_client_data(data.as_bytes()),
            Err(WebauthnError::ClientData(
                "type, challenge and origin are required"
            )),
            "{data}"
        );
    }
}

#[test]
fn client_data_is_at_most_1024_bytes_with_an_origin_of_at_most_512() {
    let fill = |length: usize| {
        let base = client_data(r#","pad":"""#).len();
        client_data(&format!(r#","pad":"{}""#, "p".repeat(length - base)))
    };
    with_client_data(&fill(MAX_CLIENT_DATA_BYTES)).unwrap();
    assert_eq!(
        with_client_data(&fill(MAX_CLIENT_DATA_BYTES + 1)),
        Err(WebauthnError::ClientData("longer than 1,024 bytes"))
    );
    let origin = |length: usize| {
        format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
            challenge(&DIGEST),
            "o".repeat(length)
        )
    };
    with_client_data(origin(MAX_ORIGIN_BYTES).as_bytes()).unwrap();
    assert_eq!(
        with_client_data(origin(MAX_ORIGIN_BYTES + 1).as_bytes()),
        Err(WebauthnError::ClientData("origin is too long"))
    );
}

#[test]
fn encoding_and_framing_are_strict() {
    let valid = client_data("");
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (
            [b"\xef\xbb\xbf".as_slice(), &valid].concat(),
            "starts with a byte order mark",
        ),
        ([valid.as_slice(), b"x"].concat(), "data follows the object"),
        (
            [valid.as_slice(), b"{}"].concat(),
            "data follows the object",
        ),
        (
            [valid.as_slice(), b"\0"].concat(),
            "data follows the object",
        ),
        (
            client_data(",\"extra\":\"\u{0}\""),
            "unescaped control character",
        ),
        (client_data(",\"extra\":\"\\x\""), "invalid escape"),
        (client_data(r#","extra":"\u12""#), "invalid escape"),
        (client_data(r#","extra":"\ud800""#), "unpaired surrogate"),
        (
            client_data(r#","extra":"\ud800\u0041""#),
            "unpaired surrogate",
        ),
        (client_data(r#","extra":"\udc00""#), "unpaired surrogate"),
        (client_data(r#","extra":01"#), "not a JSON object"),
        (client_data(r#","extra":1."#), "not a JSON number"),
        (client_data(r#","extra":-"#), "not a JSON number"),
        (client_data(r#","extra":1e"#), "not a JSON number"),
        (client_data(r#","extra":+1"#), "not a JSON value"),
        (client_data(r#","extra":tru"#), "not a JSON value"),
        (client_data(r#","extra":'x'"#), "not a JSON value"),
        (client_data(","), "member names must be strings"),
        (client_data(r#",extra:1"#), "member names must be strings"),
        ([&valid[..valid.len() - 1], b"\xff}"].concat(), "not UTF-8"),
        (b"[]".to_vec(), "not a JSON object"),
        (b"".to_vec(), "not a JSON object"),
        (valid[..valid.len() - 1].to_vec(), "not a JSON object"),
        (b"{}".to_vec(), "type, challenge and origin are required"),
    ];
    for (data, reason) in cases {
        assert_eq!(
            with_client_data(&data),
            Err(WebauthnError::ClientData(reason)),
            "{}",
            String::from_utf8_lossy(&data)
        );
    }
}
