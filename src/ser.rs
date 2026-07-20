use serde::Deserialize;

pub(crate) mod comma_sequence {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serini::to_string;

    pub fn serialize<S: Serializer, T: Serialize>(v: &[T], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(
            v.iter()
                .map(|i| to_string(i).expect("Failed to serialize"))
                .collect::<Vec<String>>()
                .join(", ")
                .as_str(),
        )
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        deserializer: D,
    ) -> Result<Vec<T>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        super::split_sequence(&raw, ',')
    }
}

pub(crate) mod semicolon_sequence {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serini::to_string;

    pub fn serialize<S: Serializer, T: Serialize>(v: &[T], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(
            v.iter()
                .map(|i| to_string(i).expect("Failed to serialize"))
                .collect::<Vec<String>>()
                .join("; ")
                .as_str(),
        )
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        deserializer: D,
    ) -> Result<Vec<T>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        super::split_sequence(&raw, ';')
    }
}

pub(crate) mod staticsecret_base64 {
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};
    use x25519_dalek::StaticSecret;

    pub fn serialize<S: Serializer>(v: &StaticSecret, s: S) -> Result<S::Ok, S::Error> {
        let base64 = BASE64_STANDARD.encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<StaticSecret, D::Error> {
        let base64 = String::deserialize(d)?;
        BASE64_STANDARD
            .decode(base64.as_bytes())
            .map(|bytes| {
                StaticSecret::from(
                    <[u8; 32]>::try_from(bytes.as_slice()).expect("Invalid key length"),
                )
            })
            .map_err(serde::de::Error::custom)
    }
}

pub(crate) mod publickey_base64 {
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};
    use x25519_dalek::PublicKey;

    pub fn serialize<S: Serializer>(v: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        let base64 = BASE64_STANDARD.encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        let base64 = String::deserialize(d)?;
        BASE64_STANDARD
            .decode(base64.as_bytes())
            .map(|bytes| {
                PublicKey::from(<[u8; 32]>::try_from(bytes.as_slice()).expect("Invalid key length"))
            })
            .map_err(serde::de::Error::custom)
    }
}

pub(crate) mod presharedkey_base64 {
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => {
                let base64 = BASE64_STANDARD.encode(bytes);
                String::serialize(&base64, serializer)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        let base64 = Option::<String>::deserialize(deserializer)?;
        match base64.as_deref().map(str::trim) {
            None | Some("") => Ok(None),
            Some(v) => BASE64_STANDARD
                .decode(v.as_bytes())
                .map(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).expect("Invalid key length"))
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}

pub(crate) mod table {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &crate::Table,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            crate::Table::Off => serializer.serialize_str("off"),
            crate::Table::Auto => serializer.serialize_str("auto"),
            crate::Table::Number(v) => serializer.serialize_str(&v.to_string()),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<crate::Table, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let value = raw.trim();

        if value.eq_ignore_ascii_case("auto") {
            return Ok(crate::Table::Auto);
        }

        if value.eq_ignore_ascii_case("off") {
            return Ok(crate::Table::Off);
        }

        let parsed = if let Some(hex) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            u32::from_str_radix(hex, 16)
        } else {
            value.parse::<u32>()
        }
        .map_err(serde::de::Error::custom)?;

        Ok(crate::Table::Number(parsed))
    }
}

pub(crate) fn is_auto(value: &crate::Table) -> bool {
    matches!(value, crate::Table::Auto)
}

pub(crate) fn is_disabled_fw_mark(value: &Option<u32>) -> bool {
    matches!(value, None | Some(0))
}

pub(crate) fn is_false(v: &bool) -> bool {
    !*v
}

pub(crate) fn is_disabled_keepalive(value: &Option<u16>) -> bool {
    matches!(value, None | Some(0))
}

pub(crate) fn deserialize_optional_fw_mark<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    match raw.as_deref().map(str::trim) {
        None | Some("") | Some("off") => Ok(None),
        Some(v) if v.starts_with("0x") || v.starts_with("0X") => u32::from_str_radix(&v[2..], 16)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(v) => v.parse::<u32>().map(Some).map_err(serde::de::Error::custom),
    }
}

pub(crate) fn deserialize_optional_keepalive<'de, D>(
    deserializer: D,
) -> Result<Option<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    match raw.as_deref().map(str::trim) {
        None | Some("") | Some("off") => Ok(None),
        Some(v) => v
            .parse::<u16>()
            .map(|value| if value == 0 { None } else { Some(value) })
            .map_err(serde::de::Error::custom),
    }
}

fn split_sequence<'de, T, E>(raw: &str, delimiter: char) -> Result<Vec<T>, E>
where
    T: Deserialize<'de>,
    E: serde::de::Error,
{
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    trimmed
        .split(delimiter)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| T::deserialize(serde::de::value::StrDeserializer::<E>::new(item)))
        .collect()
}
