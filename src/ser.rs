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
        d: D,
    ) -> Result<Vec<T>, D::Error> {
        todo!()
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
