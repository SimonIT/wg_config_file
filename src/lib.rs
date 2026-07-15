mod ser;

use crate::ser::comma_sequence;
use crate::ser::publickey_base64;
use crate::ser::staticsecret_base64;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use derive_builder::Builder;
use derive_getters::Getters;
#[cfg(feature = "ip_network")]
use ip_network::IpNetwork;
#[cfg(feature = "ipnet")]
use ipnet::IpNet as IpNetwork;
use serde::{Deserialize, Serialize};
use serini::to_string;
use std::net::SocketAddr;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

#[derive(Builder, Serialize, Deserialize, Clone, Getters)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(strip_option))]
pub struct ConfigurationFile {
    interface: Interface,
    #[builder(default)]
    #[serde(skip_serializing)]
    peers: Vec<Peer>,
}

impl ConfigurationFile {
    /**
     * Returns the configuration as INI-based format like wg expects.
     */
    pub fn format(&self) -> String {
        format!(
            "{}\n{}",
            to_string(self).unwrap(),
            self.peers
                .iter()
                .map(|p| to_string(&PeerSection { peer: p.clone() }).unwrap())
                .collect::<Vec<String>>()
                .join("\n")
        )
    }
}

#[derive(Builder, Serialize, Deserialize, Clone, Getters)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(strip_option))]
pub struct Interface {
    #[serde(with = "staticsecret_base64")]
    private_key: StaticSecret,
    #[builder(default)]
    listen_port: Option<u16>,
    #[builder(default)]
    fw_mark: Option<u32>,
}

impl InterfaceBuilder {
    pub fn private_key_base64(&mut self, value: &str) -> &mut Self {
        let new = self;
        let key = BASE64_STANDARD.decode(value).expect("Invalid base64");
        new.private_key_bytes(key.as_slice())
    }

    pub fn private_key_bytes(&mut self, value: &[u8]) -> &mut Self {
        let new = self;
        let value = StaticSecret::from(<[u8; 32]>::try_from(value).expect("Invalid key length"));
        new.private_key = Some(value);
        new
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct PeerSection {
    peer: Peer,
}

#[derive(Builder, Serialize, Deserialize, Clone, Getters)]
#[serde(rename_all = "PascalCase")]
#[builder(setter(strip_option))]
pub struct Peer {
    #[serde(with = "publickey_base64")]
    public_key: PublicKey,
    #[builder(default)]
    preshared_key: Option<[u8; 32]>, // Maybe change [u8; 32] or another alias
    #[serde(rename(serialize = "AllowedIPs"))]
    #[serde(with = "comma_sequence")]
    allowed_ips: Vec<IpNetwork>,
    #[builder(default)]
    endpoint: Option<SocketAddr>,
    #[builder(default)]
    persistent_keepalive: Option<u16>,
}

impl PeerBuilder {
    pub fn public_key_base64(&mut self, string: &str) -> &mut Self {
        let new = self;
        let key = BASE64_STANDARD.decode(string).expect("Invalid base64");
        new.public_key_bytes(key.as_slice())
    }

    pub fn public_key_bytes(&mut self, value: &[u8]) -> &mut Self {
        let new = self;
        let value = PublicKey::from(<[u8; 32]>::try_from(value).expect("Invalid key length"));
        new.public_key = Some(value);
        new
    }
}

#[cfg(test)]
mod tests {
    use crate::{ConfigurationFileBuilder, InterfaceBuilder, PeerBuilder};
    #[cfg(feature = "ip_network")]
    use ip_network::{IpNetwork, Ipv4Network};
    #[cfg(feature = "ipnet")]
    use ipnet::{IpNet as IpNetwork, Ipv4Net as Ipv4Network};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn it_works() {
        let peers = vec![
            PeerBuilder::default()
                .public_key_base64("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")
                .endpoint(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from_octets([192, 95, 5, 67]),
                    1234,
                )))
                .allowed_ips(vec![
                    IpNetwork::V4(
                        Ipv4Network::new(Ipv4Addr::from_octets([10, 192, 122, 3]), 32).unwrap(),
                    ),
                    IpNetwork::V4(
                        Ipv4Network::new(Ipv4Addr::from_octets([10, 192, 124, 0]), 24).unwrap(),
                    ),
                ])
                .build()
                .unwrap(),
            PeerBuilder::default()
                .public_key_base64("TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=")
                .endpoint(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from_segments([0x2607, 0x5300, 0x60, 0x6b0, 0x0, 0x0, 0xc05f, 0x543]),
                    2468,
                    0,
                    0,
                )))
                .allowed_ips(vec![
                    IpNetwork::V4(
                        Ipv4Network::new(Ipv4Addr::from_octets([10, 192, 122, 4]), 32).unwrap(),
                    ),
                    IpNetwork::V4(
                        Ipv4Network::new(Ipv4Addr::from_octets([192, 168, 0, 0]), 16).unwrap(),
                    ),
                ])
                .build()
                .unwrap(),
        ];
        let config = ConfigurationFileBuilder::default()
            .interface(
                InterfaceBuilder::default()
                    .private_key_base64("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
                    .listen_port(51820)
                    .build()
                    .unwrap(),
            )
            .peers(peers)
            .build();
        println!("{}", config.unwrap().format())
    }
}
