mod ser;

use crate::ser::comma_sequence;
use crate::ser::deserialize_optional_fw_mark;
use crate::ser::deserialize_optional_keepalive;
use crate::ser::is_auto;
use crate::ser::is_disabled_fw_mark;
use crate::ser::is_disabled_keepalive;
use crate::ser::is_false;
use crate::ser::presharedkey_base64;
use crate::ser::publickey_base64;
use crate::ser::semicolon_sequence;
use crate::ser::staticsecret_base64;
use crate::ser::table;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    listen_port: Option<u16>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_fw_mark",
        skip_serializing_if = "is_disabled_fw_mark"
    )]
    #[builder(default)]
    fw_mark: Option<u32>,
    #[cfg(feature = "wg-quick")]
    #[serde(with = "comma_sequence", skip_serializing_if = "Vec::is_empty")]
    #[builder(default)]
    address: Vec<IpNetwork>,
    #[cfg(feature = "wg-quick")]
    #[serde(
        rename(serialize = "DNS"),
        with = "comma_sequence",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[builder(default)]
    dns: Vec<String>,
    #[cfg(feature = "wg-quick")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    mtu: Option<u32>,
    #[cfg(feature = "wg-quick")]
    #[serde(default, with = "table", skip_serializing_if = "is_auto")]
    #[builder(default)]
    table: Table,
    #[cfg(feature = "wg-quick")]
    #[serde(with = "semicolon_sequence", skip_serializing_if = "Vec::is_empty")]
    #[builder(default)]
    pre_up: Vec<String>,
    #[cfg(feature = "wg-quick")]
    #[serde(with = "semicolon_sequence", skip_serializing_if = "Vec::is_empty")]
    #[builder(default)]
    post_up: Vec<String>,
    #[cfg(feature = "wg-quick")]
    #[serde(with = "semicolon_sequence", skip_serializing_if = "Vec::is_empty")]
    #[builder(default)]
    pre_down: Vec<String>,
    #[cfg(feature = "wg-quick")]
    #[serde(with = "semicolon_sequence", skip_serializing_if = "Vec::is_empty")]
    #[builder(default)]
    post_down: Vec<String>,
    #[cfg(feature = "wg-quick")]
    #[serde(skip_serializing_if = "is_false")]
    #[builder(default)]
    save_config: bool,
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

    pub fn fw_mark_off(&mut self) -> &mut Self {
        self.fw_mark = Some(None);
        self
    }

    pub fn fw_mark_u32(&mut self, value: u32) -> &mut Self {
        self.fw_mark = Some(if value == 0 { None } else { Some(value) });
        self
    }

    pub fn fw_mark_hex(&mut self, value: &str) -> &mut Self {
        let value = value.trim_start_matches("0x").trim_start_matches("0X");
        let parsed = u32::from_str_radix(value, 16).expect("Invalid hex fwmark");
        self.fw_mark_u32(parsed)
    }
}

#[derive(Clone, Default)]
pub enum Table {
    Off,
    Number(u32),
    #[default]
    Auto,
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
    #[serde(with = "presharedkey_base64")]
    #[builder(default)]
    preshared_key: Option<[u8; 32]>,
    #[serde(rename(serialize = "AllowedIPs"), with = "comma_sequence")]
    #[builder(default)]
    allowed_ips: Vec<IpNetwork>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    endpoint: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_keepalive",
        skip_serializing_if = "is_disabled_keepalive"
    )]
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

    pub fn preshared_key_base64(&mut self, string: &str) -> &mut Self {
        let new = self;
        let key = BASE64_STANDARD.decode(string).expect("Invalid base64");
        new.preshared_key_bytes(key.as_slice())
    }

    pub fn preshared_key_bytes(&mut self, value: &[u8]) -> &mut Self {
        let new = self;
        let value = <[u8; 32]>::try_from(value).expect("Invalid key length");
        new.preshared_key = Some(Some(value));
        new
    }

    pub fn endpoint_socket_addr(&mut self, value: SocketAddr) -> &mut Self {
        self.endpoint = Some(Some(value.to_string()));
        self
    }

    pub fn endpoint_string(&mut self, value: String) -> &mut Self {
        self.endpoint = Some(Some(value));
        self
    }

    pub fn persistent_keepalive_off(&mut self) -> &mut Self {
        self.persistent_keepalive = Some(None);
        self
    }

    pub fn persistent_keepalive_seconds(&mut self, value: u16) -> &mut Self {
        self.persistent_keepalive = Some(if value == 0 { None } else { Some(value) });
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::{ConfigurationFileBuilder, InterfaceBuilder, PeerBuilder, Table};
    #[cfg(feature = "ip_network")]
    use ip_network::{IpNetwork, Ipv4Network};
    #[cfg(feature = "ipnet")]
    use ipnet::{IpNet as IpNetwork, Ipv4Net as Ipv4Network};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_serialize_config() {
        let mut interface_builder = InterfaceBuilder::default();
        let interface_builder = interface_builder
            .private_key_base64("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
            .listen_port(51820);
        #[cfg(feature = "wg-quick")]
        interface_builder
            .address(vec![
                IpNetwork::V4(
                    Ipv4Network::new(Ipv4Addr::from_octets([10, 192, 122, 1]), 24).unwrap(),
                ),
                IpNetwork::V4(Ipv4Network::new(Ipv4Addr::from_octets([10, 10, 0, 1]), 16).unwrap()),
            ])
            .save_config(true)
            .table(Table::Number(1234))
            .post_up(vec![
                "ip rule add ipproto tcp dport 22 table 1234".to_string(),
            ])
            .pre_down(vec![
                "ip rule delete ipproto tcp dport 22 table 1234".to_string(),
            ]);
        let interface = interface_builder.build().unwrap();

        let peers = vec![
            PeerBuilder::default()
                .public_key_base64("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")
                .endpoint_socket_addr(SocketAddr::V4(SocketAddrV4::new(
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
                .endpoint_socket_addr(SocketAddr::V6(SocketAddrV6::new(
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
            PeerBuilder::default()
                .public_key_base64("gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=")
                .endpoint_string("test.wireguard.com:18981".to_string())
                .allowed_ips(vec![IpNetwork::V4(
                    Ipv4Network::new(Ipv4Addr::from_octets([10, 10, 10, 230]), 32).unwrap(),
                )])
                .build()
                .unwrap(),
        ];
        let config = ConfigurationFileBuilder::default()
            .interface(interface)
            .peers(peers)
            .build();
        println!("{}", config.unwrap().format())
    }
}
