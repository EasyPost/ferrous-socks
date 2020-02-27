use ip_network::IpNetwork;
use serde_derive::Deserialize;
use std::net::IpAddr;

#[derive(Debug, Deserialize, Clone, Copy)]
pub enum AclAction {
    Allow,
    Reject,
}

impl AclAction {
    pub fn permitted(&self) -> bool {
        match self {
            AclAction::Allow => true,
            AclAction::Reject => false,
        }
    }
}

impl Default for AclAction {
    fn default() -> Self {
        AclAction::Allow
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AclItem {
    pub action: AclAction,
    pub destination_network: Option<IpNetwork>,
    pub destination_port: Option<u16>,
}

#[derive(Debug)]
pub struct Acl {
    items: Vec<AclItem>,
    default_action: AclAction,
}

impl Acl {
    pub fn from_parts(items: Vec<AclItem>, default_action: AclAction) -> Self {
        Acl {
            items,
            default_action,
        }
    }

    pub fn is_permitted(&self, ip: IpAddr, dport: u16) -> bool {
        for rule in self.items.iter() {
            let ip_match = rule
                .destination_network
                .map(|i| i.contains(ip))
                .unwrap_or(true);
            let port_match = rule.destination_port.map(|p| p == dport).unwrap_or(true);
            if ip_match && port_match {
                return rule.action.permitted();
            }
        }
        self.default_action.permitted()
    }
}
