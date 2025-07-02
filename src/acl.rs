use ip_network::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
pub enum AclAction {
    Allow,
    Reject,
}

impl AclAction {
    pub fn permitted(self) -> bool {
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AclItem {
    pub action: AclAction,
    pub destination_network: Option<IpNetwork>,
    pub destination_port: Option<u16>,
    pub username: Option<String>,
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

    pub fn into_parts(self) -> (Vec<AclItem>, AclAction) {
        (self.items, self.default_action)
    }

    pub fn is_permitted(&self, username: Option<&str>, ip: IpAddr, dport: u16) -> bool {
        for rule in self.items.iter() {
            let ip_match = rule
                .destination_network
                .map(|i| i.contains(ip))
                .unwrap_or(true);
            let port_match = rule.destination_port.map(|p| p == dport).unwrap_or(true);
            let username_match = match (username, rule.username.as_ref()) {
                (Some(found), Some(expected)) => found == expected,
                (Some(_found), None) => true,
                (None, Some(_)) => false,
                (None, None) => true,
            };
            if ip_match && port_match && username_match {
                return rule.action.permitted();
            }
        }
        self.default_action.permitted()
    }
}

#[cfg(test)]
mod tests {
    use super::{Acl, AclAction, AclItem};
    use ip_network::IpNetwork;
    use std::net::IpAddr;

    #[test]
    fn test_basic() {
        let acl = Acl::from_parts(
            vec![
                AclItem {
                    action: AclAction::Reject,
                    destination_network: None,
                    destination_port: None,
                    username: Some("evil".to_owned()),
                },
                AclItem {
                    action: AclAction::Allow,
                    destination_network: None,
                    destination_port: Some(80),
                    username: None,
                },
                AclItem {
                    action: AclAction::Allow,
                    destination_network: Some(
                        IpNetwork::new("127.0.0.0".parse::<IpAddr>().unwrap(), 8).unwrap(),
                    ),
                    destination_port: None,
                    username: None,
                },
                AclItem {
                    action: AclAction::Allow,
                    destination_network: Some(
                        IpNetwork::new("1.0.0.0".parse::<IpAddr>().unwrap(), 8).unwrap(),
                    ),
                    destination_port: Some(443),
                    username: None,
                },
                AclItem {
                    action: AclAction::Allow,
                    destination_network: None,
                    destination_port: None,
                    username: Some("backdoor".to_owned()),
                },
            ],
            AclAction::Reject,
        );
        let localhost = "127.0.0.1".parse::<IpAddr>().unwrap();
        let non_localhost = "1.1.1.1".parse::<IpAddr>().unwrap();
        let two_network = "2.1.1.1".parse::<IpAddr>().unwrap();
        assert_eq!(acl.is_permitted(None, localhost, 22), true);
        assert_eq!(acl.is_permitted(None, non_localhost, 22), false);
        assert_eq!(acl.is_permitted(None, non_localhost, 80), true);
        assert_eq!(acl.is_permitted(None, non_localhost, 443), true);
        assert_eq!(acl.is_permitted(None, two_network, 443), false);
        assert_eq!(acl.is_permitted(Some("nobody"), non_localhost, 80), true);
        assert_eq!(acl.is_permitted(Some("evil"), non_localhost, 80), false);
        assert_eq!(acl.is_permitted(Some("backdoor"), non_localhost, 22), true);
    }
}
