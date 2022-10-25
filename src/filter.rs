use std::fmt::{Display, Formatter};
use clap::ValueEnum;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Filter {
    // Ether
    Ipv4,
    Arp,
    Ipv6,
    // Transport
    Icmp,
    Tcp,
    Udp,
    Icmpv6,
}

impl Display for Filter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Filter::Ipv4 => "Ipv4",
                Filter::Arp => "Arp",
                Filter::Ipv6 => "Ipv6",
                Filter::Icmp => "Icmp",
                Filter::Tcp => "Tcp",
                Filter::Udp => "Udp",
                Filter::Icmpv6 => "Icmpv6",
            }
        )
    }
}

pub const IP_FILTERS: [Filter; 2] = [Filter::Ipv4, Filter::Ipv6];
pub const TRANSPORT_FILTERS: [Filter; 4] = [Filter::Icmp, Filter::Tcp, Filter::Udp, Filter::Icmpv6];
