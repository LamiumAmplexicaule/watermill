use std::net::IpAddr;

use chrono::Local;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::{IcmpType, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Type, Icmpv6Types};

use crate::{MacAddr, Vendor};

pub fn get_default_interface_name(interfaces: &[NetworkInterface]) -> String {
    interfaces
        .iter()
        .find(|interface| {
            if interface.mac.is_none() || !interface.is_up() || interface.is_loopback() {
                return false;
            }
            true
        })
        .unwrap_or_else(|| panic!("No valid interfaces"))
        .name
        .clone()
}

pub fn search_vendor_name(mac_address: MacAddr, vendors: &[Vendor]) -> Option<String> {
    let vendor = vendors.iter().find(|vendor| {
        let oui = format!("{:X}{:X}{:X}", mac_address.0, mac_address.1, mac_address.2);
        vendor.assignment.eq(&oui)
    });
    vendor.map(|vendor| vendor.name.clone())
}

pub fn get_sender_and_target_vendor(
    ethernet: &EthernetPacket,
    vendors: &[Vendor],
) -> (String, String) {
    let sender_vendor = search_vendor_name(ethernet.get_source(), vendors);
    let target_vendor = search_vendor_name(ethernet.get_destination(), vendors);
    (
        sender_vendor.unwrap_or_else(|| "Unknown".to_string()),
        target_vendor.unwrap_or_else(|| "Unknown".to_string()),
    )
}

pub fn host_match(source: &IpAddr, destination: &IpAddr, hosts: &[IpAddr]) -> bool {
    hosts.is_empty()
        || hosts
            .iter()
            .any(|host| host.eq(source) || host.eq(destination))
}

pub fn get_local_time() -> String {
    Local::now().format("%H:%M:%S%.6f").to_string()
}

pub fn get_icmp_type_name(icmp_type: IcmpType) -> String {
    match icmp_type {
        IcmpTypes::EchoReply => "Echo Reply".to_string(),
        IcmpTypes::DestinationUnreachable => "Destination Unreachable".to_string(),
        IcmpTypes::SourceQuench => "Source Quench".to_string(),
        IcmpTypes::RedirectMessage => "Redirect Message".to_string(),
        IcmpTypes::EchoRequest => "Echo Request".to_string(),
        IcmpTypes::RouterAdvertisement => "Router Advertisement".to_string(),
        IcmpTypes::RouterSolicitation => "Router Solicitation".to_string(),
        IcmpTypes::TimeExceeded => "Time Exceeded".to_string(),
        IcmpTypes::ParameterProblem => "Parameter Problem".to_string(),
        IcmpTypes::Timestamp => "Timestamp".to_string(),
        IcmpTypes::TimestampReply => "Timestamp Reply".to_string(),
        IcmpTypes::InformationRequest => "Information Request".to_string(),
        IcmpTypes::InformationReply => "Information Reply".to_string(),
        IcmpTypes::AddressMaskRequest => "Address Mask Request".to_string(),
        IcmpTypes::AddressMaskReply => "Address Mask Reply".to_string(),
        IcmpTypes::Traceroute => "Traceroute".to_string(),
        _ => "Unknown".to_string(),
    }
}

pub fn get_icmpv6_type_name(icmp_type: Icmpv6Type) -> String {
    match icmp_type {
        Icmpv6Types::DestinationUnreachable => "Destination Unreachable".to_string(),
        Icmpv6Types::PacketTooBig => "Packet Too Big".to_string(),
        Icmpv6Types::TimeExceeded => "Time Exceeded".to_string(),
        Icmpv6Types::ParameterProblem => "Parameter Problem".to_string(),
        Icmpv6Types::EchoRequest => "Echo Request".to_string(),
        Icmpv6Types::EchoReply => "Echo Reply".to_string(),
        Icmpv6Types::RouterSolicit => "Router Solicit".to_string(),
        Icmpv6Types::RouterAdvert => "Router Advert".to_string(),
        Icmpv6Types::NeighborSolicit => "Neighbor Solicit".to_string(),
        Icmpv6Types::NeighborAdvert => "Neighbor Advert".to_string(),
        Icmpv6Types::Redirect => "Redirect".to_string(),
        _ => "Unknown".to_string(),
    }
}
