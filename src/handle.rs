use crate::filter::Filter;
use crate::utils::{
    get_icmp_type_name, get_icmpv6_type_name, get_local_time, get_sender_and_target_vendor,
    host_match,
};
use crate::{Vendor, IP_FILTERS, TRANSPORT_FILTERS};
use pnet::datalink::NetworkInterface;
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{icmp, icmpv6, Packet};
use std::net::IpAddr;

pub fn handle_ethernet_frame(
    interface: &NetworkInterface,
    ethernet: &EthernetPacket,
    filters: &[Filter],
    hosts: &[IpAddr],
    vendors: &[Vendor],
) {
    let interface_name = interface.name.as_str();
    let local_datetime = get_local_time();
    let have_transport_filter = filters
        .iter()
        .any(|filter| TRANSPORT_FILTERS.contains(filter));

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if !filters.is_empty() && !filters.contains(&Filter::Ipv4) && !have_transport_filter {
                return;
            }
            handle_ipv4_packet(interface_name, ethernet, filters, hosts, vendors);
        }
        EtherTypes::Arp => {
            if !filters.is_empty() && !filters.contains(&Filter::Arp) {
                return;
            }
            handle_arp_packet(interface_name, ethernet, hosts, vendors)
        }
        EtherTypes::Ipv6 => {
            if !filters.is_empty() && !filters.contains(&Filter::Ipv6) && !have_transport_filter {
                return;
            }
            handle_ipv6_packet(interface_name, ethernet, filters, hosts, vendors)
        }
        _ => {
            if filters.is_empty() && hosts.is_empty() {
                let (sender_vendor, target_vendor) =
                    get_sender_and_target_vendor(ethernet, vendors);
                println!(
                    "[{}] {} {} {}({}) > {}({}): length {}",
                    interface_name,
                    local_datetime,
                    ethernet.get_ethertype(),
                    ethernet.get_source(),
                    sender_vendor,
                    ethernet.get_destination(),
                    target_vendor,
                    ethernet.packet().len()
                )
            }
        }
    }
}

pub fn handle_ipv4_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    filters: &[Filter],
    hosts: &[IpAddr],
    vendors: &[Vendor],
) {
    let ipv4 = Ipv4Packet::new(ethernet.payload());
    if let Some(ipv4) = ipv4 {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(ipv4.get_source()),
            IpAddr::V4(ipv4.get_destination()),
            ipv4.get_next_level_protocol(),
            ipv4.payload(),
            ethernet,
            filters,
            hosts,
            vendors,
        );
    }
}

pub fn handle_ipv6_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    filters: &[Filter],
    hosts: &[IpAddr],
    vendors: &[Vendor],
) {
    let ipv6 = Ipv6Packet::new(ethernet.payload());
    if let Some(ipv6) = ipv6 {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(ipv6.get_source()),
            IpAddr::V6(ipv6.get_destination()),
            ipv6.get_next_header(),
            ipv6.payload(),
            ethernet,
            filters,
            hosts,
            vendors,
        );
    }
}

pub fn handle_arp_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    hosts: &[IpAddr],
    vendors: &[Vendor],
) {
    let arp = ArpPacket::new(ethernet.payload());
    let local_datetime = get_local_time();
    let (sender_vendor, target_vendor) = get_sender_and_target_vendor(ethernet, vendors);
    if let Some(arp) = arp {
        let host_match = host_match(
            &IpAddr::from(arp.get_sender_proto_addr()),
            &IpAddr::from(arp.get_target_proto_addr()),
            hosts,
        );
        if host_match {
            match arp.get_operation() {
                ArpOperations::Request => println!(
                    "[{}] {} ARP, Request {}({}/{}) > {}({}/{})",
                    interface_name,
                    local_datetime,
                    ethernet.get_source(),
                    arp.get_sender_proto_addr(),
                    sender_vendor,
                    ethernet.get_destination(),
                    arp.get_target_proto_addr(),
                    target_vendor
                ),
                ArpOperations::Reply => println!(
                    "[{}] {} ARP, Reply {}({}/{}) > {}({}/{})",
                    interface_name,
                    local_datetime,
                    ethernet.get_source(),
                    arp.get_sender_proto_addr(),
                    sender_vendor,
                    ethernet.get_destination(),
                    arp.get_target_proto_addr(),
                    target_vendor
                ),
                _ => println!(
                    "[{}] {} ARP, Unknown {}({}/{}) > {}({}/{})",
                    interface_name,
                    local_datetime,
                    ethernet.get_source(),
                    arp.get_sender_proto_addr(),
                    sender_vendor,
                    ethernet.get_destination(),
                    arp.get_target_proto_addr(),
                    target_vendor
                ),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    ethernet: &EthernetPacket,
    filters: &[Filter],
    hosts: &[IpAddr],
    vendors: &[Vendor],
) {
    let local_datetime = get_local_time();
    let have_ip_filters = filters.iter().any(|filter| IP_FILTERS.contains(filter));
    let host_match = host_match(&source, &destination, hosts);
    match protocol {
        IpNextHeaderProtocols::Icmp => {
            if (!filters.is_empty() && !filters.contains(&Filter::Icmp) && !have_ip_filters)
                || !host_match
            {
                return;
            }
            handle_icmp_packet(
                interface_name,
                source,
                destination,
                packet,
                ethernet,
                vendors,
            )
        }
        IpNextHeaderProtocols::Tcp => {
            if (!filters.is_empty() && !filters.contains(&Filter::Tcp) && !have_ip_filters)
                || !host_match
            {
                return;
            }
            handle_tcp_packet(
                interface_name,
                source,
                destination,
                packet,
                ethernet,
                vendors,
            )
        }
        IpNextHeaderProtocols::Udp => {
            if (!filters.is_empty() && !filters.contains(&Filter::Udp) && !have_ip_filters)
                || !host_match
            {
                return;
            }
            handle_udp_packet(
                interface_name,
                source,
                destination,
                packet,
                ethernet,
                vendors,
            )
        }
        IpNextHeaderProtocols::Icmpv6 => {
            if (!filters.is_empty() && !filters.contains(&Filter::Icmpv6) && !have_ip_filters)
                || !host_match
            {
                return;
            }
            handle_icmpv6_packet(
                interface_name,
                source,
                destination,
                packet,
                ethernet,
                vendors,
            )
        }
        _ => {
            if filters.is_empty() && host_match {
                println!(
                    "[{}] {} {} {} > {}: protocol {} length {}",
                    interface_name,
                    local_datetime,
                    match source {
                        IpAddr::V4(_) => "IPv4",
                        IpAddr::V6(_) => "IPv6",
                    },
                    source,
                    destination,
                    protocol,
                    packet.len()
                )
            }
        }
    }
}

pub fn handle_icmp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ethernet: &EthernetPacket,
    vendors: &[Vendor],
) {
    let icmp_packet = IcmpPacket::new(packet);
    let local_datetime = get_local_time();
    let (sender_vendor, target_vendor) = get_sender_and_target_vendor(ethernet, vendors);

    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = icmp::echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}] {} ICMP, Echo Reply {}({}) -> {}({}) (seq={:?}, id={:?})",
                    interface_name,
                    local_datetime,
                    source,
                    sender_vendor,
                    destination,
                    target_vendor,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet =
                    icmp::echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[{}] {} ICMP, Echo Request {}({}) -> {}({}) (seq={:?}, id={:?})",
                    interface_name,
                    local_datetime,
                    source,
                    sender_vendor,
                    destination,
                    target_vendor,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => println!(
                "[{}] {} ICMP, {} {}({}) -> {}({})",
                interface_name,
                local_datetime,
                get_icmp_type_name(icmp_packet.get_icmp_type()),
                source,
                sender_vendor,
                destination,
                target_vendor
            ),
        }
    }
}

pub fn handle_tcp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ethernet: &EthernetPacket,
    vendors: &[Vendor],
) {
    let tcp = TcpPacket::new(packet);
    let local_datetime = get_local_time();
    let (sender_vendor, target_vendor) = get_sender_and_target_vendor(ethernet, vendors);

    if let Some(tcp) = tcp {
        println!(
            "[{}] {} TCP {}({}).{} > {}({}).{}: length {}",
            interface_name,
            local_datetime,
            source,
            sender_vendor,
            tcp.get_source(),
            destination,
            target_vendor,
            tcp.get_destination(),
            packet.len()
        );
    }
}

pub fn handle_udp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ethernet: &EthernetPacket,
    vendors: &[Vendor],
) {
    let udp = UdpPacket::new(packet);
    let local_datetime = get_local_time();
    let (sender_vendor, target_vendor) = get_sender_and_target_vendor(ethernet, vendors);

    if let Some(udp) = udp {
        println!(
            "[{}] {} UDP {}({}).{} > {}({}).{}: length {}",
            interface_name,
            local_datetime,
            source,
            sender_vendor,
            udp.get_source(),
            destination,
            target_vendor,
            udp.get_destination(),
            udp.get_length()
        );
    }
}

pub fn handle_icmpv6_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ethernet: &EthernetPacket,
    vendors: &[Vendor],
) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    let local_datetime = get_local_time();
    let (sender_vendor, target_vendor) = get_sender_and_target_vendor(ethernet, vendors);

    if let Some(icmpv6_packet) = icmpv6_packet {
        match icmpv6_packet.get_icmpv6_type() {
            Icmpv6Types::EchoReply => {
                let echo_reply_packet = icmpv6::echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}] {} ICMPv6, Echo Reply {}({}) -> {}({}) (seq={:?}, id={:?})",
                    interface_name,
                    local_datetime,
                    source,
                    sender_vendor,
                    destination,
                    target_vendor,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            Icmpv6Types::EchoRequest => {
                let echo_request_packet =
                    icmpv6::echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[{}] {} ICMPv6, Echo Request {}({}) -> {}({}) (seq={:?}, id={:?})",
                    interface_name,
                    local_datetime,
                    source,
                    sender_vendor,
                    destination,
                    target_vendor,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => {
                println!(
                    "[{}] {} ICMPv6, {} {}({}) -> {}({})",
                    interface_name,
                    local_datetime,
                    get_icmpv6_type_name(icmpv6_packet.get_icmpv6_type()),
                    source,
                    sender_vendor,
                    destination,
                    target_vendor
                )
            }
        }
    }
}
