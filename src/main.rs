use crate::filter::{Filter, IP_FILTERS, TRANSPORT_FILTERS};
use crate::handle::handle_ethernet_frame;
use crate::utils::get_default_interface_name;
use crate::vendor::Vendor;
use clap::Parser;
use directories::ProjectDirs;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;
use pnet::util::MacAddr;
use std::path::Path;

mod filter;
mod handle;
mod utils;
mod vendor;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Name of the interface to capture
    #[arg(short = 'i', long = "interface")]
    interface_name: Option<String>,

    /// Name of the packet to show
    #[arg(short = 'f', long = "filter", value_enum, num_args(0..))]
    filters: Option<Vec<Filter>>,

    /// Update oui
    #[arg(long = "update")]
    update: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    sudo::escalate_if_needed().expect("sudo failed");

    let mut filters = match cli.filters {
        Some(filters) => filters,
        None => Vec::new(),
    };
    filters.sort();
    filters.dedup();

    let interfaces = datalink::interfaces();

    let interface_name = match cli.interface_name {
        Some(v) => v,
        None => get_default_interface_name(&interfaces),
    };

    let interface_names_match = |interface: &NetworkInterface| interface.name == interface_name;

    let interface = interfaces
        .into_iter()
        .find(interface_names_match)
        .unwrap_or_else(|| panic!("No such interface: {}", interface_name));

    let oui_filename = Path::new("oui.csv");
    let project_dirs = ProjectDirs::from("net", "henbit", "watermill").unwrap();
    let cache_dir = project_dirs.config_dir();
    let oui_path = cache_dir.join(oui_filename);
    let vendors = Vendor::new(oui_path.as_path(), cli.update).await;

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("No ethernet"),
        Err(e) => panic!("Error occurred: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                handle_ethernet_frame(
                    &interface,
                    &EthernetPacket::new(packet).unwrap(),
                    &filters,
                    &vendors,
                );
            }
            Err(e) => panic!("Error occurred: {}", e),
        }
    }
}
