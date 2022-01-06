use std::net::Ipv4Addr;

use pnet::datalink::{MacAddr};
use pnet::packet::{MutablePacket};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperation};
use pnet::packet::arp::{MutableArpPacket};
use pnet::packet::ethernet::{MutableEthernetPacket};
use pnet::packet::ethernet::EtherTypes;

pub fn make_arp_packet<'a>(source_ip: Ipv4Addr,
                           source_mac: MacAddr,
                           target_ip: Ipv4Addr,
                           target_mac: MacAddr, arp_operation: ArpOperation) -> MutableEthernetPacket<'a>  {

    let ethernet_buffer = vec![0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::owned(ethernet_buffer).unwrap();

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let arp_buffer = vec![0u8; 28];
    let mut arp_packet = MutableArpPacket::owned(arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(arp_operation);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);


    ethernet_packet.set_payload(arp_packet.packet_mut());
    ethernet_packet
}
