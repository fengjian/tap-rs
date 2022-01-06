#[macro_use] extern crate log;
use log::Level;


use std::collections::HashMap;
use std::time::Duration;

use async_std::{fs, io, net::TcpListener, net::TcpStream, net::UdpSocket, prelude::*, task};
use async_std::net::SocketAddr;
use async_std::sync::{Arc, RwLock};
use clap::{App, Arg};
use crypto::{rc4::Rc4, symmetriccipher::SynchronousStreamCipher};
use pnet::packet::{Packet};
use pnet::packet::arp::{ArpOperations};
use pnet::packet::arp::{ArpPacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ethernet::EtherTypes;
use smol::{self, Async};
use sysinfo::{DiskExt, System, SystemExt};
use toml;

use crate::util::cmd;
use crate::arp_util::make_arp_packet;
use crate::config::{Config, RC4_KEY, ETHERNET_HEADER_SIZE, RunMode};
use crate::iface::{Iface};
use crate::iface::Mode::MacvTap;
use crate::tap_packet::{TAP_PROTOCOL_CC, TAP_PROTOCOL_HEADER_SIZE, TAP_PROTOCOL_REPORT, TapPacketHeader};
use daemonize::Daemonize;

pub mod iface;
pub mod arp_util;
pub mod tap_packet;
pub mod config;
#[macro_use]
pub mod util;

const DEFAULT_RW_TIMEOUT:u64 = 120;

async fn handle_arp(buf: &[u8], iface: Arc<Async<Iface>>) {
    if let Some(arp_packet) = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]) {
        debug!("request arp {:?}", arp_packet);

        let sender_hw_addr = arp_packet.get_sender_hw_addr();
        let sender_ip_addr = arp_packet.get_sender_proto_addr();
        let _target_hw_addr = arp_packet.get_target_hw_addr();
        let target_ip_addr = arp_packet.get_target_proto_addr();

        if &target_ip_addr.to_string() == iface.get_ref().get_ip() {
            let eth_packet = make_arp_packet(iface.get_ref().get_ip().parse().unwrap(),
            iface.get_ref().get_mac().parse().unwrap(),
            sender_ip_addr,
            sender_hw_addr, ArpOperations::Reply);
            debug!("arp packet len {}", eth_packet.packet().len());
            iface.as_ref().write(eth_packet.packet()).await;
        } else {
            debug!("ignore arp {:?}", arp_packet);
        }
    } else {
        error!("invalid arp packet");
    }
}

async fn tcp_client_proc_report(mut stream: TcpStream) -> io::Result<()> {
    let rw_timeout = DEFAULT_RW_TIMEOUT;
    let sys = System::new();

    let mut header_buf = vec![0u8; TAP_PROTOCOL_HEADER_SIZE as usize];
    let interval = 60;
    loop {
        let load_one = sys.get_load_average().one;
        let total_mem = sys.get_total_memory();
        let use_mem = sys.get_used_memory();

        let payload_str = format!("cpu: {}, total_mem: {}, use_mem: {}", load_one,
                                  total_mem, use_mem);

        let payload = payload_str.as_bytes();
        let mut payload_encode = vec![0u8; payload.len()];

        let mut rc4 = Rc4::new(RC4_KEY.as_bytes());
        rc4.process(&payload, &mut payload_encode);

        let packet = TapPacketHeader::from_slice_as_mut(&mut header_buf);
        packet.protocol = TAP_PROTOCOL_REPORT;
        packet.size = payload.len() as u32;

        io::timeout(Duration::from_secs(rw_timeout), async {
            stream.write_all(&header_buf).await?;
            stream.write_all(&payload_encode).await?;
            Ok(())
        }).await?;

        task::sleep(Duration::from_secs(interval)).await;
    }

#[allow(unreachable_code)]
    Ok(())
}


async fn tcp_client_mode(config: Arc<Config>) -> io::Result<()>{
    let rw_timeout = DEFAULT_RW_TIMEOUT;

    let mut stream = TcpStream::connect(&config.server.bind_addr).await?;
    info!("Client connected to {}", &stream.peer_addr()?);

    let mut header_buf = vec![0u8; TAP_PROTOCOL_HEADER_SIZE as usize];
    let packet = TapPacketHeader::from_slice_as_mut(&mut header_buf);
    packet.protocol = TAP_PROTOCOL_CC;

    io::timeout(Duration::from_secs(rw_timeout), async {
        stream.write_all(&header_buf).await?;
        stream.read(&mut header_buf).await?;
        Ok(())
    }).await?;

    let packet = TapPacketHeader::from_slice_as_ref(&header_buf);

    if packet.protocol == TAP_PROTOCOL_CC && packet.size > 0 {
        let mut payload = vec![0u8; packet.size as usize];
        let mut payload_decode = vec![0u8; payload.len()];

        stream.read(&mut payload).await?;
        let mut rc4 = Rc4::new(RC4_KEY.as_bytes());
        rc4.process(&payload, &mut payload_decode);

        let mut decode_value:Config = toml::from_slice(&payload_decode).expect("invalid toml format");
        decode_value.run_mode = RunMode::Client;
        decode_value.tap_mode = decode_value.client_tap_mode.unwrap_or(MacvTap);

        if let Some(content) = &decode_value.server.script_content {
            let tmp_sh = "/tmp/tap-rs_client.sh";
            fs::write(tmp_sh, content).await?;

            task::spawn_blocking(move || {
                let args = vec![tmp_sh];
                let ret = cmd("/bin/bash", &args);
                if !ret.success() {
                    let ret_code = ret.code().expect("invalid ret code");
                    error!("Client exec remote script error, exit code {}", ret_code);
                    std::process::exit(ret_code);
                }
            }).await;
        }

        std::mem::drop(stream);
        task::spawn(run_udp_mode(Arc::new(decode_value)));

        let interval = 120;
        loop {
            let stream_wrap = TcpStream::connect(&config.server.bind_addr).await;
            if let Ok(stream) = stream_wrap {
                let report_handle = task::spawn(tcp_client_proc_report(stream));
                report_handle.await.map_err(|e| {
                    error!("tcp proc report err: {}", e);
                });

            }

            task::sleep(Duration::from_secs(interval)).await;
        }
    } else {
        error!("invalid TAP_PROTOCOL_CC protocol");
    }


    Ok(())
}


async fn tcp_server_process(stream: TcpStream, config: Arc<Config>) -> io::Result<()> {
    let rw_timeout = DEFAULT_RW_TIMEOUT;

    info!("Server accepted from: {}", stream.peer_addr()?);
    let mut reader = stream.clone();
    let mut writer = &stream;

    loop {
        let mut header_buf = vec![0u8; TAP_PROTOCOL_HEADER_SIZE as usize];
        io::timeout(Duration::from_secs(rw_timeout), async {
            let n = reader.read(&mut header_buf).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid tap protocol header"));
            }

            Ok(())
        }).await?;

        let packet = TapPacketHeader::from_slice_as_mut(& mut header_buf);

        let mut payload = vec![0u8; packet.size as usize];
        let mut payload_decode = vec![0u8; payload.len()];

        let mut readn = 0;
        if packet.size > 0 {
            readn = io::timeout(Duration::from_secs(rw_timeout), async {
                let n = reader.read(&mut payload).await?;
                Ok(n)
            }).await?;

            if readn > 0 {
                let mut rc4 = Rc4::new(RC4_KEY.as_bytes());
                rc4.process(&payload, &mut payload_decode);
            }
        }

        match packet.protocol {
            TAP_PROTOCOL_CC => {
                info!("Server recv cc");
                if let Some(_content) = &config.server.script_content {
                    let toml_str = toml::Value::try_from(config.as_ref()).expect("Serialize error").to_string();
                    debug!("toml str is {}", &toml_str);
                    let toml_buf = toml_str.as_bytes();

                    let mut encode_toml_buf = vec![0u8; toml_buf.len()];

                    let mut rc4 = Rc4::new(RC4_KEY.as_bytes());
                    rc4.process(&toml_buf, &mut encode_toml_buf);

                    packet.size = toml_buf.len() as u32;

                    io::timeout(Duration::from_secs(rw_timeout), async {
                        writer.write_all(&header_buf).await?;
                        writer.write_all(&encode_toml_buf).await?;
                        Ok(())
                    }).await?;
                } else {
                    info!("Server not found script");
                }
            },

            TAP_PROTOCOL_REPORT => {
                if readn > 0 {
                    let report = String::from_utf8(payload_decode).unwrap_or("".to_string());
                    info!("{}: {}",stream.peer_addr()?, report);
                } else {
                    error!("read report len err: {}", readn);
                }
            },
            _ => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid tap protocol type"));
            }
        }
    }

#[allow(unreachable_code)]
    Ok(())
}


async fn tcp_server_mode(config: Arc<Config>) {
    info!("Start tcp server");
    let listener = TcpListener::bind(&config.server.bind_addr).await.expect("unable to bind addr");
    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        match stream {
            Ok(s) => {
                let c = config.clone();
                task::spawn(async {
                    tcp_server_process(s, c).await.map_err(|e| {
                        error!("tcp server process err: {}",e);
                    });
                });
            },
            Err(e) => {
                error!("Tcp server incoming err: {}", e);
            }
        };
    }

}


async fn run_tcp_channel(config: Arc<Config>) {
    match config.run_mode {
            RunMode::Client => {
                tcp_client_mode(config.clone()).await.map_err(|e| {
                    error!("tcp client err: {}", e);
                });
            },
            RunMode::Server => {
                tcp_server_mode(config.clone()).await;
            }
        };
}


async fn run_udp_mode(config: Arc<Config>) {
    let mtu = config.mtu.unwrap_or(1500);

    let socket = Arc::new(match config.run_mode {
        RunMode::Client => {
            UdpSocket::bind("0.0.0.0:0").await.expect("bind 0.0.0.0 failed")
        },
        RunMode::Server => {
            UdpSocket::bind(&config.server.bind_addr).await.expect("server bind addr failed")
        }
    });

    let reply_arp = config.reply_arp.unwrap_or(false);

    let remote_addr: Arc<RwLock<SocketAddr>> = Arc::new(RwLock::new(config.server.bind_addr.parse().expect("invalid ip addr")));
    let mut handles = vec![];
    let nodes = Arc::new(RwLock::new(HashMap::new()));
    let nodes_ip = Arc::new(RwLock::new(HashMap::new()));


    for nic in &config.nics {
        let config = config.clone();

        let nic = nic.clone();
        info!("nic name {}", &nic.ifname);

        let remote_addr = remote_addr.clone();
        let socket = socket.clone();

        let tap_mode = config.tap_mode;
        let oiface = Iface::new(&nic.ifname,
                                tap_mode,
                                &nic.ip,
                                &nic.mac,
                                mtu).expect("unable to create tap dev");

        //oiface.flush_nic(true);
        let new_mac = oiface.get_mac().clone();
        let new_ip = oiface.get_ip().clone();

        let iface = Arc::new(Async::new(oiface).unwrap());
        nodes.write().await.insert(new_mac, iface.clone());
        nodes_ip.write().await.insert(new_ip, iface.clone());


        info!("Nic is {:?}", &nic);
        let handle = task::spawn(async move {
            info!("Start {} read, socket send_to task", &nic.ifname);
            let mut sendbuf = vec![0u8; (ETHERNET_HEADER_SIZE + mtu) as usize];
            let mut send_encrypt_buf = vec![0u8; sendbuf.len()];

            let default_remote_addr = config.server.bind_addr.parse::<SocketAddr>().expect("invalid ip addr");
            loop {
                let size = iface.as_ref().read(& mut sendbuf).await.unwrap_or(0);
                if size > 0 {
                    let eth: EthernetPacket = EthernetPacket::new(&sendbuf).unwrap(); //ensure is eth packet
                    debug!("{} read eth {} packet {:?} size: {} ",&nic.ifname, eth.get_ethertype(), eth, size);

                    if log_enabled!(Level::Debug) {
                        if eth.get_ethertype() == EtherTypes::Arp {
                            let arp_packet = ArpPacket::new(&sendbuf[MutableEthernetPacket::minimum_packet_size()..]).unwrap(); //ensure is arp packet
                            debug!("{} arp read {:?}", iface.get_ref().get_name(), arp_packet);
                        }
                    }

                    let run_mode = config.run_mode;
                    if reply_arp && run_mode == RunMode::Client && eth.get_ethertype() == EtherTypes::Arp {
                        debug!("Client handle arp");
                        handle_arp(&sendbuf, iface.clone()).await;
                    } else {
                        let addrs = *remote_addr.clone().read().await;
                        // avoid send to server self

                        if run_mode == RunMode::Server && &addrs == &default_remote_addr {
                            debug!("Server avoid send to self {}", &addrs);
                        } else {
                            let mut rc4 = Rc4::new(RC4_KEY.as_bytes());
                            rc4.process(&sendbuf[0..size], &mut send_encrypt_buf[0..size]);

                            let n = socket.send_to(&send_encrypt_buf[0..size], &addrs).await.unwrap_or(0);
                            debug!("Socket send to {} bytes {}", &addrs, n);
                        }

                    }
                }
            }
        });

        handles.push(handle);
    }

    let socket_recv_handle = task::spawn(async move {
        info!("Start socket recv task");
        let mut recv_de_buf = vec![0u8; (ETHERNET_HEADER_SIZE + mtu) as usize];
        let mut recvbuf = vec![0u8; recv_de_buf.len()];

        loop {
            let (n, peer) = socket.recv_from(&mut recv_de_buf).await.unwrap_or((0, *remote_addr.clone().read().await));
            if n > 0 {
                //rc4 decrypt buf
                let mut rc4 = Rc4::new(RC4_KEY.as_bytes());
                rc4.process(&recv_de_buf[0..n], &mut recvbuf[0..n]);

                let eth_wrap = EthernetPacket::new(&recvbuf);
                if eth_wrap.is_none() {
                    error!("recv invalid ethernet packet");
                    continue;
                }

                let eth: EthernetPacket = eth_wrap.unwrap();
                debug!("Socket recv {} bytes from {} eth {} packet {:?}", n, peer, eth.get_ethertype(), eth);

                let nodes_ = nodes.clone();
                let t = nodes_.read().await;
                let iface_wrap = match config.run_mode {
                    RunMode::Server => {
                        t.get(&eth.get_destination().to_string())
                    },

                    RunMode::Client => {
                        t.get(&eth.get_source().to_string())
                    }
                };

                match iface_wrap {
                    Some(async_iface) => {
                        let size = async_iface.as_ref().write(&recvbuf[0..n]).await.unwrap_or(0);
                        debug!("Write {} bytes to {}", size, async_iface.get_ref().get_name());
                    },
                    None => {
                        match config.run_mode {
                            RunMode::Server => {
                                if eth.get_ethertype() == EtherTypes::Arp {
                                    let arp_packet = ArpPacket::new(&recvbuf[MutableEthernetPacket::minimum_packet_size()..]).unwrap(); //TODO and_then
                                    let target_ip_addr = arp_packet.get_target_proto_addr();
                                    let nodes_ = nodes_ip.clone();
                                    let t = nodes_.read().await;
                                    let iface_ip = t.get(&target_ip_addr.to_string());
                                    match iface_ip {
                                        Some(async_iface2) => {
                                            debug!("Server match iface ip {}", target_ip_addr);
                                            let size = async_iface2.as_ref().write(&recvbuf[0..n]).await.unwrap_or(0);
                                            debug!("Server write arp {:?}", arp_packet);
                                            debug!("Server write {} bytes to {}", size, async_iface2.get_ref().get_name());
                                        },
                                        None => {info!("Server arp no found {}", target_ip_addr);}
                                    }
                                } else {
                                    debug!("Server ignore other eth {}, {:?}", eth.get_ethertype(), eth);
                                }

                            },

                            _  => {
                                debug!("Client ignore not match mac");
                            }
                        }

                    }
                };

                if config.run_mode == RunMode::Server {
                    *remote_addr.clone().write().await = peer;
                }

            }

        } // loop end

    });

    handles.push(socket_recv_handle);

    for i in handles {
        i.await;
    }
}

fn main() {
    env_logger::init();

    let matches = App::new("tap-rs Program")
        .version("1.1")
        .author("fengjian <hello@gnu.com>")
        .about("Light tap/macvtap Program")
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("FILE")
            .help("Sets a custom config file")
            .takes_value(true))
        .get_matches();

    let config = matches.value_of("config").unwrap_or("default_config.toml");
    info!("Value for config: {}", config);

    let contents = std::fs::read_to_string(config).expect("read config file error");
    let mut decode_config:Config  = toml::from_str(&contents).expect("invalid toml file");

    if let Some(path) = &decode_config.server.script_path {
        let script_contents = std::fs::read_to_string(path).expect("read cc script file error");
        decode_config.server.script_content = Some(script_contents);
    }

    let is_daemon = decode_config.is_daemon.unwrap_or(false);
    if is_daemon {
        let stdout = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open((&decode_config).stdout.as_ref().unwrap_or(&"/tmp/tap-rs.out".to_string())).expect("create stdout file error");

        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open((&decode_config).stderr.as_ref().unwrap_or(&"/tmp/tap-rs.err".to_string())).expect("create stderr file error");

        let daemonize = Daemonize::new()
            .pid_file((&decode_config).pid.as_ref().unwrap_or(&"/tmp/tap-rs.pid".to_string())) // Every method except `new` and `start`
            .chown_pid_file(true)      // is optional, see `Daemonize` documentation
            .working_directory("/") // for default behaviour.
            .user("root")
            .group("root") // Group name
            .group(1)        // or group id.
            .umask(0o027)    // Set umask, `0o027` by default.
            .stdout(stdout)  // Redirect stdout to `/tmp/daemon.out`.
            .stderr(stderr)  // Redirect stderr to `/tmp/daemon.err`.
            .exit_action(|| info!("Executed before master process exits"))
            .privileged_action(|| "Executed before drop privileges");

        match daemonize.start() {
            Ok(_) => info!("Success, daemonized"),
            Err(e) => {
                error!("Start daemon error: {}", e);
                std::process::exit(-1);
            }
        }
    }

    smol::run(async move {
        let arc_config = Arc::new(decode_config);

        let run_mode = arc_config.run_mode;
        if run_mode == RunMode::Server {
            let tunnel = task::spawn(run_udp_mode(arc_config.clone()));
            let cc_channel = task::spawn(run_tcp_channel(arc_config.clone()));

            tunnel.await;
            cc_channel.await;
        } else {
            if arc_config.use_remote_config.unwrap_or(false) {
                task::spawn(run_tcp_channel(arc_config.clone())).await;
            } else {
                task::spawn(run_udp_mode(arc_config.clone())).await;
            }
        }

    });
}
