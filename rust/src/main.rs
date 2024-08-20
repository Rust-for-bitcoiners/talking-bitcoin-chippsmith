#![allow(unused_imports)]
#![allow(dead_code)]


use dns_lookup::lookup_host;
use std::{
    fs::File,
    io::{self, Error, ErrorKind, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    time::SystemTime,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use bitcoin::{
    consensus::{deserialize_partial, encode::serialize_hex},
    Block,
};
use bitcoin::{
    consensus::{Decodable, Encodable},
    hashes::{sha256, sha256d, Hash},
};
use rand::seq::SliceRandom;
use rand::thread_rng;
use tokio::time::{timeout, Duration};

const PROTOCOL_VERSION: i32 = 70015;

// Define the fields
struct NetAddress {
    //time: u32, // not present in version message
    services: u64,
    ip: Ipv6Addr,
    port: u16,
}

// Define the fields
struct VersionMessage {
    version: i32,
    services: u64,
    timestamp: i64,
    addr_recv: NetAddress,
    addr_from: NetAddress,
    nonce: u64,
    user_agent: u8, //need to change to var_str
    start_height: i32,
    relay: bool,
}

const REGTEST_MAGIC: [u8; 4] = [250, 191, 181, 218];
const MAINNET_MAGIC: [u8; 4] = [249, 190, 180, 217];

fn serialize_version_msg(msg: &VersionMessage) -> Vec<u8> {
    //https://en.bitcoin.it/wiki/Protocol_documentation#version

    let mut version_message = Vec::<u8>::new();
    version_message.append(&mut msg.version.to_le_bytes().to_vec()); // add message version 4 bytes i32
    version_message.append(&mut msg.services.to_le_bytes().to_vec()); // add services 8 bytes u64
    version_message.append(&mut msg.timestamp.to_le_bytes().to_vec()); // add timestamp 8 byes i64
    version_message.append(&mut serialize_net_address(&msg.addr_recv));
    version_message.append(&mut serialize_net_address(&msg.addr_from));
    version_message.append(&mut msg.nonce.to_le_bytes().to_vec());
    version_message.append(&mut msg.user_agent.to_le_bytes().to_vec()); // user agent.  0x00 if string is 0 bytes long
    version_message.append(&mut msg.start_height.to_le_bytes().to_vec());


    if msg.relay == false {
        version_message.push(0)
    } else {
        version_message.push(1)
    }

     
    
    version_message
}

fn serialize_net_address(addr: &NetAddress) -> Vec<u8> {
    //https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
    let mut address = Vec::<u8>::new();
    //address.append(&mut addr.time.to_le_bytes().to_vec());
    address.append(&mut addr.services.to_le_bytes().to_vec());

    let ip = addr.ip; //network byte order(big endian) in docs
    for c in ip.octets() {
        address.push(c as u8);
    }

    address.append(&mut addr.port.to_be_bytes().to_vec()); //network byte order(big endian) in docs
    address
}

fn hex_to_bytes(hex_string: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    // refer [hex to bytes conversion](https://github.com/bitcoin-dev-project/rust-for-bitcoiners/blob/main/tutorials/de_se_rialization/hex_bytes_conversions.md)
    (0..hex_string.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_string[i..i + 2], 16))
        .collect()
}

fn request_block_message(hash: &str) -> Vec<u8> {
    //https://en.bitcoin.it/wiki/Protocol_documentation#getdata
    //todo!("Given a block hash return the block message inventory for getdata command")
    // one inv vector

    let mut request_block_message = Vec::<u8>::new();
    request_block_message.push(1);
    request_block_message.append(&mut hash.as_bytes().to_vec());
    request_block_message
}

fn create_message(command: &str, payload: &[u8]) -> Vec<u8> {
    // https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
    // check endianess
    let mut message = Vec::<u8>::new();
    message.append(&mut REGTEST_MAGIC.to_vec()); // Add network magic
    message.append(&mut command.as_bytes().to_vec()); //add command after converting to bytes
    message.append(&mut [0x00, 0x00, 0x00, 0x00, 0x00].to_vec()); // pad version command to 12 bytes
    let length: u32 = payload.len() as u32;
    message.append(&mut length.to_le_bytes().to_vec()); // add length of payload
    message.append(&mut (&sha256::Hash::hash(payload)[0..4]).to_vec()); // add checksum
    message.append(&mut payload.to_vec()); // add payload

    message //return message
}

fn is_verack(data: &[u8]) -> bool {
    //todo!("Check whether these bytes starts with a verack message")
    let message_type = &data[0..12];
    if message_type == String::from("verack000000").as_bytes() {
        return true;
    } else {
        return false;
    }
}

fn randomize_slice<'a>(input: &'a [&'a str]) -> Vec<&'a str> {
    let mut rng = thread_rng();
    let mut vec = input.to_vec(); // Convert slice to vector
    vec.shuffle(&mut rng); // Shuffle the vector
    vec // Return the vector (or convert to a slice if needed)
}

async fn get_valid_ip() -> Result<(TcpStream, IpAddr), String> {
    const DNS_SEEDS: [&str; 4] = [
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr.org",
        "seed.bitcoinstats.com",
    ];
    //todo!("Initially test with regtest with debug=net option");
    //todo!("then test with your local full node");
    //todo!("Then choose an ip from randomly iterating over DNS_SEEDS");

    let stream = TcpStream::connect("127.0.0.1:8332").await.unwrap();
    let localhost_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    Ok((stream, localhost_v4))
}

// bitcoin messages did not end with any special character
// So this function will keep reading from the stream until the read results in an error or 0
async fn till_read_succeeds(stream: &mut TcpStream, buffer: &mut Vec<u8>) {
    println!("reading the stream");
    loop {
        let mut t = [0; 1024];
        if let Ok(n) = stream.read(&mut t).await {
            if n == 0 {
                return;
            }
            buffer.extend(t);
            tracing::info!("read {n} bytes");
        } else {
            tracing::error!("Error in read");
            return;
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .compact()
        // Display source code file paths
        .with_file(true)
        // Display source code line numbers
        .with_line_number(true)
        // Display the thread ID an event was recorded on
        .with_thread_ids(false)
        // Don't display the event's target (module path)
        .with_target(false)
        // Build the subscriber
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let (mut stream, ip) = get_valid_ip().await.unwrap();

    let ip6 = match ip {
        IpAddr::V4(addr) => addr.to_ipv6_mapped(),
        IpAddr::V6(addr) => addr,
    };

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Construct and send the version message
    let version_msg = VersionMessage {
        version: PROTOCOL_VERSION,
        services: 1,
        timestamp: timestamp,
        addr_recv: NetAddress {
            services: 1,
            ip: ip6,
            port: 8332,
        },
        addr_from: NetAddress {
            services: 1,
            ip: ip6, // dummy bytes, can be ignored
            port: 8332,
        },
        nonce: 1,
        user_agent: 0x00,
        start_height: 0,
        relay: true,
    };

    let binding = serialize_version_msg(&version_msg);
    let payload = binding.as_slice();

    let message = create_message(&String::from("version"), payload);

    println!("{:?}", hex::encode(&message));

    stream.write_all(message.as_slice()).await?;

    let mut buffer = Vec::<u8>::new();
    get_block_payload(&buffer);

    get_data_with_timeout(&mut stream, &mut buffer).await;

    //connect but dont get any messages back.

    //tracing::info!(buffer);
    Ok(())
}

// A bitcoin peer will be continuously sending you messages
// At some point you need to pause reading them and process the messages
// So this function reads till a specified timeout
async fn get_data_with_timeout(mut stream: &mut TcpStream, mut buffer: &mut Vec<u8>) {
    println!("getting data");
    let timeout_duration = Duration::from_secs(10);
    let _ = timeout(
        timeout_duration,
        till_read_succeeds(&mut stream, &mut buffer),
    )
    .await;
}

fn get_block_payload(buffer: &[u8]) -> &[u8] {
    //todo!("The bitcoin node will keep sending you messages like ping, inv etc.,");
    //todo!("One of them will be your required block message");
    //todo!("How will you identify that?")

    if buffer == b"block0000000" {
        println!("hello")
        //let block = Block::consensus_decode(buffer).unwrap();
    }
    buffer
}

fn starts_with_magic(buffer: &[u8]) -> bool {
    let magic = &buffer[0..4];
    if magic == MAINNET_MAGIC || magic == REGTEST_MAGIC {
        return true;
    } else {
        return false;
    }
}
