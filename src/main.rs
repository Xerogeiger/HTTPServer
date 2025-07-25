use std::net::IpAddr;
use http::shared::HttpVersion::V11;
use crate::http::server::{dir_to_mappings, TlsConfig};
mod http;
mod decode;
mod ssl;

fn main() {
    let mut server = V11.create_server(1234).unwrap();
    //Create an http 1.1 server on a new thread
    server.add_mappings(dir_to_mappings("./Site/static/", None).expect("Failed to create mappings")).expect("Failed to add mappings");
    server.add_mappings(dir_to_mappings("./Site/templates/", None).expect("Failed to create mappings")).expect("Failed to add mappings");

    let cert = include_bytes!("../tests/test.cer").to_vec();
    server.enable_tls(TlsConfig { cert, key: vec![], ciphers: vec![] }).expect("Failed to enable TLS");

    server.start().expect("Failed to start server");

    loop {
        // Wait for user input to exit
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("Failed to read line");
        if input.trim() == "exit" {
            break;
        }
    }

    server.stop().expect("Failed to stop server");
}