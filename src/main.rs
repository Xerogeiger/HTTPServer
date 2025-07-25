use std::net::IpAddr;
use http::shared::HttpVersion::V11;
use crate::http::server::{dir_to_mappings, FileMapping};
use crate::http::shared::HttpVersion::V10;

mod http;
mod decode;
mod ssl;
mod rng;

fn main() {
    let mut server = V11.create_server(1234).unwrap();
    //Create an http 1.1 server on a new thread
    server.add_mappings(dir_to_mappings("./Site/static/", None).expect("Failed to create mappings")).expect("Failed to add mappings");
    server.add_mappings(dir_to_mappings("./Site/templates/", None).expect("Failed to create mappings")).expect("Failed to add mappings");
    server.start().expect("Failed to start server");

    //Create an http 1.0 client
    let client = V11.create_client(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 1234);
    match client {
        Ok(mut c) => {
            c.get("/index.html").expect("Failed to get");
        },
        Err(e) => eprintln!("Failed to create client: {}", e),
    }

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