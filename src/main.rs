use std::net::IpAddr;
use http::shared::HttpVersion::V11;
use crate::http::shared::HttpVersion::V10;

mod http;

fn main() {
    let mut server = V11.create_server(1234).unwrap();
    //Create an http 1.1 server on a new thread
    server.start().expect("Failed to start server");

    //Create an http 1.0 client
    let client = V10.create_client(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 1234);
    match client {
        Ok(c) => {
            match c.get("/") {
                Ok(response) => println!("Response: {}", response),
                Err(e) => eprintln!("Failed to get response: {}", e),
            }
        },
        Err(e) => eprintln!("Failed to create client: {}", e),
    }

    // Wait for the server thread to finish
    // server.stop().expect("Failed to stop server");
}