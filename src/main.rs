use std::net::IpAddr;
use http::shared::HttpVersion::V11;
use crate::http::server::FileMapping;
use crate::http::shared::HttpVersion::V10;

mod http;
mod decode;

fn main() {
    let mut server = V11.create_server(1234).unwrap();
    //Create an http 1.1 server on a new thread
    server.add_mapping(Box::new(FileMapping::new(
        "/".to_string(),
        http::shared::RequestMethod::Get,
        http::shared::ContentType::TextHtml,
        "index.html".to_string()
    ))).expect("Failed to add mapping");
    server.start().expect("Failed to start server");

    //Create an http 1.0 client
    let client = V10.create_client(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 1234);
    match client {
        Ok(mut c) => {
            c.get("/").expect("Failed to get");
        },
        Err(e) => eprintln!("Failed to create client: {}", e),
    }

    // Wait for the server thread to finish
    server.join().expect("Server thread panicked");
}