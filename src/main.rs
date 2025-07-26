use HTTPServer::http::server::{dir_to_mappings, TlsConfig};
use HTTPServer::http::shared::HttpVersion::V11;
use std::net::IpAddr;

fn main() {
    let mut server = V11.create_server(1234).unwrap();
    //Create an http 1.1 server on a new thread
    server
        .add_mappings(dir_to_mappings("./Site/static/", None).expect("Failed to create mappings"))
        .expect("Failed to add mappings");
    server
        .add_mappings(
            dir_to_mappings("./Site/templates/", None).expect("Failed to create mappings"),
        )
        .expect("Failed to add mappings");

    let cert =
        HTTPServer::ssl::rsa::pem_to_der(include_str!("../tests/test_cert.pem")).expect("pem to der");
    let key = include_bytes!("../tests/test_key.pem").to_vec();
    server
        .enable_tls(TlsConfig {
            cert,
            key,
            ciphers: vec![],
        })
        .expect("Failed to enable TLS");

    server.start().expect("Failed to start server");

    loop {
        // Wait for user input to exit
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");
        if input.trim() == "exit" {
            break;
        }
    }

    server.stop().expect("Failed to stop server");
}
