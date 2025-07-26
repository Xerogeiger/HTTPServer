use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Stdio};

use HTTPServer::http::server::{HttpMapping, HttpServer, TlsConfig};
use HTTPServer::http::shared::{ContentType, HttpRequest, HttpResponse, RequestMethod, StatusCode};
use HTTPServer::http::v11::http_v11::HttpV11Server;

struct HelloMapping;

impl HttpMapping for HelloMapping {
    fn matches_url(&self, url: &str) -> bool {
        url == "/hello"
    }

    fn matches_method(&self, method: &RequestMethod) -> bool {
        *method == RequestMethod::Get
    }

    fn get_content_type(&self) -> ContentType {
        ContentType::TextPlain
    }

    fn handle_request(&self, _req: &HttpRequest) -> Result<HttpResponse, String> {
        Ok(HttpResponse::from_status(
            StatusCode::Ok,
            vec![("Content-Type".into(), ContentType::TextPlain.to_string())],
            Some(b"hi".to_vec()),
        ))
    }
}

#[test]
fn openssl_https_request() {
    // Bind to port 0 to obtain an available port
    let temp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = temp.local_addr().unwrap().port();
    drop(temp);

    let mut server = HttpV11Server::new(port, IpAddr::V4(Ipv4Addr::LOCALHOST));
    server.add_mapping(Box::new(HelloMapping)).unwrap();
    server
        .enable_tls(TlsConfig {
            cert: HTTPServer::ssl::rsa::pem_to_der(include_str!("test_cert.pem"))
                .unwrap(),
            key: include_bytes!("test_key.pem").to_vec(),
            ciphers: vec![],
        })
        .expect("enable tls");
    server.start().unwrap();

    let mut child = Command::new("openssl")
        .arg("s_client")
        .arg("-legacy_renegotiation")
        .arg("-sigalgs")
        .arg("rsa_pkcs1_sha256")
        .arg("-cipher")
        .arg("ALL:@SECLEVEL=0")
        .arg("-connect")
        .arg(format!("127.0.0.1:{}", port))
        .arg("-servername")
        .arg("localhost")
        .arg("-quiet")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn openssl");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin
            .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
    }

    let output = child.wait_with_output().expect("wait on openssl");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("HTTP/1.1 200 OK"), "{}", stdout);

    server.stop().unwrap();
}
