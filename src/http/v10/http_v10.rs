use crate::http::client::HttpClient;
use crate::http::shared::{HttpRequest, HttpResponse, HttpStatus};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream};

pub struct HttpV10Client {
    // Fields for the HTTP/1.0 client can be defined here
    host: IpAddr,
    port: u16,
    headers: Vec<(String, String)>
}

impl HttpV10Client {
    pub fn new(host: IpAddr, port: u16) -> Self {
        HttpV10Client {
            host,
            port,
            headers: vec![],
        }
    }
}

impl HttpClient for HttpV10Client {
    fn set_headers(&mut self, headers: Vec<(String, String)>) {
        self.headers = headers;
    }

    fn get_headers(&self) -> Vec<(String, String)> {
        self.headers.clone()
    }

    fn set_host(&mut self, host: IpAddr) {
        self.host = host;
    }

    fn get_host(&self) -> IpAddr {
        self.host
    }

    fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    fn get_port(&self) -> u16 {
        self.port
    }

    fn send_request(&mut self, req: HttpRequest) -> Result<HttpResponse, String> {
        let mut req = req.clone();
        req.headers.push(("Host".to_string(), format!("{}:{}", self.host, self.port)));
        req.headers.push(("Connection".to_string(), "close".to_string()));
        req.headers.push(("User-Agent".to_string(), "Rust HTTP Client/1.0".to_string()));
        req.headers.push(("Accept".to_string(), "*/*".to_string()));
        req.headers.push(("Accept-Language".to_string(), "en-US,en;q=0.5".to_string()));
        req.headers.push(("Accept-Encoding".to_string(), "gzip, deflate".to_string()));
        req.headers.push(("Content-Length".to_string(),
            req.body.as_ref().map_or("0".to_string(), |b| b.len().to_string())));

        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = TcpStream::connect(&addr)
            .map_err(|e| format!("Connection error: {}", e))?;

        // Send it
        stream
            .write_all(&*req.get_bytes())
            .map_err(|e| format!("Write error: {}", e))?;

        // Read the full response
        self.receive_response(&mut stream)
    }

    fn receive_response(&self, stream: &TcpStream) -> Result<HttpResponse, String> {
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).map_err(|e| format!("Failed to read status line: {}", e))?;

        let status_parts: Vec<&str> = status_line.trim_end().split_whitespace().collect();
        if status_parts.len() < 2 {
            return Err("Invalid status line".to_string());
        }

        let status_code: u16 = status_parts[1]
            .parse()
            .map_err(|_| "Invalid status code".to_string())?;
        let status_text = status_parts.get(2).map_or("OK", |s| *s).to_string();

        // Read headers
        let mut headers = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            reader.read_line(&mut line).map_err(|e| format!("Failed to read header line: {}", e))?;
            let line_trimmed = line.trim_end();
            if line_trimmed.is_empty() {
                break;
            }
            if let Some((k, v)) = line_trimmed.split_once(": ") {
                headers.push((k.to_string(), v.to_string()));
            }
        }

        // Determine content length
        let content_length = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
            .and_then(|(_, v)| v.parse::<usize>().ok())
            .unwrap_or(0);

        if content_length == 0 {
            println!("Finished reading response with no body.");

            return Ok(HttpResponse {
                status: HttpStatus::new(status_code, status_text),
                headers,
                body: None,
            });
        }

        println!("Finished reading response with body.");

        // Read body
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).map_err(|e| format!("Failed to read body: {}", e))?;

        Ok(HttpResponse {
            status: HttpStatus::new(status_code, status_text),
            headers,
            body: Some(String::from_utf8_lossy(&body).to_string()),
        })
    }
}