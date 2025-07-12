use crate::http::client::HttpClient;
use crate::http::shared::{HttpRequest, HttpResponse, HttpStatus};
use std::io::{Read, Write};
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

    fn send_request(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = TcpStream::connect(&addr)
            .map_err(|e| format!("Connection error: {}", e))?;

        // Build the request line + headers
        let mut request_text = format!(
            "{} {} HTTP/1.0\r\nHost: {}\r\n",
            req.method, req.path, self.host
        );
        for (k, v) in self.headers.iter().chain(req.headers.iter()) {
            request_text.push_str(&format!("{}: {}\r\n", k, v));
        }
        request_text.push_str("\r\n"); // end of headers

        // Add body if present
        if let Some(body) = req.body {
            request_text.push_str(&body);
        }

        // Send it
        stream
            .write_all(request_text.as_bytes())
            .map_err(|e| format!("Write error: {}", e))?;

        // Read the full response
        let mut resp_buf = String::new();
        stream
            .read_to_string(&mut resp_buf)
            .map_err(|e| format!("Read error: {}", e))?;

        // Simple parse: split headers/body on "\r\n\r\n"
        let parts: Vec<&str> = resp_buf.splitn(2, "\r\n\r\n").collect();
        let header_lines: Vec<&str> = parts[0].lines().collect();
        let status_line = header_lines
            .get(0)
            .ok_or("Missing status line")?
            .to_string();

        let status_parts: Vec<&str> = status_line.split_whitespace().collect();
        if status_parts.len() < 2 {
            return Err("Invalid status line".to_string());
        }
        let status_code: u16 = status_parts[1]
            .parse()
            .map_err(|_| "Invalid status code".to_string())?;
        if status_code < 100 || status_code >= 600 {
            return Err("Status code out of range".to_string());
        }

        let status_text = status_parts.get(2).map_or_else(
            || "OK".to_string(), // Default to "OK" if no reason phrase is provided
            |s| s.to_string()
        );

        let mut headers = Vec::new();
        for line in header_lines.iter().skip(1) {
            if let Some((k, v)) = line.split_once(": ") {
                headers.push((k.to_string(), v.to_string()));
            }
        }

        let body = if parts.len() > 1 {
            parts[1].to_string()
        } else {
            String::new()
        };

        Ok(HttpResponse {
            status: HttpStatus::new(status_code, status_text),
            headers,
            body: Some(body),
        })
    }
}