use std::io;
use std::io::{BufRead, BufReader, Error, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use crate::http::server::{HttpMapping, ServerStatus};
use crate::http::server::HttpServer;
use crate::http::server::{HttpServerClient};
use crate::http::shared::{write_chunked, HttpRequest, HttpResponse, HttpStatus, RequestMethod, StatusCode};
use crate::http::shared::RequestMethod::Get;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use crate::decode::gz_decoder::GzDecoder;
use crate::http::client::HttpClient;
use crate::http::shared::ContentType::TextPlain;

pub struct HttpV11Client {
    host: IpAddr,
    port: u16,
    default_headers: Vec<(String, String)>,
    stream: Option<TcpStream>,
    keep_alive: bool,
}

impl HttpV11Client {
    /// Create a new client; connection is established lazily.
    pub fn new(host: IpAddr, port: u16) -> Self {
        Self {
            host,
            port,
            default_headers: Vec::new(),
            stream: None,
            keep_alive: true,
        }
    }

    /// Ensure we have a live connection (or reconnect).
    fn ensure_connection(&mut self) -> io::Result<&mut TcpStream> {
        match &self.stream {
            Some(_) if self.keep_alive => Ok(self.stream.as_mut().unwrap()),
            _ => {
                let addr = format!("{}:{}", self.host, self.port);
                let stream = TcpStream::connect(addr)?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                self.stream = Some(stream);
                Ok(self.stream.as_mut().unwrap())
            }
        }
    }

    /// Read a chunked transfer-encoded body into a Vec<u8>.
    fn read_chunked_body(reader: &mut BufReader<&TcpStream>) -> io::Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            // Read the chunk-size line
            let mut size_line = String::new();
            reader.read_line(&mut size_line)?;
            let size = usize::from_str_radix(size_line.trim(), 16)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if size == 0 {
                // Consume trailing CRLF
                let mut crlf = [0; 2];
                reader.read_exact(&mut crlf)?;
                break;
            }
            let mut chunk = vec![0; size];
            reader.read_exact(&mut chunk)?;
            body.extend_from_slice(&chunk);
            // consume CRLF
            let mut crlf = [0; 2];
            reader.read_exact(&mut crlf)?;
        }
        Ok(body)
    }
}

impl HttpClient for HttpV11Client {
    fn set_headers(&mut self, headers: Vec<(String, String)>) {
        self.default_headers = headers;
    }

    fn get_headers(&self) -> Vec<(String, String)> {
        self.default_headers.clone()
    }

    fn set_host(&mut self, host: IpAddr) {
        self.host = host;
        self.stream = None; // reset connection
    }

    fn get_host(&self) -> IpAddr {
        self.host
    }

    fn set_port(&mut self, port: u16) {
        self.port = port;
        self.stream = None;
    }

    fn get_port(&self) -> u16 {
        self.port
    }

    fn send_request(&mut self, req: HttpRequest) -> Result<HttpResponse, String> {
        // Mutable borrow to manage connection & write
        let mut_self = self.ensure_connection().map_err(|e| e.to_string())?;
        let mut headers = self.default_headers.clone();
        headers.push(("Host".into(), format!("{}:{}", self.host, self.port)));
        headers.push(("Connection".into(), "keep-alive".into()));
        headers.push(("User-Agent".into(), "RustHttpClient/1.1".into()));

        let mut request = req.clone();
        request.headers = headers;

        // Build request bytes
        let mut raw = format!("{} {} HTTP/1.1\r\n", request.method, request.path);
        for (k, v) in &request.headers {
            raw.push_str(&format!("{}: {}\r\n", k, v));
        }
        raw.push_str("\r\n");
        if let Some(body) = request.body {
            raw.push_str(&body);
        }

        // Send over the connection
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream: TcpStream = TcpStream::connect(addr).expect("Failed to connect");

        stream.write_all(raw.as_bytes()).map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;

        // Read and parse response
        self.receive_response(&stream)
    }

    fn receive_response(&self, stream: &TcpStream) -> Result<HttpResponse, String> {
        let mut reader = BufReader::new(stream);
        // 1) Status line
        let mut status_line = String::new();
        reader.read_line(&mut status_line).map_err(|e| e.to_string())?;
        let mut parts = status_line.trim_end().splitn(3, ' ');
        let _version = parts.next().ok_or("Malformed status line")?;
        let code: u16 = parts
            .next()
            .ok_or("No status code")?
            .parse()
            .map_err(|_| "Invalid status code")?;
        let reason = parts.next().unwrap_or("").to_string();

        // 2) Headers with folding
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut last_key: Option<String> = None;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).map_err(|e| e.to_string())?;
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if trimmed.starts_with(' ') || trimmed.starts_with('\t') {
                // continuation
                if let Some(k) = &last_key {
                    if let Some((_, v)) = headers.last_mut() {
                        v.push(' ');
                        v.push_str(trimmed.trim());
                    }
                }
            } else if let Some((k, v)) = trimmed.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                headers.push((key.clone(), val));
                last_key = Some(key);
            }
        }

        // 3) Body
        let mut body_bytes = Vec::new();
        let is_chunked = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") &&
                v.eq_ignore_ascii_case("chunked"));
        let is_gzip = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-encoding") &&
                v.eq_ignore_ascii_case("gzip"));
        if is_chunked {
            body_bytes = HttpV11Client::read_chunked_body(&mut reader).map_err(|e| e.to_string())?;
        } else if let Some((_, v)) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
            let len: usize = v.parse().map_err(|_| "Invalid Content-Length")?;
            let mut buf = vec![0; len];
            reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
            body_bytes = buf;
        } else {
            // read until EOF
            reader.read_to_end(&mut body_bytes).map_err(|e| e.to_string())?;
        }

        // 4) Handle gzip
        let mut final_body = body_bytes;
        if is_gzip {
            let d = GzDecoder::load(&final_body[..]);
            let decompressed = d.unwrap().decompress();
            final_body = decompressed.unwrap();
        }

        let body_str = String::from_utf8_lossy(&final_body).to_string();
        Ok(HttpResponse::new(HttpStatus::new(code, reason), headers, Some(body_str)))
    }
}

struct HttpV11ServerClient {
    ip_address: IpAddr,
    stream: TcpStream,
    port: u16,
    connected: bool,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Clone for HttpV11ServerClient {
    fn clone(&self) -> Self {
        HttpV11ServerClient {
            ip_address: self.ip_address,
            stream: self.stream.try_clone().expect("Failed to clone stream"),
            port: self.port,
            connected: self.connected,
            thread: None,
        }
    }
}

impl HttpServerClient for HttpV11ServerClient {
    fn receive_request(&mut self) -> Result<Option<HttpRequest>, String> {
        // Implementation for receiving an HTTP request
        if !self.connected {
            return Err("Client is not connected".to_string());
        }

        let mut buffer = [0; 1024];
        match self.stream.read(&mut buffer) {
            Ok(size) if size > 0 => {
                let request_text = String::from_utf8_lossy(&buffer[..size]);
                let mut lines = request_text.lines();
                let request_line = lines.next().ok_or("Empty request line")?;
                let parts: Vec<&str> = request_line.split_whitespace().collect();
                if parts.len() < 2 {
                    return Err("Invalid request line".to_string());
                }
                let method = parts[0].to_string();
                let path = parts[1].to_string();
                let headers: Vec<(String, String)> = lines.clone()
                    .filter_map(|line| {
                        let mut header_parts = line.splitn(2, ':');
                        if let (Some(key), Some(value)) = (header_parts.next(), header_parts.next()) {
                            Some((key.trim().to_string(), value.trim().to_string()))
                        } else {
                            None
                        }
                    })
                    .collect();

                if(headers.is_empty()) {
                    return Err("No headers found".to_string());
                }

                let content_length = headers.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
                    .and_then(|(_, v)| v.parse::<usize>().ok())
                    .unwrap_or(0);

                if content_length == 0 {
                    // If content length is 0, there is no body
                    return Ok(Some(HttpRequest {
                        method: RequestMethod::from_str(&method).unwrap_or(Get),
                        path,
                        headers,
                        body: None,
                    }));
                }

                let body = if lines.clone().any(|line| !line.is_empty()) {
                    // If there's an empty line, the body starts after it
                    let body_lines: Vec<String> = lines.skip_while(|line| line.is_empty()).map(String::from).collect();
                    if body_lines.is_empty() {
                        None
                    } else {
                        Some(body_lines.join("\n"))
                    }
                } else {
                    None
                };
                println!("Received request: {} {} with headers: {:?}", method, path, headers);

                Ok(Some(HttpRequest {
                    method: RequestMethod::from_str(&method).unwrap_or(Get),
                    path,
                    headers,
                    body,
                }))
            }
            Ok(_) => Err("No data received".to_string()),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(None)
                }
                Err(format!("Failed to read request: {}", e))
            }
        }
    }

    fn send_response(&mut self, response: HttpResponse) -> Result<(), String> {
        // Implementation for sending an HTTP response
        if !self.connected {
            return Err("Client is not connected".to_string());
        }

        let mut r = response.clone();

        r.headers.push(("Connection".to_string(), "keep-alive".to_string()));

        let chunked = !r.body.is_none() && r.body.clone().unwrap_or_default().len() > 1024; // Arbitrary threshold for chunked encoding

        if chunked {
            r.headers.push(("Transfer-Encoding".to_string(), "chunked".to_string()));
        } else {
            let content_length = r.body.as_ref().map_or(0, |b| b.len());
            r.headers.push(("Content-Length".to_string(), content_length.to_string()));
        }

        let status_line = format!("HTTP/1.1 {} {}\r\n", r.status.code, r.status.text);
        let mut headers = String::new();
        for (key, value) in &r.headers {
            headers.push_str(&format!("{}: {}\r\n", key, value));
        }
        headers.push_str("\r\n"); // End of headers

        let response_text: String;

        if(chunked) {
            response_text = format!("{}{}", status_line, headers);
            self.stream.write_all(response_text.as_bytes()).map_err(|e| format!("Failed to write chunked response: {}", e))?;
            let body = r.body.clone().unwrap_or_default();
            write_chunked(&mut self.stream, body.as_ref()).map_err(|e| format!("Failed to write chunked response: {}", e))?;
        } else {
            let body = r.body.clone().unwrap_or_default();
            response_text = format!("{}{}{}", status_line, headers, body.to_string());
            self.stream.write_all(response_text.as_bytes()).map_err(|e| format!("Failed to write response: {}", e))?;
        }

        println!(
            "Sending response: {}",
            r
        );

        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), String> {
        // Implementation for disconnecting the client
        if !self.connected {
            return Err("Client is not connected".to_string());
        }
        // Simulate disconnecting
        if let Err(e) = self.stream.shutdown(std::net::Shutdown::Both) {
            return Err(format!("Failed to disconnect: {}", e));
        }
        println!("Client disconnected from {}:{}", self.ip_address, self.port);
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> Result<bool, String> {
        Ok(self.connected)
    }

    fn new(ip_address: IpAddr, port: u16, stream: TcpStream) -> Self {
        HttpV11ServerClient {
            ip_address,
            port,
            connected: false,
            stream,
            thread: None,
        }
    }

    fn get_ip_address(&self) -> Result<IpAddr, String> {
        Ok(self.ip_address)
    }

    fn get_port(&self) -> Result<u16, String> {
        Ok(self.port)
    }
}

impl HttpV11ServerClient {
    fn join(&mut self) -> Result<(), String> {
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| "Failed to join client thread".to_string())?;
        }
        Ok(())
    }
}
pub struct HttpV11Server {
    port: u16,
    status: Arc<Mutex<ServerStatus>>,
    clients: Arc<Mutex<Vec<Arc<Mutex<HttpV11ServerClient>>>>>,
    address: IpAddr,
    tcp_listener: Option<TcpListener>,
    server_thread: Option<std::thread::JoinHandle<()>>,
    mappings: Arc<Mutex<Vec<Box<dyn HttpMapping + Send + Sync>>>>,
}

impl HttpServer for HttpV11Server {
    fn start(&mut self) -> Result<(), String> {
        if *self.status.lock().unwrap() == ServerStatus::Running {
            return Err("Server is already running".to_string());
        }

        *self.status.lock().unwrap() = ServerStatus::Starting;
        // Implementation for starting the HTTP/1.1 server
        println!("Starting HTTP/1.1 server on {}:{}", self.address, self.port);

        // Bind to the specified address and port
        let tcp_listener = TcpListener::bind((self.address, self.port))
            .map_err(|e| format!("Failed to bind to {}: {}: {}", self.address, self.port, e))?;
        self.tcp_listener = Some(tcp_listener.try_clone().expect("Expected valid tcp listener"));
        self.clients.lock().unwrap().clear(); // Clear any existing clients

        *self.status.lock().unwrap() = ServerStatus::Running;

        //Start listening for incoming connections on a separate thread
        let listener = tcp_listener.try_clone().map_err(|e| e.to_string())?;
        let status   = Arc::clone(&self.status);
        let mappings = Arc::clone(&self.mappings);
        let clients  = Arc::clone(&self.clients);
        // 2) Now spawn your listener thread without touching `self` anymore:
        self.server_thread = Some(std::thread::spawn(move || {
            loop {
                // We only refer to `status` (the Arc), never `self`:
                if *status.lock().unwrap() != ServerStatus::Running {
                    println!("Stopping listener thread.");
                    break;
                }

                match listener.accept() {
                    Ok((stream, addr)) => {
                        println!("Accepted {}", addr);
                        // Create a new client
                        let client = create_client(stream).unwrap();
                        client.lock().unwrap().thread = handle_client(client.clone(), mappings.clone()).expect("Failed to handle client");
                        // Add the client to the list of clients
                        clients.lock().unwrap().push(client.clone());
                    }

                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // no pending connections
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        continue;
                    }
                    Err(e) => {
                        eprintln!("accept error: {}", e);
                    }
                }
            }
        }));
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        // 1) Signal to the listener thread to exit:
        *self.status.lock().unwrap() = ServerStatus::Stopped;

        // 2) Wait for the listener thread to finish:
        if let Some(server_thread) = self.server_thread.take() {
            server_thread
                .join()
                .map_err(|_| "Failed to join server thread".to_string())?;
        }
        println!("HTTP/1.1 listener thread stopped.");

        // 3) Drain and join *all* of the client‐handler threads in one go:
        {
            let mut clients = self.clients.lock().unwrap();
            for client in clients.drain(..) {
                if let Err(err) = client.lock().unwrap().join() {
                    eprintln!("Failed to join client thread: {:?}", err);
                }
            }
        }

        println!("All client threads joined. Server fully stopped.");
        Ok(())
    }

    fn get_port(&self) -> Result<u16, String> {
        Ok(self.port)
    }

    fn status(&self) -> Result<ServerStatus, String> {
        Ok(self.status.lock().unwrap().clone())
    }

    fn is_running(&self) -> Result<bool, String> {
        Ok(self.status.lock().unwrap().clone() == ServerStatus::Running)
    }

    fn join(&mut self) -> Result<(), String> {
        if let Some(server_thread) = self.server_thread.take() {
            server_thread
                .join()
                .map_err(|_| "Failed to join server thread".to_string())?;
        }
        Ok(())
    }

    fn add_mapping(&mut self, mapping: Box<dyn HttpMapping + Send + Sync>) -> Result<(), String> {
        let mut mappings = self.mappings.lock().unwrap();
        mappings.push(mapping);
        Ok(())
    }
}

impl HttpV11Server {
    pub fn new(port: u16, address: IpAddr) -> Self {
        HttpV11Server {
            port,
            status: Arc::new(Mutex::new(ServerStatus::Stopped)),
            mappings: Arc::new(Mutex::new(Vec::new())),
            clients: Arc::new(Mutex::new(Vec::new())),
            address,
            tcp_listener: None,
            server_thread: None,
        }
    }
}

fn validate_request(request: &HttpRequest) -> Result<(), String> {
    // 1) Request method must be valid
    match request.method {
        RequestMethod::Get
        | RequestMethod::Head
        | RequestMethod::Post
        | RequestMethod::Put
        | RequestMethod::Delete
        | RequestMethod::Options
        | RequestMethod::Trace
        | RequestMethod::Connect => {}
        _ => return Err(format!("Unsupported method: {}", request.method)),
    }

    // 2) Request‑target must be non‑empty; for origin‑form it should start with '/'
    if request.path.is_empty() {
        return Err("Request path cannot be empty".into());
    } else if !request.path.starts_with('/') && request.method != RequestMethod::Connect {
        // CONNECT uses authority‑form, OPTIONS can use "*"
        return Err("Invalid request‑target format".into());
    }

    // 3) Host header is mandatory in HTTP/1.1
    if !request
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        return Err("Missing required `Host` header".into());
    }

    // 4) If there is a message body, require either Content-Length or Transfer-Encoding
    if request.body.is_some() {
        let has_len = request
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
        let has_te = request
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
        if !has_len && !has_te {
            return Err(
                "Requests with a body must include `Content-Length` or `Transfer-Encoding`"
                    .into(),
            );
        }
    }

    // 5) Content-Type is only required when you actually expect a body with semantic content
    if matches!(
        request.method,
        RequestMethod::Post | RequestMethod::Put | RequestMethod::Patch
    ) && !request
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
        return Err("POST/PUT requests should include a `Content-Type` header".into());
    }

    // 6) Validate header syntax: token characters for names, no raw control chars in values
    for (name, value) in &request.headers {
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-!#$%&'*+.^_`|~".contains(c)) {
            return Err(format!("Invalid header name token: `{}`", name));
        }
        if value.bytes().any(|b| b == b'\r' || b == b'\n') {
            return Err(format!("Illegal control char in header `{}` value", name));
        }
    }

    Ok(())
}

fn create_client(tcp_stream: TcpStream) -> Result<Arc<Mutex<HttpV11ServerClient>>, String> {
    let client = Arc::new(Mutex::new(HttpV11ServerClient::new(tcp_stream.local_addr().unwrap().ip(), tcp_stream.local_addr().unwrap().port(), tcp_stream)));
    client.lock().unwrap().connected = true;
    Ok(client)
}

fn handle_client(client: Arc<Mutex<HttpV11ServerClient>>, mappings: Arc<Mutex<Vec<Box<dyn HttpMapping + Send + Sync>>>>) -> Result<Option<std::thread::JoinHandle<()>>, Error> {
    if(client.lock().unwrap().is_connected().unwrap_or(false) == false) {
        return Ok(None); // Client is not connected, return None
    }
    let handle = std::thread::spawn(move || {
        let mut c = client.lock().unwrap();
        loop {
            if !c.is_connected().unwrap_or(false) {
                break;
            }
            match c.receive_request() {
                Ok(request) => {
                    if request.is_none() {
                        // No request received, continue to next iteration
                        continue;
                    }

                    println!("Received request: {}", request.clone().expect("Request should not be None"));
                    // Validate the request
                    if let Err(e) = validate_request(&request.clone().expect("Request should not be None")) {
                        eprintln!("Invalid request: {}", e);
                        let err = HttpResponse::from_status(
                            StatusCode::BadRequest,
                            vec![("Content-Type".into(), TextPlain.to_string())],
                            Some(e),
                        );
                        let _ = c.send_response(err);
                        continue; // Skip to the next iteration
                    }

                    let request = request.expect("Request should not be None");
                    let keep_alive = request.headers.iter()
                        .any(|(k, v)| k.eq_ignore_ascii_case("Connection") && v.eq_ignore_ascii_case("keep-alive"));
                    let mut handled = false;

                    for mapping in mappings.lock().unwrap().iter() {
                        if mapping.matches_url(&request.path)
                            && mapping.matches_method(&request.method) {
                            handled = true;
                            match mapping.handle_request(&request) {
                                Ok(resp) => {
                                    if let Err(e) = c.send_response(resp) {
                                        eprintln!("Sending Response: {}", e);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("handler error: {}", e);
                                    let err = HttpResponse::from_status(
                                        StatusCode::InternalServerError,
                                        vec![("Content-Type".into(), TextPlain.to_string())],
                                        Some("Internal Server Error".into()),
                                    );
                                    let _ = c.send_response(err);
                                }
                            }
                        }
                    }

                    if !handled {
                        let not_found = HttpResponse::from_status(
                            StatusCode::NotFound,
                            vec![("Content-Type".into(), TextPlain.to_string())],
                            Some("Not Found".into()),
                        );
                        let _ = c.send_response(not_found);
                    }

                    println!("keep_alive: {}", keep_alive);

                    if !keep_alive {
                        c.disconnect().unwrap_or_else(|e| eprintln!("disconnect error: {}", e));
                        break; // Exit the loop if not keep-alive
                    }
                }
                Err(e) => {
                    eprintln!("receive_request error: {}", e);
                    let err = HttpResponse::from_status(
                        StatusCode::InternalServerError,
                        vec![("Content-Type".into(), TextPlain.to_string())],
                        Some("Internal Server Error".into()),
                    );
                    let _ = c.send_response(err);
                    break; // Exit the loop on error
                }
            }
        }

        println!("Server Client {} disconnected", c.ip_address);
    });

    // Return the thread handle
    if handle.is_finished() {
        return Err(Error::new(std::io::ErrorKind::Other, "Client thread finished immediately"));
    }

    // Thread handle is returned, or `None` if the client is not connected
    Ok(Some(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_request_success() {
        let req = HttpRequest::new(
            RequestMethod::Get,
            "/".into(),
            vec![("Host".into(), "example.com".into())],
            None,
        );
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn test_validate_request_errors() {
        // Missing host
        let req = HttpRequest::new(RequestMethod::Get, "/".into(), vec![], None);
        assert!(validate_request(&req).is_err());

        // Body without length
        let req = HttpRequest::new(
            RequestMethod::Post,
            "/".into(),
            vec![("Host".into(), "a".into()), ("Content-Type".into(), "text/plain".into())],
            Some("body".into()),
        );
        assert!(validate_request(&req).is_err());

        // Invalid header name
        let req = HttpRequest::new(
            RequestMethod::Get,
            "/".into(),
            vec![("Bad Header".into(), "v".into()), ("Host".into(), "a".into())],
            None,
        );
        assert!(validate_request(&req).is_err());
    }
}