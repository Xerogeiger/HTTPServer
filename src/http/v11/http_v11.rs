use std::io::{Error, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use crate::http::server::{HttpMapping, ServerStatus};
use crate::http::server::HttpServer;
use crate::http::server::{HttpServerClient};
use crate::http::shared::{HttpRequest, HttpResponse, RequestMethod, StatusCode};
use crate::http::shared::RequestMethod::Get;
use std::sync::{Arc, Mutex};
use crate::http::shared::ContentType::TextPlain;

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

        r.headers.push(("Content-Length".to_string(), r.body.clone().unwrap().len().to_string()));

        let bytes = r.get_bytes();

        println!(
            "Sending response: {}",
            response
        );

        self.stream.write_all(&bytes).unwrap();
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
                        let err = HttpResponse::new(
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
                                    let err = HttpResponse::new(
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
                        let not_found = HttpResponse::new(
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
                    let err = HttpResponse::new(
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