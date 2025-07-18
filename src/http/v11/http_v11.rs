use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use crate::http::server::{HttpMapping, ServerStatus};
use crate::http::server::HttpServer;
use crate::http::server::{HttpServerClient};
use crate::http::shared::{HttpRequest, HttpResponse, HttpStatus, RequestMethod, StatusCode};
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
    fn receive_request(&mut self) -> Result<HttpRequest, String> {
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

                let body = if let Some(body_line) = lines.next() {
                    Some(body_line.to_string())
                } else {
                    None
                };

                Ok(HttpRequest {
                    method: RequestMethod::from_str(&method).unwrap_or(Get),
                    path,
                    headers,
                    body,
                })
            }
            Ok(_) => Err("No data received".to_string()),
            Err(e) => Err(format!("Failed to read from stream: {}", e)),
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
            "Sending response: {} \r\n {}",
            response.status,
            response.body.unwrap_or_default()
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
    tcp_listener: TcpListener,
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
        self.tcp_listener = TcpListener::bind((self.address, self.port)).map_err(|e| e.to_string())?;
        self.clients.lock().unwrap().clear(); // Clear any existing clients

        *self.status.lock().unwrap() = ServerStatus::Running;

        //Start listening for incoming connections on a separate thread
        let listener = self.tcp_listener.try_clone().map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let address = self.address.clone();
        let port = self.port;
        // 1) Clone the Arc for `status` and `mappings` so we can use them in the thread:
        let status = Arc::clone(&self.status);
        let mappings = Arc::clone(&self.mappings);
        let clients = Arc::clone(&self.clients);
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

                        let mappings = Arc::clone(&mappings);
                        let client = Arc::new(Mutex::new(HttpV11ServerClient::new(address.clone(), port, stream)));
                        {
                            // set connected flag under the lock
                            let mut c0 = client.lock().unwrap();
                            c0.connected = true; // Mark the client as connected
                        }

                        // 3) Now we can spawn a thread to handle this client:
                        {
                            let client_clone = Arc::clone(&client);
                            let thread = std::thread::spawn(move || {
                                loop {
                                    let mut c = client_clone.lock().unwrap();
                                    if !c.is_connected().unwrap_or(false) {
                                        break;
                                    }
                                    match c.receive_request() {
                                        Ok(request) => {
                                            println!("Got: {}", request);
                                            let mut handled = false;

                                            for mapping in mappings.lock().unwrap().iter() {
                                                if mapping.matches_url(&request.path)
                                                    && mapping.matches_method(&request.method) {
                                                    handled = true;
                                                    match mapping.handle_request(&request) {
                                                        Ok(resp) => {
                                                            if let Err(e) = c.send_response(resp) {
                                                                eprintln!("send_response: {}", e);
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
                                                    break;
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

                                            break; // one request per connection
                                        }
                                        Err(e) => {
                                            eprintln!("receive_request: {}", e);
                                            break;
                                        }
                                    }
                                }

                                let ip_address = client_clone.lock().unwrap()
                                    .get_ip_address().unwrap();
                                println!("Server Client {} disconnected", ip_address);
                             });
                            client.lock().unwrap().thread = Some(thread);
                        }

                        clients.lock().unwrap().push(client);
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
}

impl HttpV11Server {
    pub fn new(port: u16, address: IpAddr) -> Self {
        HttpV11Server {
            port,
            status: Arc::new(Mutex::new(ServerStatus::Stopped)),
            mappings: Arc::new(Mutex::new(Vec::new())),
            clients: Arc::new(Mutex::new(Vec::new())),
            address,
            tcp_listener: TcpListener::bind((address, 0)).expect("Could not bind to address"),
            server_thread: None,
        }
    }
}