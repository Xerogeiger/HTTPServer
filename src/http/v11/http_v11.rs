use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use crate::http::server::ServerStatus;
use crate::http::server::HttpServer;
use crate::http::server::HttpServerClient;
use crate::http::shared::{HttpRequest, HttpResponse, HttpStatus, RequestMethod, StatusCode};
use crate::http::shared::RequestMethod::Get;
use std::sync::{Arc, Mutex};
use crate::http::shared::ContentType::TextPlain;

struct HttpV11ServerClient {
    ip_address: IpAddr,
    stream: TcpStream,
    port: u16,
    connected: bool
}

impl Clone for HttpV11ServerClient {
    fn clone(&self) -> Self {
        HttpV11ServerClient {
            ip_address: self.ip_address,
            stream: self.stream.try_clone().expect("Failed to clone stream"),
            port: self.port,
            connected: self.connected
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
            stream
        }
    }

    fn get_ip_address(&self) -> Result<IpAddr, String> {
        Ok(self.ip_address)
    }

    fn get_port(&self) -> Result<u16, String> {
        Ok(self.port)
    }
}

pub struct HttpV11Server {
    port: u16,
    status: Arc<Mutex<ServerStatus>>,
    clients: Arc<Mutex<Vec<HttpV11ServerClient>>>,
    address: IpAddr,
    tcp_listener: TcpListener,
    server_thread: Option<std::thread::JoinHandle<()>>,
}

impl HttpServer for HttpV11Server {
    fn start(&mut self) -> Result<(), String> {
        if self.status.lock().unwrap().clone() == ServerStatus::Running {
            return Err("Server is already running".to_string());
        }

        *self.status.lock().unwrap() = ServerStatus::Starting;
        // Implementation for starting the HTTP/1.1 server
        println!("Starting HTTP/1.1 server on {}:{}", self.address, self.port);

        // Bind to the specified address and port
        self.tcp_listener = TcpListener::bind((self.address, self.port)).map_err(|e| e.to_string())?;
        self.clients.lock().unwrap().clear(); // Clear any existing clients
        self.tcp_listener.set_nonblocking(true).map_err(|e| e.to_string())?;

        *self.status.lock().unwrap() = ServerStatus::Running;

        //Start listening for incoming connections on a separate thread
        let listener = self.tcp_listener.try_clone().map_err(|e| e.to_string())?;
        let clients_arc = Arc::clone(&self.clients);
        let address = self.address;
        let port = self.port;
        let status = Arc::clone(&self.status);
        self.server_thread = Some(std::thread::spawn(move || {
            loop {
                if *status.lock().unwrap() != ServerStatus::Running {
                    println!("Server is stopping, exiting listener thread.");
                    break;
                }

                match listener.accept() {
                    Ok((stream, addr)) => {
                        println!("Accepted connection from {}", addr);
                        let client = HttpV11ServerClient::new(address, port, stream);

                        // Mark the client as connected
                        let mut client = client;
                        client.connected = true;

                        clients_arc.lock().unwrap().push(client.clone());

                        // Spawn a new thread to handle the client connection
                        std::thread::spawn(move || {
                            // Handle the client connection in a separate thread
                            while client.is_connected().unwrap() {
                                match client.receive_request() {
                                    Ok(request) => {
                                        println!("Received request: {}", request);
                                        // Here you would handle the request and send a response
                                        let response = HttpResponse {
                                            status: HttpStatus::new(StatusCode::Ok.code(), StatusCode::Ok.text().to_string()),
                                            headers: vec![("Content-Type".to_string(), TextPlain.to_string())],
                                            body: Some("Hello, World!".to_string()),
                                        };
                                        if let Err(e) = client.send_response(response) {
                                            eprintln!("Failed to send response: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to receive request: {}", e);
                                        break; // Exit loop on error
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            // No connections available, continue to accept more
                            std::thread::sleep(std::time::Duration::from_millis(100)); // Sleep to avoid busy waiting
                            continue;
                        } else {
                            eprintln!("Failed to accept connection: {}", e);
                        }
                    }
                }
            }
        }));
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        *self.status.lock().unwrap() = ServerStatus::Stopped;

        // Join the server thread
        if let Some(thread) = self.server_thread.take() {
            thread.join().map_err(|_| "Failed to join server thread".to_string())?;
        }

        // Clear client list
        self.clients.lock().unwrap().clear();

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
            clients: Arc::new(Mutex::new(Vec::new())),
            address,
            tcp_listener: TcpListener::bind((address, 0)).expect("Could not bind to address"),
            server_thread: None,
        }
    }
}