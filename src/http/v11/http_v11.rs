use std::io::Read;
use std::net::{IpAddr, TcpListener, TcpStream};
use crate::http::server::ServerStatus;
use crate::http::server::HttpServer;
use crate::http::server::HttpServerClient;
use crate::http::shared::{HttpRequest, HttpResponse, HttpStatus, RequestMethod};
use crate::http::shared::RequestMethod::Get;
use std::sync::{Arc, Mutex};

struct HttpV11ServerClient {
    ip_address: IpAddr,
    stream: TcpStream,
    port: u16,
    connected: bool
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
                let headers: Vec<(String, String)> = lines
                    .filter_map(|line| {
                        let mut header_parts = line.splitn(2, ':');
                        if let (Some(key), Some(value)) = (header_parts.next(), header_parts.next()) {
                            Some((key.trim().to_string(), value.trim().to_string()))
                        } else {
                            None
                        }
                    })
                    .collect();

                Ok(HttpRequest {
                    method: RequestMethod::from_str(&method).unwrap_or(Get),
                    path,
                    headers,
                    body: None,
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
        // Simulate sending a response
        println!("Sending response: {} \r\n {}", response.status, response.body.unwrap_or_default());
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
    status: ServerStatus,
    clients: Arc<Mutex<Vec<HttpV11ServerClient>>>,
    address: IpAddr,
    tcp_listener: TcpListener,
    server_thread: Option<std::thread::JoinHandle<()>>,
}

impl HttpServer for HttpV11Server {
    fn start(&mut self) -> Result<(), String> {
        if self.status == ServerStatus::Running {
            return Err("Server is already running".to_string());
        }

        self.status = ServerStatus::Starting;
        // Implementation for starting the HTTP/1.1 server
        self.status = ServerStatus::Running;
        self.tcp_listener = TcpListener::bind((self.address, self.port)).map_err(|e| e.to_string())?;
        self.clients.lock().unwrap().clear(); // Clear any existing clients

        //Start listening for incoming connections on a separate thread
        let listener = self.tcp_listener.try_clone().map_err(|e| e.to_string())?;
        let clients_arc = Arc::clone(&self.clients);
        let address = self.address;
        let port = self.port;
        self.server_thread = Some(std::thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        println!("New client connected: {:?}", stream.peer_addr());
                        let mut client = HttpV11ServerClient::new(address, port, stream);
                        client.connected = true; // Mark client as connected
                        // Handle the client in a separate thread or process
                        match client.receive_request() {
                            Ok(request) => {
                                println!("Received request: {} {}", request.method, request.path);
                                // Here you would typically process the request and send a response
                                let response = HttpResponse {
                                    status: HttpStatus {
                                        code: 200,
                                        text: "OK".to_string(),
                                    },
                                    headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                                    body: Some("Hello, World!".to_string()),
                                };
                                if let Err(e) = client.send_response(response) {
                                    eprintln!("Failed to send response: {}", e);
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to receive request: {}", e);
                                if let Err(disconnect_err) = client.disconnect() {
                                    eprintln!("Failed to disconnect client: {}", disconnect_err);
                                }
                            }
                        }
                        clients_arc.lock().unwrap().push(client);
                    }
                    Err(e) => eprintln!("Failed to accept connection: {}", e),
                }
            }
        }));
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        // Implementation for stopping the HTTP/1.1 server
        // Here we would close the TcpListener and clean up resources
        self.status = ServerStatus::Stopped;
        self.tcp_listener
            .set_nonblocking(false)
            .map_err(|e| e.to_string())?;
        self.tcp_listener
            .incoming()
            .for_each(|_stream| {
                // Close the stream or handle cleanup if necessary
                _stream.unwrap();
            });
        self.clients.lock().unwrap().clear(); // Clear all clients
        if let Some(thread) = self.server_thread.take() {
            if thread.join().is_err() {
                return Err("Failed to join server thread".to_string());
            }
        }
        Ok(())
    }

    fn get_port(&self) -> Result<u16, String> {
        Ok(self.port)
    }

    fn status(&self) -> Result<ServerStatus, String> {
        Ok(self.status.clone())
    }

    fn is_running(&self) -> Result<bool, String> {
        Ok(self.status == ServerStatus::Running)
    }
}

impl HttpV11Server {
    pub fn new(port: u16, address: IpAddr) -> Self {
        HttpV11Server {
            port,
            status: ServerStatus::Stopped,
            clients: Arc::new(Mutex::new(Vec::new())),
            address,
            tcp_listener: TcpListener::bind((address, 0)).expect("Could not bind to address"),
            server_thread: None,
        }
    }
}