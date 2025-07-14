use crate::http::shared::{ContentType, HttpRequest, HttpResponse, HttpStatus};
use std::net::{IpAddr, TcpStream};
use std::string::ToString;

pub enum ServerStatus {
    Starting,
    Running,
    Stopped
}
impl Clone for ServerStatus {
    fn clone(&self) -> Self {
        match self {
            ServerStatus::Starting => ServerStatus::Starting,
            ServerStatus::Running => ServerStatus::Running,
            ServerStatus::Stopped => ServerStatus::Stopped,
        }
    }
}
impl PartialEq for ServerStatus {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ServerStatus::Starting, ServerStatus::Starting) => true,
            (ServerStatus::Running, ServerStatus::Running) => true,
            (ServerStatus::Stopped, ServerStatus::Stopped) => true,
            _ => false,
        }
    }
}

pub trait HttpServer {
    fn start(&mut self) -> Result<(), String>;
    fn stop(&mut self) -> Result<(), String>;
    fn restart(&mut self) -> Result<(), String> {
        self.stop()?;
        self.start()
    }
    fn get_port(&self) -> Result<u16, String>;
    fn status(&self) -> Result<ServerStatus, String>;
    fn is_running(&self) -> Result<bool, String>;
}

pub trait HttpServerClient {
    fn receive_request(&mut self) -> Result<HttpRequest, String>;
    fn send_response(&mut self, response: HttpResponse) -> Result<(), String>;
    fn send_error_response(&mut self, status: HttpStatus, message: &str) -> Result<(), String> {
        let response = HttpResponse {
            status,
            headers: vec![("Content-Type".to_string(), ContentType::TextPlain.to_string())],
            body: Some(message.to_string()),
        };
        self.send_response(response)
    }
    fn disconnect(&mut self) -> Result<(), String>;
    fn is_connected(&self) -> Result<bool, String>;
    fn new(ip_address: IpAddr, port: u16, stream: TcpStream) -> Self;
    fn get_ip_address(&self) -> Result<IpAddr, String>;
    fn get_port(&self) -> Result<u16, String>;
}