use crate::http::shared::{ContentType, HttpRequest, HttpResponse, HttpStatus, RequestMethod, StatusCode};
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

pub trait HttpMapping {
    fn matches_url(&self, url: &str) -> bool;
    fn matches_method(&self, method: &RequestMethod) -> bool;
    fn get_content_type(&self) -> ContentType;
    fn handle_request(&self, request: &HttpRequest) -> Result<HttpResponse, String>;
}

pub struct FileMapping {
    pub url: String,
    pub method: RequestMethod,
    pub content_type: ContentType,
    pub file_path: String,
}

impl Clone for FileMapping {
    fn clone(&self) -> Self {
        FileMapping {
            url: self.url.clone(),
            method: self.method.clone(),
            content_type: self.content_type.clone(),
            file_path: self.file_path.clone(),
        }
    }
}

impl PartialEq for FileMapping {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url && self.method == other.method && self.content_type == other.content_type && self.file_path == other.file_path
    }
}

impl FileMapping {
    pub fn new(url: String, method: RequestMethod, content_type: ContentType, file_path: String) -> Self {
        FileMapping {
            url,
            method,
            content_type,
            file_path,
        }
    }
}

impl HttpMapping for FileMapping {
    fn matches_url(&self, url: &str) -> bool {
        // Check if the URL matches the pattern
        if self.url == "*" {
            return true; // Matches all URLs
        }

        let path = url.split(&['?', '#'][..]).next().unwrap_or(url);
        if self.url == path {
            return true; // Exact match
        }
        let pattern_parts: Vec<&str> =
            self.url.trim_matches('/').split('/').collect();
        let url_parts: Vec<&str> =
            path.trim_matches('/').split('/').collect();
        if pattern_parts.len() != url_parts.len() {
            return false;
        }
        for (pattern, part) in pattern_parts.iter().zip(url_parts.iter()) {
            if pattern != &"*" && pattern != part {
                return false;
            }
        }

        true
    }

    fn matches_method(&self, method: &RequestMethod) -> bool {
        self.method == *method
    }

    fn get_content_type(&self) -> ContentType {
        self.content_type.clone()
    }

    fn handle_request(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
        let file_content = std::fs::read_to_string(&self.file_path)
            .map_err(|e| format!("Failed to read file {}: {}", self.file_path, e))?;
        Ok(HttpResponse {
            status: StatusCode::Ok.status(),
            headers: vec![("Content-Type".to_string(), self.content_type.to_string()),
                          ("Content-Length".to_string(), file_content.len().to_string())],
            body: Some(file_content),
        })
    }
}

pub struct DirectoryMapping {
    pub url: String,
    pub method: RequestMethod,
    pub content_type: ContentType,
    pub directory_path: String,
}

impl Clone for DirectoryMapping {
    fn clone(&self) -> Self {
        DirectoryMapping {
            url: self.url.clone(),
            method: self.method.clone(),
            content_type: self.content_type.clone(),
            directory_path: self.directory_path.clone(),
        }
    }
}

impl PartialEq for DirectoryMapping {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url && self.method == other.method && self.content_type == other.content_type && self.directory_path == other.directory_path
    }
}

impl DirectoryMapping {
    pub fn new(url: String, method: RequestMethod, content_type: ContentType, directory_path: String) -> Self {
        DirectoryMapping {
            url,
            method,
            content_type,
            directory_path,
        }
    }
}

impl HttpMapping for DirectoryMapping {
    fn matches_url(&self, url: &str) -> bool {
        // Check if the URL matches the pattern
        if self.url == "*" {
            return true; // Matches all URLs
        }

        let path = url.split(&['?', '#'][..]).next().unwrap_or(url);
        if self.url == path {
            return true; // Exact match
        }
        let pattern_parts: Vec<&str> =
            self.url.trim_matches('/').split('/').collect();
        let url_parts: Vec<&str> =
            path.trim_matches('/').split('/').collect();
        if pattern_parts.len() != url_parts.len() {
            return false;
        }
        for (pattern, part) in pattern_parts.iter().zip(url_parts.iter()) {
            if pattern != &"*" && pattern != part {
                return false;
            }
        }

        true
    }

    fn matches_method(&self, method: &RequestMethod) -> bool {
        self.method == *method
    }

    fn get_content_type(&self) -> ContentType {
        self.content_type.clone()
    }

    fn handle_request(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
        let dir_content = std::fs::read_dir(&self.directory_path)
            .map_err(|e| format!("Failed to read directory {}: {}", self.directory_path, e))?;

        let mut body = String::new();
        for entry in dir_content {
            let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
            body.push_str(&format!("{}\n", entry.file_name().to_string_lossy()));
        }

        Ok(HttpResponse {
            status: StatusCode::Ok.status(),
            headers: vec![("Content-Type".to_string(), self.content_type.to_string()),
                          ("Content-Length".to_string(), body.len().to_string())],
            body: Some(body),
        })
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
    fn join(&mut self) -> Result<(), String>;
    fn add_mapping(&mut self, mapping: Box<dyn HttpMapping + Send + Sync>) -> Result<(), String>;
}

pub trait HttpServerClient {
    fn receive_request(&mut self) -> Result<Option<HttpRequest>, String>;
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

mod tests {
    use super::*;
    use crate::http::shared::HttpVersion;

    #[test]
    fn test_file_mapping() {
        let mapping = FileMapping::new(
            "/test/*".to_string(),
            RequestMethod::Get,
            ContentType::TextPlain,
            "test.txt".to_string(),
        );

        assert!(mapping.matches_url("/test/123"));
        assert!(!mapping.matches_url("/other/123"));
        assert!(mapping.matches_method(&RequestMethod::Get));
        assert!(!mapping.matches_method(&RequestMethod::Post));
    }
}