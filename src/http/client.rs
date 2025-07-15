use std::net::{IpAddr, TcpStream};
use crate::http::shared::{HttpRequest, HttpResponse};
use crate::http::shared::RequestMethod::{Delete, Get, Post, Put};

pub(crate) trait HttpClient {
    fn set_headers(&mut self, headers: Vec<(String, String)>);
    fn get_headers(&self) -> Vec<(String, String)>;

    fn set_host(&mut self, host: IpAddr);
    fn get_host(&self) -> IpAddr;

    fn set_port(&mut self, port: u16);
    fn get_port(&self) -> u16;

    fn send_request(&self, request: HttpRequest) -> Result<HttpResponse, String>;
    fn receive_response(&self, stream: &mut TcpStream) -> Result<HttpResponse, String>;

    fn get(&self, url: &str) -> Result<HttpResponse, String> {
        let req = HttpRequest {
            method: Get,
            path: url.into(),
            headers: self.get_headers(),
            body: None,
        };
        self.send_request(req)
    }

    fn post(&self, url: &str, body: Option<String>) -> Result<HttpResponse, String> {
        let req = HttpRequest {
            method: Post,
            path: url.into(),
            headers: self.get_headers(),
            body
        };
        self.send_request(req)
    }

    fn put(&self, url: &str, body: Option<String>) -> Result<HttpResponse, String> {
        let req = HttpRequest {
            method: Put,
            path: url.into(),
            headers: self.get_headers(),
            body
        };
        self.send_request(req)
    }

    fn delete(&self, url: &str) -> Result<HttpResponse, String> {
        let req = HttpRequest {
            method: Delete,
            path: url.into(),
            headers: self.get_headers(),
            body: None,
        };
        self.send_request(req)
    }
}