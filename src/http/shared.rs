use std::fmt::Display;
use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use crate::http::client::HttpClient;
use crate::http::server::HttpServer;
use crate::http::v10::http_v10::HttpV10Client;
use crate::http::v11::http_v11::HttpV11Server;

pub enum HttpVersion {
    V10,
    V11,
    V2,
    V3
}

impl HttpVersion {
    pub fn from_str(s: &str) -> Option<HttpVersion> {
        match s {
            "HTTP/1.0" => Some(HttpVersion::V10),
            "HTTP/1.1" => Some(HttpVersion::V11),
            "HTTP/2" => Some(HttpVersion::V2),
            "HTTP/3" => Some(HttpVersion::V3),
            _ => None,
        }
    }

    pub fn create_server(&self, port: u16) -> Result<Box<dyn HttpServer>, String> {
        match self {
            HttpVersion::V10 => Err("HTTP/1.0 server not implemented".to_string()),
            HttpVersion::V11 => Ok(Box::new(HttpV11Server::new(port, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))),
            HttpVersion::V2 => Err("HTTP/2 server not implemented".to_string()),
            HttpVersion::V3 => Err("HTTP/3 server not implemented".to_string()),
        }
    }

    pub fn create_client(&self, host: IpAddr, port: u16) -> Result<Box<dyn HttpClient>, String> {
        match self {
            HttpVersion::V10 => Ok(Box::new(HttpV10Client::new(host, port))),
            HttpVersion::V11 => Err("HTTP/1.1 client not implemented".to_string()),
            HttpVersion::V2 => Err("HTTP/2 client not implemented".to_string()),
            HttpVersion::V3 => Err("HTTP/3 client not implemented".to_string()),
        }
    }

    pub fn to_string(&self) -> &'static str {
        match self {
            HttpVersion::V10 => "HTTP/1.0",
            HttpVersion::V11 => "HTTP/1.1",
            HttpVersion::V2 => "HTTP/2",
            HttpVersion::V3 => "HTTP/3",
        }
    }
}

impl Clone for HttpVersion {
    fn clone(&self) -> Self {
        match self {
            HttpVersion::V10 => HttpVersion::V10,
            HttpVersion::V11 => HttpVersion::V11,
            HttpVersion::V2 => HttpVersion::V2,
            HttpVersion::V3 => HttpVersion::V3,
        }
    }
}

impl PartialEq for HttpVersion {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (HttpVersion::V10, HttpVersion::V10) => true,
            (HttpVersion::V11, HttpVersion::V11) => true,
            (HttpVersion::V2, HttpVersion::V2) => true,
            (HttpVersion::V3, HttpVersion::V3) => true,
            _ => false,
        }
    }
}

impl Display for HttpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str: &'static str = match self {
            HttpVersion::V10 => "HTTP/1.0",
            HttpVersion::V11 => "HTTP/1.1",
            HttpVersion::V2 => "HTTP/2",
            HttpVersion::V3 => "HTTP/3",
        };
        write!(f, "{}", str)
    }
}

pub enum StatusCode {
    Ok,
    Created,
    Accepted,
    NoContent,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    InternalServerError
}

pub struct HttpStatus {
    pub code: u16,
    pub text: String,
}

impl HttpStatus {
    pub fn new(code: u16, text: String) -> Self {
        HttpStatus { code, text }
    }
}

impl Clone for HttpStatus {
    fn clone(&self) -> Self {
        HttpStatus {
            code: self.code,
            text: self.text.clone(),
        }
    }
}

impl PartialEq for HttpStatus {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.text == other.text
    }
}

impl Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.code, self.text)
    }
}

impl StatusCode {
    pub fn code(&self) -> u16 {
        match self {
            StatusCode::Ok => 200,
            StatusCode::Created => 201,
            StatusCode::Accepted => 202,
            StatusCode::NoContent => 204,
            StatusCode::BadRequest => 400,
            StatusCode::Unauthorized => 401,
            StatusCode::Forbidden => 403,
            StatusCode::NotFound => 404,
            StatusCode::InternalServerError => 500,
        }
    }

    pub fn text(&self) -> &'static str {
        match self {
            StatusCode::Ok => "OK",
            StatusCode::Created => "Created",
            StatusCode::Accepted => "Accepted",
            StatusCode::NoContent => "No Content",
            StatusCode::BadRequest => "Bad Request",
            StatusCode::Unauthorized => "Unauthorized",
            StatusCode::Forbidden => "Forbidden",
            StatusCode::NotFound => "Not Found",
            StatusCode::InternalServerError => "Internal Server Error",
        }
    }

    pub fn status(&self) -> HttpStatus {
        HttpStatus::new(self.code(), self.text().to_string())
    }

    pub fn from_code(code: u16) -> Option<StatusCode> {
        match code {
            200 => Some(StatusCode::Ok),
            201 => Some(StatusCode::Created),
            202 => Some(StatusCode::Accepted),
            204 => Some(StatusCode::NoContent),
            400 => Some(StatusCode::BadRequest),
            401 => Some(StatusCode::Unauthorized),
            403 => Some(StatusCode::Forbidden),
            404 => Some(StatusCode::NotFound),
            500 => Some(StatusCode::InternalServerError),
            _ => None,
        }
    }
}

impl Clone for StatusCode {
    fn clone(&self) -> Self {
        match self {
            StatusCode::Ok => StatusCode::Ok,
            StatusCode::Created => StatusCode::Created,
            StatusCode::Accepted => StatusCode::Accepted,
            StatusCode::NoContent => StatusCode::NoContent,
            StatusCode::BadRequest => StatusCode::BadRequest,
            StatusCode::Unauthorized => StatusCode::Unauthorized,
            StatusCode::Forbidden => StatusCode::Forbidden,
            StatusCode::NotFound => StatusCode::NotFound,
            StatusCode::InternalServerError => StatusCode::InternalServerError,
        }
    }
}

impl PartialEq for StatusCode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (StatusCode::Ok, StatusCode::Ok) => true,
            (StatusCode::Created, StatusCode::Created) => true,
            (StatusCode::Accepted, StatusCode::Accepted) => true,
            (StatusCode::NoContent, StatusCode::NoContent) => true,
            (StatusCode::BadRequest, StatusCode::BadRequest) => true,
            (StatusCode::Unauthorized, StatusCode::Unauthorized) => true,
            (StatusCode::Forbidden, StatusCode::Forbidden) => true,
            (StatusCode::NotFound, StatusCode::NotFound) => true,
            (StatusCode::InternalServerError, StatusCode::InternalServerError) => true,
            _ => false,
        }
    }
}

impl Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str: &'static str = match self {
            StatusCode::Ok => "200 OK",
            StatusCode::Created => "201 Created",
            StatusCode::Accepted => "202 Accepted",
            StatusCode::NoContent => "204 No Content",
            StatusCode::BadRequest => "400 Bad Request",
            StatusCode::Unauthorized => "401 Unauthorized",
            StatusCode::Forbidden => "403 Forbidden",
            StatusCode::NotFound => "404 Not Found",
            StatusCode::InternalServerError => "500 Internal Server Error",
        };
        write!(f, "{}", str)
    }
}

pub enum RequestMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Trace,
    Connect,
    Patch,
}

impl RequestMethod {
    pub fn from_str(s: &str) -> Option<RequestMethod> {
        match s {
            "GET" => Some(RequestMethod::Get),
            "POST" => Some(RequestMethod::Post),
            "PUT" => Some(RequestMethod::Put),
            "DELETE" => Some(RequestMethod::Delete),
            "HEAD" => Some(RequestMethod::Head),
            "OPTIONS" => Some(RequestMethod::Options),
            "TRACE" => Some(RequestMethod::Trace),
            "CONNECT" => Some(RequestMethod::Connect),
            "PATCH" => Some(RequestMethod::Patch),
            _ => None,
        }
    }
}

impl Clone for RequestMethod {
    fn clone(&self) -> Self {
        match self {
            RequestMethod::Get => RequestMethod::Get,
            RequestMethod::Post => RequestMethod::Post,
            RequestMethod::Put => RequestMethod::Put,
            RequestMethod::Delete => RequestMethod::Delete,
            RequestMethod::Head => RequestMethod::Head,
            RequestMethod::Options => RequestMethod::Options,
            RequestMethod::Trace => RequestMethod::Trace,
            RequestMethod::Connect => RequestMethod::Connect,
            RequestMethod::Patch => RequestMethod::Patch,
        }
    }
}

impl PartialEq for RequestMethod {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (RequestMethod::Get, RequestMethod::Get) => true,
            (RequestMethod::Post, RequestMethod::Post) => true,
            (RequestMethod::Put, RequestMethod::Put) => true,
            (RequestMethod::Delete, RequestMethod::Delete) => true,
            (RequestMethod::Head, RequestMethod::Head) => true,
            (RequestMethod::Options, RequestMethod::Options) => true,
            (RequestMethod::Trace, RequestMethod::Trace) => true,
            (RequestMethod::Connect, RequestMethod::Connect) => true,
            (RequestMethod::Patch, RequestMethod::Patch) => true,
            _ => false,
        }
    }
}

impl Display for RequestMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str: &'static str = match self {
            RequestMethod::Get => "GET",
            RequestMethod::Post => "POST",
            RequestMethod::Put => "PUT",
            RequestMethod::Delete => "DELETE",
            RequestMethod::Head => "HEAD",
            RequestMethod::Options => "OPTIONS",
            RequestMethod::Trace => "TRACE",
            RequestMethod::Connect => "CONNECT",
            RequestMethod::Patch => "PATCH",
        };
        write!(f, "{}", str)
    }
}

use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentType {
    TextPlain,
    TextHtml,
    TextCss,
    ApplicationJson,
    ApplicationXml,
    ApplicationJavascript,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageSvg,
    ImageIco,
    ImageWebp,
    AudioMpeg,
    AudioWav,
    AudioOgg,
    FontWoff,
    FontWoff2,
    FontTtf,
    FontOtf,
    VideoMp4,
}

impl ContentType {
    /// Parse from a MIME‐type string
    pub fn from_str(s: &str) -> Option<ContentType> {
        match s {
            "text/plain"                     => Some(ContentType::TextPlain),
            "text/html"                      => Some(ContentType::TextHtml),
            "text/css"                       => Some(ContentType::TextCss),
            "application/json"               => Some(ContentType::ApplicationJson),
            "application/xml"                => Some(ContentType::ApplicationXml),
            "application/javascript"
            | "application/x-javascript"
            | "text/javascript"              => Some(ContentType::ApplicationJavascript),
            "image/png"                      => Some(ContentType::ImagePng),
            "image/jpeg" | "image/jpg"       => Some(ContentType::ImageJpeg),
            "image/gif"                      => Some(ContentType::ImageGif),
            "image/svg+xml"                  => Some(ContentType::ImageSvg),
            "image/x-icon" | "image/vnd.microsoft.icon"
            => Some(ContentType::ImageIco),
            "image/webp"                     => Some(ContentType::ImageWebp),
            "audio/mpeg"                     => Some(ContentType::AudioMpeg),
            "audio/wav"                      => Some(ContentType::AudioWav),
            "audio/ogg"                      => Some(ContentType::AudioOgg),
            "font/woff"                      => Some(ContentType::FontWoff),
            "font/woff2"                     => Some(ContentType::FontWoff2),
            "font/ttf"                       => Some(ContentType::FontTtf),
            "font/otf"                       => Some(ContentType::FontOtf),
            "video/mp4"                      => Some(ContentType::VideoMp4),
            _                                => None,
        }
    }

    /// Guess from a file‐extension like "html", "png", "woff2", etc.
    pub fn from_extension(ext: &str) -> Option<ContentType> {
        match ext.to_lowercase().as_str() {
            "html" | "htm"                  => Some(ContentType::TextHtml),
            "txt"                           => Some(ContentType::TextPlain),
            "css"                           => Some(ContentType::TextCss),
            "json"                          => Some(ContentType::ApplicationJson),
            "xml"                           => Some(ContentType::ApplicationXml),
            "js" | "mjs" | "cjs"            => Some(ContentType::ApplicationJavascript),
            "png"                           => Some(ContentType::ImagePng),
            "jpeg" | "jpg"                  => Some(ContentType::ImageJpeg),
            "gif"                           => Some(ContentType::ImageGif),
            "svg"                           => Some(ContentType::ImageSvg),
            "ico"                           => Some(ContentType::ImageIco),
            "webp"                          => Some(ContentType::ImageWebp),
            "mp3"                           => Some(ContentType::AudioMpeg),
            "wav"                           => Some(ContentType::AudioWav),
            "ogg"                           => Some(ContentType::AudioOgg),
            "woff"                          => Some(ContentType::FontWoff),
            "woff2"                         => Some(ContentType::FontWoff2),
            "ttf"                           => Some(ContentType::FontTtf),
            "otf"                           => Some(ContentType::FontOtf),
            "mp4"                           => Some(ContentType::VideoMp4),
            _                               => None,
        }
    }

    /// Pull the extension off a `Path` and feed into `from_extension`
    pub fn from_path(path: &Path) -> Option<ContentType> {
        path.extension()
            .and_then(|os| os.to_str())
            .and_then(ContentType::from_extension)
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mime = match self {
            ContentType::TextPlain            => "text/plain",
            ContentType::TextHtml             => "text/html",
            ContentType::TextCss              => "text/css",
            ContentType::ApplicationJson      => "application/json",
            ContentType::ApplicationXml       => "application/xml",
            ContentType::ApplicationJavascript=> "application/javascript",
            ContentType::ImagePng             => "image/png",
            ContentType::ImageJpeg            => "image/jpeg",
            ContentType::ImageGif             => "image/gif",
            ContentType::ImageSvg             => "image/svg+xml",
            ContentType::ImageIco             => "image/x-icon",
            ContentType::ImageWebp            => "image/webp",
            ContentType::AudioMpeg            => "audio/mpeg",
            ContentType::AudioWav             => "audio/wav",
            ContentType::AudioOgg             => "audio/ogg",
            ContentType::FontWoff             => "font/woff",
            ContentType::FontWoff2            => "font/woff2",
            ContentType::FontTtf              => "font/ttf",
            ContentType::FontOtf              => "font/otf",
            ContentType::VideoMp4             => "video/mp4",
        };
        write!(f, "{}", mime)
    }
}


pub struct HttpRequest {
    pub method: RequestMethod,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl HttpRequest {
    pub fn new(method: RequestMethod, path: String, headers: Vec<(String, String)>, body: Option<String>) -> Self {
        HttpRequest {
            method,
            path,
            headers,
            body,
        }
    }
}

impl HttpRequest {
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut request_text = format!("{} {} HTTP/1.1\r\n", self.method, self.path);
        for (key, value) in &self.headers {
            request_text.push_str(&format!("{}: {}\r\n", key, value));
        }
        request_text.push_str("\r\n"); // end of headers
        if let Some(body) = &self.body {
            request_text.push_str(body);
        }
        request_text.into_bytes()
    }
}

impl PartialEq for HttpRequest {
    fn eq(&self, other: &Self) -> bool {
        self.method == other.method && self.path == other.path && self.headers == other.headers && self.body == other.body
    }
}

impl Clone for HttpRequest {
    fn clone(&self) -> Self {
        HttpRequest {
            method: self.method.clone(),
            path: self.path.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
        }
    }
}

impl Display for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut request_text = format!("{} {} HTTP/1.1\r\n", self.method, self.path);
        let mut first = true;
        for (key, value) in &self.headers {
            if !first {
                request_text.push_str("\r\n");
            } else {
                first = false;
            }

            request_text.push_str(&format!("{}: {}", key, value));
        }
        if self.headers.len() > 0 {
            request_text.push_str("\r\n");
        }
        write!(f, "{}", request_text)
    }
}

pub struct HttpResponse {
    pub status: HttpStatus,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl HttpResponse {
    pub fn from_status(status: StatusCode, headers: Vec<(String, String)>, body: Option<String>) -> HttpResponse {
        HttpResponse {
            status: status.status(),
            headers,
            body,
        }
    }

    pub fn new(status: HttpStatus, headers: Vec<(String, String)>, body: Option<String>) -> Self {
        HttpResponse {
            status,
            headers,
            body,
        }
    }
}

impl HttpResponse {
    pub fn clone(&self) -> HttpResponse {
        HttpResponse {
            status: self.status.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
        }
    }
}

impl HttpResponse {
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut headers = self.headers.clone();
        if self.body.is_none() {
            headers.push(("Content-Length".to_string(), "0".to_string()));
        } else if let Some(body) = &self.body {
            headers.push(("Content-Length".to_string(), body.len().to_string()));
        }
        let mut response_text = format!("HTTP/1.1 {} {}\r\n", self.status.code, self.status.text);
        for (key, value) in &headers {
            response_text.push_str(&format!("{}: {}\r\n", key, value));
        }
        response_text.push_str("\r\n"); // end of headers
        if let Some(body) = &self.body {
            response_text.push_str(body);
        }
        response_text.into_bytes()
    }
}

impl Display for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut response_text = format!("{} {}\r\n", self.status.code, self.status.text);
        let mut first = true;
        for (key, value) in &self.headers {
            if !first {
                response_text.push_str("\r\n");
            } else {
                first = false;
            }

            response_text.push_str(&format!("{}: {}", key, value));
        }
        response_text.push_str("\r\n"); // end of headers
        write!(f, "{}", response_text.to_string())
    }
}

pub fn write_chunked<W: Write>(stream: &mut W, mut data: &[u8]) -> io::Result<()> {
    const CHUNK_SIZE: usize = 1024;

    while !data.is_empty() {
        // 1) How many bytes we'll write in this chunk
        let this_size = data.len().min(CHUNK_SIZE);

        // 2) Write the chunk‐size in hex, + CRLF
        write!(stream, "{:X}\r\n", this_size)?;

        // 3) Write the chunk‐data + CRLF
        stream.write_all(&data[..this_size])?;
        stream.write_all(b"\r\n")?;

        // 4) Advance our window
        data = &data[this_size..];
    }

    // 5) Final zero‐length chunk to signal “done”
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_http_version_parsing_and_display() {
        assert!(HttpVersion::from_str("HTTP/1.0") == Some(HttpVersion::V10));
        assert!(HttpVersion::from_str("HTTP/1.1") == Some(HttpVersion::V11));
        assert!(HttpVersion::from_str("HTTP/2") == Some(HttpVersion::V2));
        assert!(HttpVersion::from_str("HTTP/3") == Some(HttpVersion::V3));
        assert!(HttpVersion::from_str("HTTP/0.9").is_none());
        assert_eq!(HttpVersion::V11.to_string(), "HTTP/1.1");
    }

    #[test]
    fn test_http_version_create_server_client() {
        // Supported server/client combinations
        assert!(HttpVersion::V11.create_server(0).is_ok());
        assert!(HttpVersion::V10
            .create_client(IpAddr::V4(Ipv4Addr::LOCALHOST), 80)
            .is_ok());

        // Unsupported variants should return errors
        assert!(HttpVersion::V10.create_server(0).is_err());
        assert!(HttpVersion::V11
            .create_client(IpAddr::V4(Ipv4Addr::LOCALHOST), 80)
            .is_err());
        assert!(HttpVersion::V2.create_server(0).is_err());
        assert!(HttpVersion::V2
            .create_client(IpAddr::V4(Ipv4Addr::LOCALHOST), 80)
            .is_err());
        assert!(HttpVersion::V3.create_server(0).is_err());
    }

    #[test]
    fn test_request_and_response_bytes() {
        let req = HttpRequest::new(
            RequestMethod::Post,
            "/submit".into(),
            vec![("Content-Length".into(), "4".into())],
            Some("data".into()),
        );
        let req_bytes = String::from_utf8(req.get_bytes()).unwrap();
        assert!(req_bytes.starts_with("POST /submit HTTP/1.1"));
        assert!(req_bytes.contains("\r\n\r\ndata"));

        let resp = HttpResponse::from_status(
            StatusCode::Ok,
            vec![("Content-Type".into(), ContentType::TextPlain.to_string())],
            None,
        );
        let resp_bytes = String::from_utf8(resp.get_bytes()).unwrap();
        assert!(resp_bytes.contains("Content-Length: 0"));
        assert!(resp_bytes.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_write_chunked() {
        let data = vec![b'a'; 3000];
        let mut out = Vec::new();
        write_chunked(&mut out, &data).unwrap();
        let s = String::from_utf8(out).unwrap();
        // should contain two full chunks of 1024 and one remainder
        assert!(s.starts_with("400\r\n"));
        assert!(s.ends_with("0\r\n\r\n"));
    }

    #[test]
    fn test_parsing_enums_from_str() {
        assert!(RequestMethod::from_str("GET") == Some(RequestMethod::Get));
        assert!(ContentType::from_str("text/html") == Some(ContentType::TextHtml));
        assert!(RequestMethod::from_str("UNKNOWN").is_none());
        assert!(ContentType::from_str("invalid/type").is_none());
    }
}