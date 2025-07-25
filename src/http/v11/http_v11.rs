use crate::decode::gz_decoder::GzDecoder;
use crate::decode::gz_encoder::GzEncoder;
use crate::http::client::HttpClient;
use crate::http::server::{HttpServer, TlsConfig};
use crate::http::server::HttpServerClient;
use crate::http::server::{HttpMapping, ServerStatus};
use crate::http::shared::ContentType::TextPlain;
use crate::http::shared::RequestMethod::Get;
use crate::http::shared::{
    write_chunked, HttpRequest, HttpResponse, HttpStatus, RequestMethod, StatusCode,
};
use crate::ssl::handshake_state::server_handshake;
use crate::ssl::state::TlsSession;
use std::io;
use std::io::{BufRead, BufReader, Error, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

        let mut raw = raw.into_bytes();
        if let Some(body) = request.body {
            raw.extend_from_slice(&body);
        }

        if self.stream.is_none() {
            self.ensure_connection().map_err(|e| e.to_string())?;
        }

        let mut stream = self
            .stream
            .take()
            .expect("stream was just set so this is safe");

        stream.write_all(&raw).map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;

        // Read and parse response
        let response = self.receive_response(&stream)?;
        // Put the stream back for keep-alive
        self.stream = Some(stream);
        Ok(response)
    }

    fn receive_response(&self, stream: &TcpStream) -> Result<HttpResponse, String> {
        let mut reader = BufReader::new(stream);
        // 1) Status line
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .map_err(|e| e.to_string())?;
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
        let is_chunked = headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked")
        });
        let is_gzip = headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("content-encoding") && v.eq_ignore_ascii_case("gzip")
        });
        if is_chunked {
            body_bytes =
                HttpV11Client::read_chunked_body(&mut reader).map_err(|e| e.to_string())?;
        } else if let Some((_, v)) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        {
            let len: usize = v.parse().map_err(|_| "Invalid Content-Length")?;
            let mut buf = vec![0; len];
            reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
            body_bytes = buf;
        } else {
            // read until EOF
            reader
                .read_to_end(&mut body_bytes)
                .map_err(|e| e.to_string())?;
        }

        // 4) Handle gzip
        let mut final_body = body_bytes;
        if is_gzip {
            let d = GzDecoder::load(&final_body[..]);
            let decompressed = d.unwrap().decompress();
            final_body = decompressed.unwrap();
        }

        Ok(HttpResponse::new(
            HttpStatus::new(code, reason),
            headers,
            Some(final_body),
        ))
    }
}

enum Connection {
    Plain(BufReader<TcpStream>),
    Tls(BufReader<TlsSession>),
}

struct HttpV11ServerClient {
    ip_address: IpAddr,
    port: u16,
    connected: bool,
    connection: Connection,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Clone for HttpV11ServerClient {
    fn clone(&self) -> Self {
        let connection = match &self.connection {
            Connection::Plain(reader) => {
                let stream_clone = reader
                    .get_ref()
                    .try_clone()
                    .expect("Failed to clone stream");
                Connection::Plain(BufReader::new(stream_clone))
            }
            Connection::Tls(reader) => {
                let session_clone = reader.get_ref().clone();
                Connection::Tls(BufReader::new(session_clone))
            }
        };
        HttpV11ServerClient {
            ip_address: self.ip_address,
            port: self.port,
            connected: self.connected,
            connection,
            thread: None,
        }
    }
}

fn read_request<R: BufRead>(reader: &mut R) -> Result<Option<HttpRequest>, String> {
    let mut request_line = String::new();
    match reader.read_line(&mut request_line) {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(e) => return Err(format!("Failed to read request line: {}", e)),
    }
    let request_line = request_line.trim_end();
    if request_line.is_empty() {
        return Ok(None);
    }
    let mut parts = request_line.split_whitespace();
    let method_str = parts.next().ok_or("Missing request method")?;
    let path = parts.next().ok_or("Missing request path")?;
    let version = parts.next().ok_or("Missing HTTP version")?;
    if !version.eq_ignore_ascii_case("HTTP/1.1") && !version.eq_ignore_ascii_case("HTTP/1.0") {
        return Err(format!("Unsupported HTTP version: {}", version));
    }
    let method = RequestMethod::from_str(method_str)
        .ok_or_else(|| format!("Unsupported HTTP method: {}", method_str))?;
    let mut headers = Vec::new();
    let mut body = None;
    loop {
        let mut header_line = String::new();
        match reader.read_line(&mut header_line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => return Err(format!("Failed to read header line: {}", e)),
        }
        let header_line = header_line.trim_end();
        if header_line.is_empty() {
            break;
        }
        if let Some((k, v)) = header_line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            return Err(format!("Invalid header format: {}", header_line));
        }
    }
    if let Some(cl) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
    {
        let mut body_bytes = vec![0; cl];
        reader
            .read_exact(&mut body_bytes)
            .map_err(|e| format!("Failed to read request body: {}", e))?;
        body = Some(body_bytes);
    } else if headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("Transfer-Encoding") && v.eq_ignore_ascii_case("chunked")
    }) {
        let mut body_bytes = Vec::new();
        loop {
            let mut size_line = String::new();
            reader
                .read_line(&mut size_line)
                .map_err(|e| format!("Failed to read chunk size: {}", e))?;
            let size = usize::from_str_radix(size_line.trim_end(), 16)
                .map_err(|_| "Invalid chunk size".to_string())?;
            if size == 0 {
                break;
            }
            let mut chunk = vec![0; size];
            reader
                .read_exact(&mut chunk)
                .map_err(|e| format!("Failed to read chunk data: {}", e))?;
            body_bytes.extend_from_slice(&chunk);
            let mut crlf = [0; 2];
            reader
                .read_exact(&mut crlf)
                .map_err(|e| format!("Failed to read trailing CRLF: {}", e))?;
        }
        body = Some(body_bytes);
    }
    Ok(Some(HttpRequest::new(
        method,
        path.to_string(),
        headers,
        body,
    )))
}

fn write_response<W: Write>(mut writer: W, mut response: HttpResponse) -> Result<(), String> {
    response
        .headers
        .push(("Connection".into(), "keep-alive".into()));
    let chunked = !response.body.is_none() && response.body.as_ref().map_or(0, |b| b.len()) > 1024;
    let is_gzip = response
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("Content-Encoding") && v.eq_ignore_ascii_case("gzip"));
    if chunked {
        response
            .headers
            .push(("Transfer-Encoding".into(), "chunked".into()));
    } else {
        let len = response.body.as_ref().map_or(0, |b| b.len());
        response
            .headers
            .push(("Content-Length".into(), len.to_string()));
    }
    let status_line = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status.code, response.status.text
    );
    let mut headers = String::new();
    for (k, v) in &response.headers {
        headers.push_str(&format!("{}: {}\r\n", k, v));
    }
    headers.push_str("\r\n");
    let mut body = response.body.clone().unwrap_or_default();
    if is_gzip {
        body = GzEncoder::new()
            .encode(&body)
            .map_err(|e| format!("Failed to gzip response body: {}", e))?;
    }
    writer
        .write_all(status_line.as_bytes())
        .map_err(|e| format!("Failed to write response header: {}", e))?;
    writer
        .write_all(headers.as_bytes())
        .map_err(|e| format!("Failed to write headers: {}", e))?;
    if chunked {
        write_chunked(&mut writer, &body)
            .map_err(|e| format!("Failed to write chunked response: {}", e))?;
    } else {
        writer
            .write_all(&body)
            .map_err(|e| format!("Failed to write response body: {}", e))?;
    }
    Ok(())
}

impl HttpServerClient for HttpV11ServerClient {
    fn receive_request(&mut self) -> Result<Option<HttpRequest>, String> {
        if !self.connected {
            return Err("Client is not connected".into());
        }
        match &mut self.connection {
            Connection::Plain(r) => read_request(r),
            Connection::Tls(r) => read_request(r),
        }
    }

    fn send_response(&mut self, response: HttpResponse) -> Result<(), String> {
        if !self.connected {
            return Err("Client is not connected".into());
        }
        match &mut self.connection {
            Connection::Plain(r) => write_response(r.get_mut(), response),
            Connection::Tls(r) => write_response(r.get_mut(), response),
        }
    }

    fn disconnect(&mut self) -> Result<(), String> {
        if !self.connected {
            return Err("Client is not connected".into());
        }
        match &mut self.connection {
            Connection::Plain(r) => r
                .get_mut()
                .shutdown(std::net::Shutdown::Both)
                .map_err(|e| e.to_string())?,
            Connection::Tls(r) => r.get_mut().shutdown().map_err(|e| e.to_string())?,
        }
        println!("Client disconnected from {}:{}", self.ip_address, self.port);
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> Result<bool, String> {
        Ok(self.connected)
    }

    fn new(ip_address: IpAddr, port: u16, stream: TcpStream) -> Self {
        let reader = BufReader::new(stream);
        HttpV11ServerClient {
            ip_address,
            port,
            connected: false,
            connection: Connection::Plain(reader),
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
            thread
                .join()
                .map_err(|_| "Failed to join client thread".to_string())?;
        }
        Ok(())
    }

    fn new_tls(ip_address: IpAddr, port: u16, session: TlsSession) -> Self {
        let reader = BufReader::new(session);
        HttpV11ServerClient {
            ip_address,
            port,
            connected: false,
            connection: Connection::Tls(reader),
            thread: None,
        }
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
    tls_config: Option<TlsConfig>,
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
        // Set the listener to non-blocking mode
        tcp_listener
            .set_nonblocking(true)
            .map_err(|e| format!("Failed to set non-blocking mode: {}", e))?;
        self.tcp_listener = Some(
            tcp_listener
                .try_clone()
                .expect("Expected valid tcp listener"),
        );
        self.clients.lock().unwrap().clear(); // Clear any existing clients

        *self.status.lock().unwrap() = ServerStatus::Running;

        //Start listening for incoming connections on a separate thread
        let listener = tcp_listener.try_clone().map_err(|e| e.to_string())?;
        let status = Arc::clone(&self.status);
        let mappings = Arc::clone(&self.mappings);
        let clients = Arc::clone(&self.clients);
        let tls_config = self.tls_config.clone();
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
                        let client = create_client(stream, tls_config.clone()).unwrap();
                        client.lock().unwrap().thread =
                            handle_client(client.clone(), mappings.clone())
                                .expect("Failed to handle client");
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

    fn enable_tls(&mut self, config: TlsConfig) -> Result<(), String> {
        self.tls_config = Some(config);
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
            tls_config: None,
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
        .any(|(k, _)| k.eq_ignore_ascii_case("host"))
    {
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
                "Requests with a body must include `Content-Length` or `Transfer-Encoding`".into(),
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
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        return Err("POST/PUT requests should include a `Content-Type` header".into());
    }

    // 6) Validate header syntax: token characters for names, no raw control chars in values
    for (name, value) in &request.headers {
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-!#$%&'*+.^_`|~".contains(c))
        {
            return Err(format!("Invalid header name token: `{}`", name));
        }
        if value.bytes().any(|b| b == b'\r' || b == b'\n') {
            return Err(format!("Illegal control char in header `{}` value", name));
        }
    }

    Ok(())
}

fn create_client(
    tcp_stream: TcpStream,
    tls: Option<TlsConfig>,
) -> Result<Arc<Mutex<HttpV11ServerClient>>, String> {
    if let Some(cfg) = tls {
        let mut session = TlsSession::new(tcp_stream);
        server_handshake(&mut session, &cfg.cert).map_err(|e| e.to_string())?;
        let addr = session.local_addr().unwrap();
        let client = Arc::new(Mutex::new(HttpV11ServerClient::new_tls(
            addr.ip(),
            addr.port(),
            session,
        )));
        client.lock().unwrap().connected = true;
        Ok(client)
    } else {
        let addr = tcp_stream.local_addr().unwrap();
        let client = Arc::new(Mutex::new(HttpV11ServerClient::new(
            addr.ip(),
            addr.port(),
            tcp_stream,
        )));
        client.lock().unwrap().connected = true;
        Ok(client)
    }
}

fn handle_client(
    client: Arc<Mutex<HttpV11ServerClient>>,
    mappings: Arc<Mutex<Vec<Box<dyn HttpMapping + Send + Sync>>>>,
) -> Result<Option<std::thread::JoinHandle<()>>, Error> {
    if (client.lock().unwrap().is_connected().unwrap_or(false) == false) {
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

                    println!(
                        "Received request: {}",
                        request.clone().expect("Request should not be None")
                    );
                    // Validate the request
                    if let Err(e) =
                        validate_request(&request.clone().expect("Request should not be None"))
                    {
                        eprintln!("Invalid request: {}", e);
                        let err = HttpResponse::from_status(
                            StatusCode::BadRequest,
                            vec![("Content-Type".into(), TextPlain.to_string())],
                            Some(e.into_bytes()),
                        );
                        let _ = c.send_response(err);
                        continue; // Skip to the next iteration
                    }

                    let request = request.expect("Request should not be None");
                    let keep_alive = request.headers.iter().any(|(k, v)| {
                        k.eq_ignore_ascii_case("Connection") && v.eq_ignore_ascii_case("keep-alive")
                    });
                    let mut handled = false;

                    for mapping in mappings.lock().unwrap().iter() {
                        if mapping.matches_url(&request.path)
                            && mapping.matches_method(&request.method)
                        {
                            handled = true;
                            match mapping.handle_request(&request) {
                                Ok(mut resp) => {
                                    let response_length = resp.body.as_ref().map_or(0, |b| b.len());
                                    if response_length > 1024
                                        && request.headers.iter().any(|(k, v)| {
                                            k.eq_ignore_ascii_case("Accept-Encoding")
                                                && v.contains("gzip")
                                        })
                                    {
                                        // Add gzip encoding if body is large
                                        resp.headers
                                            .push(("Content-Encoding".into(), "gzip".into()));
                                    }
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
                        c.disconnect()
                            .unwrap_or_else(|e| eprintln!("disconnect error: {}", e));
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
        return Err(Error::new(
            std::io::ErrorKind::Other,
            "Client thread finished immediately",
        ));
    }

    // Thread handle is returned, or `None` if the client is not connected
    Ok(Some(handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::shared::{ContentType, HttpRequest, HttpResponse, RequestMethod, StatusCode};

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
            vec![
                ("Host".into(), "a".into()),
                ("Content-Type".into(), "text/plain".into()),
            ],
            Some("body".into()),
        );
        assert!(validate_request(&req).is_err());

        // Invalid header name
        let req = HttpRequest::new(
            RequestMethod::Get,
            "/".into(),
            vec![
                ("Bad Header".into(), "v".into()),
                ("Host".into(), "a".into()),
            ],
            None,
        );
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn test_multiple_requests_single_connection() {
        use std::net::{Shutdown, TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let (server_stream, _) = listener.accept().unwrap();
            let mut client = HttpV11ServerClient::new(addr.ip(), addr.port(), server_stream);
            client.connected = true;

            let first = client.receive_request().unwrap().unwrap();
            let second = client.receive_request().unwrap().unwrap();
            (first, second)
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        stream
            .write_all(b"GET /two HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        stream.shutdown(Shutdown::Write).unwrap();

        let (req1, req2) = handle.join().unwrap();
        assert_eq!(req1.path, "/one");
        assert_eq!(req2.path, "/two");
    }

    #[test]
    fn https_server_connection() {
        use std::io::{Read, Write};
        use std::net::{IpAddr, Ipv4Addr, TcpStream};
        use crate::ssl::handshake_state::client_handshake;
        use crate::ssl::state::TlsSession;

        struct HelloMapping;
        impl HttpMapping for HelloMapping {
            fn matches_url(&self, url: &str) -> bool {
                url == "/hello"
            }

            fn matches_method(&self, method: &RequestMethod) -> bool {
                *method == RequestMethod::Get
            }

            fn get_content_type(&self) -> ContentType {
                ContentType::TextPlain
            }

            fn handle_request(&self, _req: &HttpRequest) -> Result<HttpResponse, String> {
                Ok(HttpResponse::from_status(
                    StatusCode::Ok,
                    vec![("Content-Type".into(), ContentType::TextPlain.to_string())],
                    Some(b"hi".to_vec()),
                ))
            }
        }

        let mut server = HttpV11Server::new(0, IpAddr::V4(Ipv4Addr::LOCALHOST));
        server.add_mapping(Box::new(HelloMapping)).unwrap();
        server.enable_tls(TlsConfig { cert: vec![], key: vec![], ciphers: vec![] });
        server.start().unwrap();

        let port = server
            .tcp_listener
            .as_ref()
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let mut session = TlsSession::new(stream);
        client_handshake(&mut session).unwrap();
        session
            .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        session.flush().unwrap();
        let (_, data) = session.recv().unwrap();
        let text = String::from_utf8_lossy(&data);
        assert!(text.starts_with("HTTP/1.1 200 OK"));

        server.stop().unwrap();
    }
}
