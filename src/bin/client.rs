use std::{net::{SocketAddr, TcpStream, SocketAddrV4, TcpListener}, thread};
use my_proxy::socks5::{TransferConfig, transfer};

struct Client {
    server_addr: SocketAddr,
    local_port: u32,
}

impl Client {

    fn new(server_addr: SocketAddr, local_port: u32) -> Self {
        Client{
            server_addr,
            local_port
        }
    }

    fn run(&self) {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.local_port)).unwrap();
        for stream in listener.incoming() {
            let addr = self.server_addr.clone();
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    println!("[client] contruct tcp stream failed, err: {}", e);
                    continue;
                }
            };
            thread::spawn(move || {
                Client::handle_connection(addr, stream);
            });
        }
    }

    fn handle_connection(server_addr: SocketAddr, stream: TcpStream) {
        println!("server addr: {}", server_addr);
        let proxy_stream = TcpStream::connect(server_addr).unwrap();

        let transfer_configs = vec![
            TransferConfig{from: &stream, to: &proxy_stream},
            TransferConfig{from: &proxy_stream, to: &stream},
        ];

        let mut handlers = Vec::new();
        for v in transfer_configs {
            let from = v.from.try_clone().unwrap();
            let to = v.to.try_clone().unwrap();
            handlers.push(thread::spawn( move || {
                _ = transfer(from, to);
            }));
        }
        for handler in handlers {
            handler.join().unwrap();
        }
    }
}

fn main() {
    log4rs::init_file("src/config/client_log.yaml", Default::default()).unwrap();

    let addr: SocketAddrV4 = "127.0.0.1:8999".parse().unwrap();
    let client = Client::new(SocketAddr::V4(addr), 9999);
    client.run();
}
