use std::{net::{TcpListener, TcpStream}, io::Read};
use my_proxy::socks5::Server;

fn main() {
    log4rs::init_file("src/config/server_log.yaml", Default::default()).unwrap();
    let server = Server::new(8999);
    server.run().unwrap();
}
