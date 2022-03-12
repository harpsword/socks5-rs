use std::{net::{TcpListener, TcpStream}, io::Read};
use my_proxy::socks5::Server;

fn main() {
    let server = Server::new(8999);
    server.run().unwrap();
}
