use core::time;
use std::net::{SocketAddr, TcpStream, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr, TcpListener, ToSocketAddrs};
use std::io::{Error as IOError, Write, Read, BufReader, Cursor, BufWriter};
use std::str::{from_utf8, Utf8Error};
use std::thread::sleep;
use std::time::Duration;
use std::{vec, thread};
use thiserror::Error;

use bytes::{BytesMut, Buf};
use log::{info, trace, error};
use num_enum::{TryFromPrimitive, IntoPrimitive, TryFromPrimitiveError, FromPrimitive};

use crate::exponent::Exponent;

trait ToByte {
    fn to_byte(&self) -> u8;
}

trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

trait FromBytes {
    fn from_bytes(d: &mut Cursor<&[u8]>) -> Result<Self, Socks5Error> where Self: Sized;
}

#[derive(Error, Debug)]
pub enum Socks5Error {
    #[error("encounter io error: {:?}", .0)]
    IOError(#[from] IOError),

    #[error("wrong length of data packet")]
    WrongLen, // 数据包的长度不对
    #[error("wrong socks version")]
    WrongVer, // socks的版本不对
    #[error("empty data")]
    EmptyData, 
    #[error("parse string failed")]
    ParseStringFailed(#[from] Utf8Error), // 解析失败

    #[error("transfer data between proxy and target server failed")]
    TransferFailed, // 流量传输失败

    #[error("parse ValidationMethod failed, err:{:?}", .0)]
    ParseValidationMethodError(#[from] TryFromPrimitiveError<ValidateMethod>),

    #[error("parse CmdType failed, err:{:?}", .0)]
    ParseCmdTypeError(#[from] TryFromPrimitiveError<CmdType>),
}

#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum ValidateMethod {
    NoAuth,
    GSSAPI,
    UserNamePassword,
}

impl ToByte for ValidateMethod {
    fn to_byte(&self) -> u8 {
        (*self).clone().into()
    }
}

impl FromBytes for ValidateMethod {
    fn from_bytes(d: &mut Cursor<&[u8]>) -> Result<Self, Socks5Error> where Self: Sized {
        Ok(Self::try_from_primitive(get_u8(d)?)?)
    }
}

/// Response Code 
///
// RESPONSE 响应命令
// 0x00 代理服务器连接目标服务器成功
// 0x01 代理服务器故障
// 0x02 代理服务器规则集不允许连接
// 0x03 网络无法访问
// 0x04 目标服务器无法访问（主机名无效）
// 0x05 连接目标服务器被拒绝
// 0x06 TTL已过期
// 0x07 不支持的命令
// 0x08 不支持的目标服务器地址类型
// 0x09 - 0xFF 未分配
#[derive(Debug, PartialEq, Eq, FromPrimitive, IntoPrimitive, Copy, Clone)]
#[repr(u8)]
enum ResponseCode {
    Success = 0,
    ProxyError = 1,
    NotPermitted = 2,
    NetworkError = 3,
    TargetNotReachable = 4,
    TargetReject = 5,
    TTLExpired = 6,
    NotSupportCmd = 7,
    NotSupportAddrType = 8,
    #[num_enum(default)]
    Others = 9,
}

impl ToByte for ResponseCode {
    fn to_byte(&self) -> u8 {
        (*self).clone().into()
    }
}

impl FromBytes for ResponseCode {
    fn from_bytes(d: &mut Cursor<&[u8]>) -> Result<Self, Socks5Error> where Self: Sized {
        Ok(Self::from(get_u8(d)?))
    }
}

/// Command Type
/// 0x01 CONNECT 连接上游服务器
/// 0x02 BIND 绑定，客户端会接收来自代理服务器的链接，著名的FTP被动模式
/// 0x03 UDP ASSOCIATE UDP中继
#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum CmdType {
    CONNECT = 1,
    BIND = 2,
    UDP = 3,
}

impl ToByte for CmdType {
    fn to_byte(&self) -> u8 {
        (*self).clone().into()
    }
}

impl FromBytes for CmdType {
    fn from_bytes(d: &mut Cursor<&[u8]>) -> Result<Self, Socks5Error> where Self: Sized {
            Ok(Self::try_from_primitive(get_u8(d)?)?)
    }
}

#[derive(Debug)]
enum Addr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Domain(String),
}

impl ToBytes for Addr {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        match self {
            Addr::V4(a) => {
                data.push(1);
                data.append(&mut Vec::from(a.octets()));
            }
            Addr::V6(a) => {
                data.push(4);
                data.append(&mut Vec::from(a.octets()));
            },
            Addr::Domain(a) => {
                data.push(3);
                data.append(&mut Vec::from(a.as_bytes()));
            },
        }
        data
    }
}

fn get_u8(src: &mut Cursor<&[u8]>) -> Result<u8, Socks5Error> {
    if !src.has_remaining() {
        return Err(Socks5Error::EmptyData);
    }
    Ok(src.get_u8())
}

fn get_u16(src: &mut Cursor<&[u8]>) -> Result<u16, Socks5Error> {
    if !src.has_remaining() {
        return Err(Socks5Error::EmptyData);
    }
    Ok(src.get_u16())
}

fn get_u32(src: &mut Cursor<&[u8]>) -> Result<u32, Socks5Error> {
    if !src.has_remaining() {
        return Err(Socks5Error::EmptyData);
    }
    Ok(src.get_u32())
}

fn get_u128(src: &mut Cursor<&[u8]>) -> Result<u128, Socks5Error> {
    if !src.has_remaining() {
        return Err(Socks5Error::EmptyData);
    }
    Ok(src.get_u128())
}

impl FromBytes for Addr {
    fn from_bytes(d: &mut Cursor<&[u8]>) -> Result<Self, Socks5Error> where Self: Sized {
        let t = get_u8(d)?;
        match t {
            4 => {
                // V6
                Ok(Addr::V6(Ipv6Addr::from(get_u128(d)?)))
            },
            3 => {
                // domain
                let len = get_u8(d)?;
                let b = d.copy_to_bytes(len as usize);
                return Ok(Addr::Domain(String::from(from_utf8(&b)?)));
            },
            1| _ => {
                // V4
                Ok(Addr::V4(Ipv4Addr::from(get_u32(d)?)))
            },
        }
    }
}

#[derive(Debug)]
struct NegotiationReq {
    validate_methods: Vec<ValidateMethod>,
}

impl ToBytes for NegotiationReq {
    fn to_bytes(&self) -> Vec<u8> {
        let mut a = vec![5, self.validate_methods.len() as u8];
        for m in &self.validate_methods {
            a.push(m.to_byte());
        }
        a
    }
}

impl FromBytes for NegotiationReq {
    fn from_bytes(d: &mut Cursor<&[u8]>) -> Result<Self, Socks5Error> where Self: Sized {
        if get_u8(d)? != 5 {
            return Err(Socks5Error::WrongVer);
        }
        let mut req = NegotiationReq{
            validate_methods: Vec::new(),
        };
        for _ in 0..get_u8(d)? {
            req.validate_methods.push(ValidateMethod::from_bytes(d)?);
        }
        Ok(req)
    }
}

struct NegotiationResp {
    support_method: ValidateMethod,
}

impl FromBytes for NegotiationResp {
    fn from_bytes(d: &mut Cursor<&[u8]>) -> Result<Self, Socks5Error> where Self: Sized {
        if get_u8(d)? != 5 {
            return Err(Socks5Error::WrongVer);
        }
        Ok(NegotiationResp{
            support_method: ValidateMethod::from_bytes(d)?,
        })
    }
}

impl ToBytes for NegotiationResp {
    fn to_bytes(&self) -> Vec<u8> {
        vec![5, self.support_method.to_byte()]
    }
}

#[derive(Debug)]
struct Request {
    command: CmdType,
    dst_addr: Addr,
    dst_port: u16,
}

impl Request {
    pub fn get_addr(&self) -> SocketAddr {
        match &self.dst_addr {
            Addr::V4(d) => SocketAddr::V4(SocketAddrV4::new(*d, self.dst_port)),
            Addr::V6(d) => SocketAddr::V6(SocketAddrV6::new(*d, self.dst_port, 0, 0)),
            Addr::Domain(d) => {
                let mut addrs_iter = format!("{}:{}", d, self.dst_port).to_socket_addrs().unwrap();
                if let Some(addr) = addrs_iter.next() {
                    return addr;
                }
                panic!("cannot found ip");
            },
        }
    }
}

impl ToBytes for Request {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec![5, self.command.to_byte(), 0];
        data.append(&mut self.dst_addr.to_bytes());
        data.append(&mut Vec::from(self.dst_port.to_be_bytes()));
        data
    }
}

impl FromBytes for Request {
    fn from_bytes(d: &mut Cursor<&[u8]>) -> Result<Self, Socks5Error> where Self: Sized {
        if get_u8(d)? != 5 {
            return Err(Socks5Error::WrongVer);
        }
        let command = CmdType::from_bytes(d)?;
        d.advance(1);
        Ok(Request{
            command,
            dst_addr: Addr::from_bytes(d)?,
            dst_port: get_u16(d)?,
        })
    }
}

struct Response {
    code: ResponseCode,
    bind_addr: Addr,
    bind_port: u16, 
}

impl ToBytes for Response {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec![5, self.code.to_byte(), 0];
        data.append(&mut self.bind_addr.to_bytes());
        data.append(&mut Vec::from(self.bind_port.to_be_bytes()));
        data
    }
}

impl FromBytes for Response {
    fn from_bytes(d: &mut Cursor<&[u8]>) -> Result<Self, Socks5Error> where Self: Sized {
        if get_u8(d)? != 5 {
            return Err(Socks5Error::WrongVer);
        }
        Ok(Response{
            code: ResponseCode::from_bytes(d)?,
            bind_addr: Addr::from_bytes(d)?,
            bind_port: get_u16(d)?,
        })
    }
}

pub struct TransferConfig<'a> {
    pub from: &'a TcpStream,
    pub to: &'a TcpStream,
}

pub struct Server {
    port: u16,
}

impl Server {
    pub fn new(port: u16) -> Self {
        Server {
            port
        }
    }

    pub fn run(&self) -> Result<(), Socks5Error>{
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr)?;
        info!("runing socks5 server");
        for stream in listener.incoming() {
            let stream = stream?;
            thread::spawn(move || {
                Server::handle_connection(stream);
            });
        }
        Ok(())
    }

    fn handle_connection(stream: TcpStream) {
        let mut buf_reader = BufReader::new(stream.try_clone().unwrap());
        let mut buf_writer = BufWriter::new(stream.try_clone().unwrap());
        let mut buf = [0; 1024];

        // first: negotiation
        let r = buf_reader.read(&mut buf).unwrap();
        if r <= 0 {
            return;
        }
        let req = NegotiationReq::from_bytes(&mut Cursor::new(&buf[..r]));
        trace!("request: {:?}", req);

        let negotiation_resp = NegotiationResp{
            support_method: ValidateMethod::NoAuth,
        };
        let mut r = buf_writer.write(&negotiation_resp.to_bytes()).unwrap();
        buf_writer.flush().unwrap();
        trace!("response write len: {}", r);

        // second: receive connect
        let r = buf_reader.read(&mut buf).unwrap();
        trace!("original request: {:?}", &buf[..80]);
        let req2 = Request::from_bytes(&mut Cursor::new(&buf[..r])).unwrap();
        trace!("connect request: {:?}", req2);

        let mut resp = Response{
            code: ResponseCode::Success,
            bind_addr: Addr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            bind_port: 0,
        };
        let proxy_stream = TcpStream::connect_timeout(&req2.get_addr(), Duration::from_secs(2));
        if let Err(_) = proxy_stream {
            resp.code = ResponseCode::NetworkError;
        }
        let r = buf_writer.write(&resp.to_bytes()).unwrap();
        buf_writer.flush().unwrap();
        trace!("connect response len: {}", r);
        trace!("connect response byte: {:?}", &resp.to_bytes());
        if resp.code != ResponseCode::Success {
            error!("connect failed, socks5 terminate");
            return;
        }

        // final : transfer data
        let proxy_stream = proxy_stream.unwrap();
        let transfer_configs = vec![
            TransferConfig{from: &stream, to: &proxy_stream},
            TransferConfig{from: &proxy_stream, to: &stream},
        ];

        let mut handlers = Vec::new();
        for v in transfer_configs {
            let from = v.from.try_clone().unwrap();
            let to = v.to.try_clone().unwrap();
            handlers.push(thread::spawn( move || {
                transfer(from, to);
            }));
        }
        
        info!("build connection success with {}", req2.get_addr());
        for handler in handlers {
            handler.join().unwrap();
        }
    }
}

pub fn transfer(mut from: TcpStream, mut to: TcpStream) -> Result<(), Socks5Error> {
    let mut buf = [0; 1024 * 16];
    let mut exponent = Exponent::new(100, 1.3, 4);
    loop {
        let mut read_numbers: usize = 0;
        match from.read(&mut buf) {
            Err(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    error!("[tansfer] encounter Interrupted");
                    read_numbers = 0;
                } else {
                    return Err(Socks5Error::from(e));
                }
            }
            Ok(r) => {
                read_numbers = r;
            }   
        }
        trace!("[transfer] read {} bytes", read_numbers);
        if read_numbers == 0 {
            exponent.count();
            if exponent.terminate() {
                info!("terminate transfer");
                return Ok(());
            }
            sleep(time::Duration::from_millis(exponent.now()));
            continue;
        }
        exponent.reset();

        let res = to.write(&buf[..read_numbers])?;
        trace!("[transfer] write {} bytes", res);
        if res != read_numbers {
            error!("write != read, read: {}, write: {}", read_numbers, &res);
            return Err(Socks5Error::TransferFailed);
        }
    }
}
