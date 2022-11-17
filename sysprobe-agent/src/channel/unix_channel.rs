use std::{
    io::{self, ErrorKind},
    ptr::copy_nonoverlapping,
};

use async_trait::async_trait;
use tokio::net::UnixDatagram;

use crate::msg::{Msg, MsgIO, MsgType, MAX_MSG_SIZE};

pub const CONTROL_CHAN_FILE_PATH: &'static str = "/var/run/sysprobec-agent-ctr.sock";
pub const DATA_CHAN_FILE_PATH: &'static str = "/var/run/sysprobe-agent-data.sock";
pub struct UnixSocketMsgIO {
    socket: UnixDatagram,
}

#[async_trait]
impl MsgIO for UnixSocketMsgIO {
    async fn send_to(&self, msg: &Msg, addr: Option<String>) -> io::Result<()> {
        let data = unsafe { msg.to_c_bytes() };
        if let Some(a) = addr {
            self.socket.send_to(data, a.as_str()).await?;
        } else {
            return Err(io::Error::new(
                ErrorKind::Other,
                "send to unix socket with None addr",
            ));
        }

        Ok(())
    }

    async fn recv_from(&self, msg: &mut Msg) -> io::Result<Option<String>> {
        let mut buf = [0 as u8; MAX_MSG_SIZE];
        let (size, addr) = self.socket.recv_from(&mut buf).await?;
        let path = if let Some(a) = addr.as_pathname() {
            a.to_string_lossy().to_string()
        } else {
            return Err(io::Error::new(
                ErrorKind::Other,
                "unix recv can not get recv path",
            ));
        };

        if size < 4 {
            return Err(io::Error::new(ErrorKind::Other, "recv unexpect data"));
        }

        // read the first 4 byte as u32 to determine type
        let typ = unsafe { *((&buf).as_ptr() as *const u32) };
        let msg_size = MsgType::from(typ).msg_size();
        if size != msg_size {
            return Err(io::Error::new(
                ErrorKind::Other,
                "recv size not equal to msg size",
            ));
        }

        unsafe {
            copy_nonoverlapping(buf.as_ptr(), msg as *mut Msg as *mut u8, msg_size);
        }
        Ok(Some(path))
    }
}

impl UnixSocketMsgIO {
    pub fn new(socket: UnixDatagram) -> Self {
        Self { socket }
    }
}

#[cfg(test)]
mod test {

    use tokio::net::UnixDatagram;

    use crate::msg::{io_event::IoEvent, Msg, MsgIO};

    use super::UnixSocketMsgIO;

    #[tokio::test]
    async fn test_unix() {
        let file = "/tmp/a";

        let sock = UnixSocketMsgIO::new(UnixDatagram::bind(file).unwrap());

        let mut msg = IoEvent::default();
        msg.tgid = 999;
        msg.io_event_others_enabled = 998;
        msg.ret = 997;

        sock.send_to(
            &Msg {
                io_event: msg.clone(),
            },
            Some(String::from(file)),
        )
        .await
        .unwrap();

        let mut recv_msg = &mut Msg {
            io_event: IoEvent::default(),
        };
        sock.recv_from(&mut recv_msg).await.unwrap();
        unsafe {
            assert_eq!(msg, recv_msg.io_event);
        }
    }
}
