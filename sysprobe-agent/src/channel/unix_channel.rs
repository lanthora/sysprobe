use std::{
    io::{self, ErrorKind},
    ptr::copy_nonoverlapping,
};

use async_trait::async_trait;
use tokio::net::UnixDatagram;

use crate::msg::{Msg, MsgIO, MsgType, MAX_MSG_SIZE};

pub const CONTROL_CHAN_FILE_PATH: &'static str = "/var/run/sysprobe-ctl.sock";
pub const DATA_CHAN_FILE_PATH: &'static str = "/var/run/sysprobe-data.sock";
pub struct UnixSocketMsgIO {
    socket: UnixDatagram,
}

#[async_trait]
impl MsgIO for UnixSocketMsgIO {
    async fn send_to(&self, msg: &Msg, addr: String) -> io::Result<()> {
        let data = unsafe { msg.to_c_bytes() };
        self.socket.send_to(data, addr.as_str()).await?;
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
    use tempfile::tempdir;
    use tokio::net::UnixDatagram;

    use crate::msg::{
        io_event::{CtlIoEvent, IO_EVENT_OTHERS_ENABLE_TRUE},
        Msg, MsgIO,
    };

    use super::UnixSocketMsgIO;

    #[tokio::test]
    async fn test_unix() {
        let tmp = tempdir().unwrap();
        let socket_path = tmp.path().join("socket");

        let sock = UnixSocketMsgIO::new(UnixDatagram::bind(&socket_path).unwrap());

        let mut msg = CtlIoEvent::default();
        msg.tgid = 0;
        msg.io_event_others_enabled = IO_EVENT_OTHERS_ENABLE_TRUE;
        msg.ret = -1;

        sock.send_to(
            &Msg {
                io_event: msg.clone(),
            },
            String::from(socket_path.to_str().unwrap()),
        )
        .await
        .unwrap();

        let mut recv_msg = &mut Msg::default();
        sock.recv_from(&mut recv_msg).await.unwrap();
        unsafe {
            assert_eq!(msg, recv_msg.io_event);
        }
    }
}
