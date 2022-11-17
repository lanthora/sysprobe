use std::{
    fs,
    io::{self},
    path::Path,
    sync::Arc,
};

use async_channel::Sender;
use async_channel::{bounded, Receiver};
use tokio::{net::UnixDatagram, sync::RwLock};
use tracing::{info, warn};

use crate::{
    handler::MsgHandler,
    msg::{Msg, MsgDataType, MsgIO},
};

use self::unix_channel::UnixSocketMsgIO;

pub mod unix_channel;

pub struct MsgWrap {
    pub msg: Msg,
    pub recv_addr: Option<String>,
}

pub struct Channel {
    pub msg_io: Arc<RwLock<dyn MsgIO>>,
    // only receive some type. if not the msg type, fill discard
    pub data_type: MsgDataType,
    pub channel_sender: Sender<MsgWrap>,
    pub channel_recever: Receiver<MsgWrap>,
    handler_worker_num: usize,
}

impl Channel {
    pub fn new_unix_channel(
        bind_file: &str,
        data_type: MsgDataType,
        chan_buf_size: usize,
        remove_when_exit: bool,
        handler_worker_num: usize,
    ) -> io::Result<Self> {
        info!("creating unix channel with file: {}", bind_file);
        if Path::new(bind_file).exists() && remove_when_exit {
            fs::remove_file(bind_file)?;
        }

        let socket = UnixDatagram::bind(bind_file)?;
        let (s, r) = bounded(chan_buf_size);

        Ok(Self {
            msg_io: Arc::new(RwLock::new(UnixSocketMsgIO::new(socket))),
            data_type,
            channel_sender: s,
            channel_recever: r,
            handler_worker_num,
        })
    }

    pub async fn run(&self) {
        for i in 0..self.handler_worker_num {
            info!("{:?} channel creating handler work: {}", self.data_type, i,);
            let handler = MsgHandler::from(self as &Channel);
            tokio::spawn(async move {
                handler.run().await;
            });
        }

        let m = self.msg_io.read().await;
        info!("{:?} channel running loop", self.data_type);
        loop {
            let mut msg = Msg::default();
            match m.recv_from(&mut msg).await {
                Ok(recv_addr) => {
                    if !(msg.data_type() == self.data_type) {
                        warn!(
                            "{:?} channel recv {:?} msg, the data type is not correspond",
                            self.data_type,
                            msg.data_type()
                        );
                        continue;
                    }
                    // send to handler
                    self.channel_sender
                        .send(MsgWrap { msg, recv_addr })
                        .await
                        .unwrap();
                }
                Err(e) => warn!("recv msg fail: {}", e),
            }
        }
    }
}
