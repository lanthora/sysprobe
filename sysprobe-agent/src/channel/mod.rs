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
    msg::{Msg, MsgIO},
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
    pub channel_sender: Sender<MsgWrap>,
    pub channel_recever: Receiver<MsgWrap>,
    handler_worker_num: usize,
}

impl Channel {
    pub fn new_unix_channel(
        bind_file: &str,
        chan_buf_size: usize,
        handler_worker_num: usize,
    ) -> io::Result<Self> {
        info!("creating unix channel with file: {}", bind_file);
        if Path::new(bind_file).exists() {
            fs::remove_file(bind_file)?;
        }

        let socket = UnixDatagram::bind(bind_file)?;
        let (s, r) = bounded(chan_buf_size);

        Ok(Self {
            msg_io: Arc::new(RwLock::new(UnixSocketMsgIO::new(socket))),
            channel_sender: s,
            channel_recever: r,
            handler_worker_num,
        })
    }

    pub async fn run(&self) {
        for i in 0..self.handler_worker_num {
            info!("channel creating handler work: {}", i,);
            let handler = MsgHandler::from(self as &Channel);
            tokio::spawn(async move {
                handler.run(i).await;
            });
        }

        let m = self.msg_io.read().await;
        info!("channel running loop");
        loop {
            let mut msg = Msg::default();
            match m.recv_from(&mut msg).await {
                Ok(recv_addr) => {
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
