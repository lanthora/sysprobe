use async_channel::Receiver;
use core::panic;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::UnixDatagram;
use tokio::sync::RwLock;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::channel::unix_channel::UnixSocketMsgIO;
use crate::channel::unix_channel::CONTROL_CHAN_FILE_PATH;
use crate::msg::Msg;
use crate::{
    channel::{Channel, MsgWrap},
    msg::MsgIO,
};

pub struct MsgHandler {
    chan_queue: Receiver<MsgWrap>,
    ctl_chan: Arc<RwLock<dyn MsgIO>>,
}

impl From<&Channel> for MsgHandler {
    fn from(c: &Channel) -> Self {
        let tmp = tempdir().unwrap();
        let socket_path = tmp.path().join("socket");
        let ctl_chan = UnixSocketMsgIO::new(UnixDatagram::bind(socket_path).unwrap());
        Self {
            chan_queue: c.channel_recever.clone(),
            ctl_chan: Arc::new(RwLock::new(ctl_chan)),
        }
    }
}

impl MsgHandler {
    /*
        recv from channel, and process msg.
        if msg handle return not None, send it to control channel.
    */
    pub async fn run(&self, worker_num: usize) {
        let ctl_chan = self.ctl_chan.clone();
        // span future to handle control chan receive msg
        tokio::spawn(async move {
            let ctl_chan_recv = ctl_chan.read().await;
            let mut msg = Msg::default();
            // TODO handle ctl chan msg
            info!(
                "handler {} control channel receiver running loop",
                worker_num
            );
            loop {
                if let Err(err) = ctl_chan_recv.recv_from(&mut msg).await {
                    error!("recv from ctl sock fail: {}", err);
                } else {
                    info!("ctl channel resp {:?} msg", msg.msg_type());
                }
            }
        });

        let ctl_chan_sender = self.ctl_chan.read().await;
        info!("handler {} running loop", worker_num);
        // recv msg from data channel
        while let Ok(MsgWrap { mut msg, .. }) = self.chan_queue.recv().await {
            // handle msg
            let res = msg.handle().await;
            if let Some(r) = res {
                // send to control channel
                if let Err(e) = ctl_chan_sender
                    .send_to(&r, String::from(CONTROL_CHAN_FILE_PATH))
                    .await
                {
                    warn!("send msg fail: {}", e);
                };
            }
        }

        panic!("channel queue close unexpectly");
    }
}
