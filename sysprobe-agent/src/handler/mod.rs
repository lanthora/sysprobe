use core::panic;
use std::sync::Arc;

use async_channel::Receiver;
use tokio::sync::RwLock;
use tracing::info;
use tracing::warn;

use crate::{
    channel::{Channel, MsgWrap},
    msg::{MsgDataType, MsgIO},
};

pub struct MsgHandler {
    // use for control msg send back
    msg_io: Arc<RwLock<dyn MsgIO>>,
    chan_queue: Receiver<MsgWrap>,
    data_type: MsgDataType,
}

impl From<&Channel> for MsgHandler {
    fn from(c: &Channel) -> Self {
        Self {
            msg_io: c.msg_io.clone(),
            chan_queue: c.channel_recever.clone(),
            data_type: c.data_type,
        }
    }
}

impl MsgHandler {
    /*
        recv from channel, and process msg.
        if it is control msg handler, send back to the msgIO.
    */
    pub async fn run(&self) {
        let msg_sender = self.msg_io.read().await;
        info!("{:?} handler running loop", self.data_type);
        // recv msg from channel
        while let Ok(MsgWrap { mut msg, recv_addr }) = self.chan_queue.recv().await {
            // handle msg
            let r = msg.handle().await;
            if self.data_type == MsgDataType::ControlMsg {
                if let Some(res) = r {
                    if let Err(e) = msg_sender.send_to(&res, recv_addr).await {
                        warn!("send msg fail: {}", e);
                    };
                } else {
                    warn!("{:?} msg not return msg after process", msg.data_type());
                }
            }
        }

        panic!("queue close unexpectly");
    }
}
