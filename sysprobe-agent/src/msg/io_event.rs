use async_trait::async_trait;
use tracing::info;

use super::{Msg, MsgDataType, MsgInterface, MsgType};

/*
struct ctl_io_event {
    unsigned int type; // always CTL_EVENT_IO_EVENT
    int tgid;
    int io_event_others_enabled;
    int ret;
} __attribute__((__packed__));

*/
#[repr(C)]
#[repr(packed(1))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoEvent {
    pub typ: MsgType,
    pub tgid: i32,
    pub io_event_others_enabled: i32,
    pub ret: i32,
}

impl Default for IoEvent {
    fn default() -> Self {
        Self {
            typ: MsgType::CtlEventIoEvent,
            tgid: 0,
            io_event_others_enabled: 0,
            ret: 0,
        }
    }
}

#[async_trait]
impl MsgInterface for IoEvent {
    async fn handle_msg(&mut self) -> Option<Msg> {
        // TODO handle msg
        let mut s = self.clone();
        s.ret = 1;
        info!("handle io event: {:?}", self);
        return Some(Msg { io_event: s });
    }

    fn data_type(&self) -> MsgDataType {
        MsgDataType::ControlMsg
    }
}
