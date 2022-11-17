pub mod io_event;

use async_trait::async_trait;
use num_enum::FromPrimitive;
use std::io;
use std::mem::size_of;
use std::ptr::slice_from_raw_parts;
use tracing::warn;

use self::io_event::IoEvent;

pub const MAX_MSG_SIZE: usize = 1500;

#[async_trait]
pub trait MsgIO: Send + Sync {
    async fn send_to(&self, msg: &Msg, addr: Option<String>) -> io::Result<()>;
    async fn recv_from(&self, msg: &mut Msg) -> io::Result<Option<String>>;
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromPrimitive, num_enum::Default)]
pub enum MsgType {
    #[num_enum(default)]
    CtlEventUnspec = 0,
    CtlEventIoEvent = 1,
}

#[repr(C)]
#[repr(packed(1))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// only use for init msg
pub struct NullMsg {
    typ: u32,
}
#[async_trait]
impl MsgInterface for NullMsg {
    async fn handle_msg(&mut self) -> Option<Msg> {
        warn!("handle with null msg, maybe the msg type is unknown");
        None
    }

    fn data_type(&self) -> MsgDataType {
        MsgDataType::DataMsg
    }
}

/*
    control msg or data msg
        control msg recv from user and need send back to control channel.
        data msg recv from user and write to db directly.
*/
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum MsgDataType {
    ControlMsg,
    DataMsg,
}

macro_rules! all_msg {
    ($( $name:ident : $type:ident : $msg:ident ),+$(,)?) => {
        #[repr(C)]
        #[repr(packed(1))]
        pub union Msg {
            $(
                pub $name:$msg,
            )+
        }

        impl Msg{
            pub fn default() -> Self {
                Self{
                    null_msg: NullMsg{typ:0},
                }
            }

            pub fn msg_type(&self) -> MsgType {
                unsafe{
                    MsgType::from(*(self as * const Msg as * const u32))
                }
            }

            pub fn data_type(&self) -> MsgDataType {
                unsafe{
                    match self.msg_type(){
                        $(
                            MsgType::$type=>self.$name.data_type(),
                        )+
                    }
                }
            }

            pub fn size(&self) -> usize {
                let typ = self.msg_type();
                typ.msg_size()
            }

            pub unsafe fn to_c_bytes(&self) -> &[u8] {
                let ptr = self as *const Msg as *const u8;
                &*slice_from_raw_parts(ptr, self.size())
            }

            pub async fn handle(& mut self) -> Option<Msg> {
                let typ = self.msg_type();
                match typ {
                    $(
                        MsgType::$type => unsafe {self.$name.handle_msg().await},
                    )+
                }
            }
        }

        impl MsgType {
            pub fn msg_size(&self) -> usize{
                match self {
                    $(
                        MsgType::$type => size_of::<$msg>(),
                    )+
                }
            }
        }

    };
}

/*
    msg macro, format:
        union struct name : enum MsgType : msg struct
*/
all_msg!(
    io_event: CtlEventIoEvent: IoEvent,
    null_msg: CtlEventUnspec: NullMsg,
);

#[async_trait]
pub(crate) trait MsgInterface {
    // data msg return None, control msg return handle resule.
    async fn handle_msg(&mut self) -> Option<Msg>;
    // async fn handle_msg(&mut self,);
    fn data_type(&self) -> MsgDataType;
}
