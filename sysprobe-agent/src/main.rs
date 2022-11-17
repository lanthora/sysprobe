use std::io;

use channel::{
    unix_channel::{CONTROL_CHAN_FILE_PATH, DATA_CHAN_FILE_PATH},
    Channel,
};
use clap::Parser;
use cmd::{Cmd, SubCommands};
use msg::MsgDataType;
use tokio::runtime;
use tracing::error;
use tracing::subscriber::set_global_default;
mod channel;
mod cmd;
mod handler;
mod msg;

fn main() {
    let s = tracing_subscriber::fmt().finish();
    set_global_default(s).unwrap();
    let cmd = Cmd::parse();
    match &cmd.command {
        SubCommands::Run { max_thread, .. } => {
            let rt = runtime::Builder::new_multi_thread()
                .worker_threads(max_thread.unwrap_or(2))
                .enable_all()
                .build()
                .unwrap();
            if let Err(e) = rt.block_on(async_main(cmd.command.into())) {
                error!("{}", e);
            }
        }
    };
}

async fn async_main(cmd: SubCommands) -> io::Result<()> {
    match cmd {
        SubCommands::Run {
            data_chan_sock,
            ctr_chan_sock,
            worker,
            delete_when_file_exist,
            ..
        } => {
            let data_sock = if let Some(d) = &data_chan_sock {
                d.as_str()
            } else {
                DATA_CHAN_FILE_PATH
            };

            let ctr_sock = if let Some(d) = &ctr_chan_sock {
                d.as_str()
            } else {
                CONTROL_CHAN_FILE_PATH
            };
            let data_chan = Channel::new_unix_channel(
                data_sock,
                MsgDataType::DataMsg,
                100,
                delete_when_file_exist.unwrap_or_default(),
                1,
            )?;
            let ctr_chan = Channel::new_unix_channel(
                ctr_sock,
                MsgDataType::ControlMsg,
                100,
                delete_when_file_exist.unwrap_or_default(),
                worker.unwrap_or(2),
            )?;

            // spawn a future to run control channel
            tokio::spawn(async move {
                ctr_chan.run().await;
            });

            // run data channel
            data_chan.run().await;
        }
    }
    Ok(())
}
