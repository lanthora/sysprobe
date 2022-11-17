use std::io;

use channel::{unix_channel::DATA_CHAN_FILE_PATH, Channel};
use clap::Parser;
use cmd::{Cmd, SubCommands};
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
                .worker_threads(max_thread.unwrap_or(1).min(num_cpus::get()).max(1))
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
        SubCommands::Run { worker_num, .. } => {
            let data_chan = Channel::new_unix_channel(
                DATA_CHAN_FILE_PATH,
                500,
                worker_num.unwrap_or(2).min(16).max(1),
            )?;

            // run data channel
            data_chan.run().await;
        }
    }
    Ok(())
}
