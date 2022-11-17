use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about, long_about = None)]
pub struct Cmd {
    #[command(subcommand)]
    pub command: SubCommands,
}

#[derive(Subcommand)]
pub enum SubCommands {
    Run {
        #[arg(long)]
        data_chan_sock: Option<String>,
        #[arg(long)]
        ctr_chan_sock: Option<String>,
        #[arg(long)]
        delete_when_file_exist: Option<bool>,
        #[arg(long)]
        worker: Option<usize>,
        #[arg(long)]
        max_thread: Option<usize>,
    },
}
