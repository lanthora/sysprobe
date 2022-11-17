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
        worker_num: Option<usize>,
        #[arg(long)]
        max_thread: Option<usize>,
    },
}
