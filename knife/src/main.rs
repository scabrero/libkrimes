use clap::{Parser, Subcommand};
use opt::{AcquireCredsOpt, CcacheDumpOpt, InitCredsOpt};

mod ccache;
mod getcreds;
mod initcreds;
mod opt;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    commands: KnifeCommands,
}

#[derive(Debug, Clone, Subcommand)]
enum KnifeCommands {
    Init(InitCredsOpt),
    Acquire(AcquireCredsOpt),
    Ccache {
        #[clap(subcommand)]
        command: CcacheOpt,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum CcacheOpt {
    Dump(CcacheDumpOpt),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), ()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.commands {
        KnifeCommands::Ccache { command } => match command {
            CcacheOpt::Dump(opt) => ccache::dump(opt),
        },
        KnifeCommands::Init(opt) => initcreds::acquire(opt).await,
        KnifeCommands::Acquire(opt) => getcreds::acquire(opt).await,
    }
    Ok(())
}
