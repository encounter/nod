use argp::FromArgs;

pub mod cmd;
pub(crate) mod util;

// Re-export nod
pub use nod;

#[derive(FromArgs, Debug)]
#[argp(subcommand)]
pub enum SubCommand {
    Convert(cmd::convert::Args),
    Dat(cmd::dat::Args),
    Extract(cmd::extract::Args),
    Gen(cmd::gen::Args),
    GenTest(cmd::gen::TestArgs),
    Info(cmd::info::Args),
    Verify(cmd::verify::Args),
}

pub fn run(command: SubCommand) -> nod::Result<()> {
    match command {
        SubCommand::Convert(c_args) => cmd::convert::run(c_args),
        SubCommand::Dat(c_args) => cmd::dat::run(c_args),
        SubCommand::Extract(c_args) => cmd::extract::run(c_args),
        SubCommand::Gen(c_args) => cmd::gen::run(c_args),
        SubCommand::GenTest(c_args) => cmd::gen::run_test(c_args),
        SubCommand::Info(c_args) => cmd::info::run(c_args),
        SubCommand::Verify(c_args) => cmd::verify::run(c_args),
    }
}
