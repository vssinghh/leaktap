use clap::Parser;
use leaktap::cli::Cli;
use std::process;

fn main() {
    let cli = Cli::parse();
    let code = leaktap::execute(cli);
    process::exit(code);
}
