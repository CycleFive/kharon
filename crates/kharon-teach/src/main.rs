use clap::Parser;
use kharon_teach::cli::Cli;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("kharon-teach: cannot start: {e}");
            return ExitCode::from(1);
        }
    };
    let exit = runtime.block_on(kharon_teach::run(
        cli,
        tokio::io::BufReader::new(tokio::io::stdin()),
        std::io::stdout(),
        std::io::stderr(),
    ));
    exit.into()
}
