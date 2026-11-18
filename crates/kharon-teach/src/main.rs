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
    // `run` has already closed the browser and removed its profile, whatever ended the session
    // (the window, a confirm, Ctrl-C or SIGTERM). What is left is the blocking thread of the
    // end-prompt read, which cannot be cancelled and would hold the process until Enter, so
    // the runtime is shut down without waiting for it.
    {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
    }
    runtime.shutdown_background();
    exit.into()
}
