use clap::Parser;
use kharon_teach::cli::Cli;
use std::process::ExitCode;

/// The one line a panic prints: where it happened and nothing from its message. The message of
/// a panic can hold a slice of whatever text the program was handling.
fn panic_line(file: &str, line: u32) -> String {
    format!("kharon-teach: internal error at {file}:{line}")
}

fn main() -> ExitCode {
    // First of all, so that no panic ever reaches the default hook, which prints its payload.
    std::panic::set_hook(Box::new(|info| match info.location() {
        Some(l) => eprintln!("{}", panic_line(l.file(), l.line())),
        None => eprintln!("kharon-teach: internal error"),
    }));
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

#[cfg(test)]
mod tests {
    use super::panic_line;

    #[test]
    fn the_panic_line_names_the_place_and_nothing_else() {
        assert_eq!(
            panic_line("src/strip.rs", 134),
            "kharon-teach: internal error at src/strip.rs:134"
        );
    }
}
