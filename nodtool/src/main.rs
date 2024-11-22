mod argp_version;

// musl's allocator is very slow, so use mimalloc when targeting musl.
// Otherwise, use the system allocator to avoid extra code size.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::{env, error::Error, ffi::OsStr, fmt, path::PathBuf, str::FromStr};

use argp::{FromArgValue, FromArgs};
use enable_ansi_support::enable_ansi_support;
use nodtool::{run, SubCommand};
use supports_color::Stream;

#[derive(FromArgs, Debug)]
/// Tool for reading GameCube and Wii disc images.
struct TopLevel {
    #[argp(subcommand)]
    command: SubCommand,
    #[argp(option, short = 'C')]
    /// Change working directory.
    chdir: Option<PathBuf>,
    #[argp(option, short = 'L')]
    /// Minimum logging level. (Default: info)
    /// Possible values: error, warn, info, debug, trace
    log_level: Option<LogLevel>,
    #[allow(unused)]
    #[argp(switch, short = 'V')]
    /// Print version information and exit.
    version: bool,
    #[argp(switch)]
    /// Disable color output. (env: NO_COLOR)
    no_color: bool,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl FromStr for LogLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "error" => Self::Error,
            "warn" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => return Err(()),
        })
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        })
    }
}

impl FromArgValue for LogLevel {
    fn from_arg_value(value: &OsStr) -> Result<Self, String> {
        String::from_arg_value(value)
            .and_then(|s| Self::from_str(&s).map_err(|_| "Invalid log level".to_string()))
    }
}

// Duplicated from supports-color so we can check early.
fn env_no_color() -> bool {
    match env::var("NO_COLOR").as_deref() {
        Ok("") | Ok("0") | Err(_) => false,
        Ok(_) => true,
    }
}

fn main() {
    let args: TopLevel = argp_version::from_env();
    let use_colors = if args.no_color || env_no_color() {
        false
    } else {
        // Try to enable ANSI support on Windows.
        let _ = enable_ansi_support();
        // Disable isatty check for supports-color. (e.g. when used with ninja)
        env::set_var("IGNORE_IS_TERMINAL", "1");
        supports_color::on(Stream::Stdout).is_some_and(|c| c.has_basic)
    };

    #[cfg(feature = "tracy")]
    {
        use tracing_subscriber::layer::SubscriberExt;
        tracing::subscriber::set_global_default(
            tracing_subscriber::registry().with(tracing_tracy::TracyLayer::default()),
        )
        .expect("setup tracy layer");
    }

    #[cfg(not(feature = "tracy"))]
    {
        use tracing::level_filters::LevelFilter;
        use tracing_subscriber::EnvFilter;
        let format = tracing_subscriber::fmt::format()
            .with_ansi(use_colors)
            .with_target(false)
            .without_time();
        let builder = tracing_subscriber::fmt().event_format(format);
        if let Some(level) = args.log_level {
            builder
                .with_max_level(match level {
                    LogLevel::Error => LevelFilter::ERROR,
                    LogLevel::Warn => LevelFilter::WARN,
                    LogLevel::Info => LevelFilter::INFO,
                    LogLevel::Debug => LevelFilter::DEBUG,
                    LogLevel::Trace => LevelFilter::TRACE,
                })
                .init();
        } else {
            builder
                .with_env_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                )
                .init();
        }
    }

    let mut result = Ok(());
    if let Some(dir) = &args.chdir {
        result = env::set_current_dir(dir).map_err(|e| {
            nod::Error::Io(format!("Failed to change working directory to '{}'", dir.display()), e)
        });
    }
    result = result.and_then(|_| run(args.command));
    if let Err(e) = result {
        eprintln!("Failed: {}", e);
        if let Some(source) = e.source() {
            eprintln!("Caused by: {}", source);
        }
        std::process::exit(1);
    }
}
