use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "micromail",
    about = "Lightweight outbound SMTP relay and CLI mail sender",
    disable_version_flag = true
)]
pub struct Cli {
    /// Config directory [default: ~/.config/micromail]
    #[arg(short, long, global = true, value_name = "DIR")]
    pub config: Option<PathBuf>,

    /// Verbose logging to the console
    #[arg(short = 'v', long, global = true, action = clap::ArgAction::SetTrue)]
    pub verbose: bool,

    /// Print version
    #[arg(short = 'V', long, action = clap::ArgAction::SetTrue)]
    pub version: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the SMTP + REST relay daemon (default)
    Serve,
    /// Send an email synchronously without starting a daemon
    Send(Box<SendArgs>),
}

#[derive(Debug, Args)]
pub struct SendArgs {
    /// Envelope sender address
    #[arg(long)]
    pub from: String,

    /// Recipient address (repeatable)
    #[arg(long, required = true)]
    pub to: Vec<String>,

    /// CC recipient (repeatable)
    #[arg(long)]
    pub cc: Vec<String>,

    /// BCC recipient (repeatable)
    #[arg(long)]
    pub bcc: Vec<String>,

    /// Subject line
    #[arg(long)]
    pub subject: Option<String>,

    /// Plain-text body
    #[arg(long)]
    pub text: Option<String>,

    /// Read the plain-text body from a file
    #[arg(long)]
    pub text_file: Option<PathBuf>,

    /// HTML body
    #[arg(long)]
    pub html: Option<String>,

    /// Read the HTML body from a file
    #[arg(long)]
    pub html_file: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_to_serve() {
        let cli = Cli::try_parse_from(["micromail"]).unwrap();
        assert!(cli.command.is_none());
        assert!(!cli.version);
    }

    #[test]
    fn cli_parses_version_flag() {
        let cli = Cli::try_parse_from(["micromail", "--version"]).unwrap();
        assert!(cli.version);
    }

    #[test]
    fn cli_parses_send_args() {
        let cli = Cli::try_parse_from([
            "micromail",
            "send",
            "--from",
            "a@b.com",
            "--to",
            "c@d.com",
            "--to",
            "e@f.com",
            "--subject",
            "Hi",
            "--text",
            "hello",
        ])
        .unwrap();
        match cli.command.unwrap() {
            Command::Send(args) => {
                assert_eq!(args.from, "a@b.com");
                assert_eq!(args.to, vec!["c@d.com".to_string(), "e@f.com".to_string()]);
                assert_eq!(args.subject.as_deref(), Some("Hi"));
                assert_eq!(args.text.as_deref(), Some("hello"));
            }
            _ => panic!("expected send command"),
        }
    }

    #[test]
    fn cli_accepts_config_flag() {
        let cli = Cli::try_parse_from(["micromail", "-c", "/tmp/mm", "serve"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/mm")));
    }

    #[test]
    fn cli_defaults_to_user_config_dir() {
        let cli = Cli::try_parse_from(["micromail"]).unwrap();
        assert_eq!(cli.config, None);
        let def = crate::config::default_config_dir();
        assert!(def.ends_with("micromail"));
    }
}
