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
    /// Get or set configuration values
    Config(Box<ConfigArgs>),
    /// Manage SMTP submission users
    User(Box<UserArgs>),
    /// Manage REST API bearer tokens
    Token(Box<TokenArgs>),
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

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the effective value of a key (merged config; secrets are redacted)
    Get {
        /// Dotted configuration key, e.g. "hostname" or "smtp.listen"
        key: String,
    },
    /// Set a key and persist it to <config dir>/config.toml
    Set {
        /// Dotted configuration key, e.g. "hostname" or "retry.max_attempts"
        key: String,
        /// New scalar value ("true"/"false", numbers, or text)
        value: String,
    },
}

#[derive(Debug, Args)]
pub struct UserArgs {
    #[command(subcommand)]
    pub command: UserCommand,
}

#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// List SMTP users and how their passwords are stored
    List,
    /// Add a user (prompts for a password; stores its Argon2 hash)
    Add {
        username: String,
        #[command(flatten)]
        input: PasswordInput,
    },
    /// Replace an existing user's password
    Passwd {
        username: String,
        #[command(flatten)]
        input: PasswordInput,
    },
    /// Remove a user
    Remove { username: String },
}

/// Ways to supply a password for `user add` / `user passwd`.
#[derive(Debug, Args)]
#[command(flatten_help = true)]
pub struct PasswordInput {
    /// Supply the password inline (visible in shell history and process lists)
    #[arg(long, conflicts_with_all = &["password_stdin", "password_file"])]
    pub password: Option<String>,
    /// Read the password from stdin
    #[arg(long, conflicts_with_all = &["password", "password_file"])]
    pub password_stdin: bool,
    /// Read the password from a file
    #[arg(long, value_name = "PATH", conflicts_with_all = &["password", "password_stdin"])]
    pub password_file: Option<PathBuf>,
    /// Store the password as plaintext ("literal:") instead of an Argon2 hash
    #[arg(long)]
    pub literal: bool,
}

impl PasswordInput {
    /// Map the supplied flags to a secret source. No flags = interactive prompt.
    pub fn source(&self) -> SecretSource {
        if let Some(pw) = &self.password {
            SecretSource::Inline(pw.clone())
        } else if self.password_stdin {
            SecretSource::Stdin
        } else if let Some(path) = &self.password_file {
            SecretSource::File(path.clone())
        } else {
            SecretSource::Prompt
        }
    }
}

#[derive(Debug, Args)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub command: TokenCommand,
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// List API tokens and how they are stored
    List,
    /// Add a named API token
    Add {
        name: String,
        #[command(flatten)]
        input: TokenInput,
    },
    /// Replace an existing API token
    Rotate {
        name: String,
        #[command(flatten)]
        input: TokenInput,
    },
    /// Remove an API token
    Remove { name: String },
}

/// Ways to supply a token for `token add` / `token rotate`.
#[derive(Debug, Args)]
#[command(flatten_help = true)]
pub struct TokenInput {
    /// Generate a random token, print it once, store only its Argon2 hash
    #[arg(long, conflicts_with_all = &["token", "token_stdin", "token_file", "literal"])]
    pub generate: bool,
    /// Supply the token inline (visible in shell history and process lists)
    #[arg(long, conflicts_with_all = &["generate", "token_stdin", "token_file"])]
    pub token: Option<String>,
    /// Read the token from stdin
    #[arg(long, conflicts_with_all = &["generate", "token", "token_file"])]
    pub token_stdin: bool,
    /// Read the token from a file
    #[arg(long, value_name = "PATH", conflicts_with_all = &["generate", "token", "token_stdin"])]
    pub token_file: Option<PathBuf>,
    /// Store the supplied token as plaintext ("literal:") instead of hashing
    #[arg(long)]
    pub literal: bool,
}

impl TokenInput {
    /// Map the supplied flags to a secret source. No flags = interactive prompt.
    pub fn source(&self) -> SecretSource {
        if self.generate {
            SecretSource::Generate
        } else if let Some(tok) = &self.token {
            SecretSource::Inline(tok.clone())
        } else if self.token_stdin {
            SecretSource::Stdin
        } else if let Some(path) = &self.token_file {
            SecretSource::File(path.clone())
        } else {
            SecretSource::Prompt
        }
    }
}

/// Where a new secret comes from when adding or rotating credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSource {
    /// Value supplied directly on the command line.
    Inline(String),
    /// Read one line from stdin.
    Stdin,
    /// Read the first line of a file.
    File(PathBuf),
    /// Hidden interactive prompt with confirmation.
    Prompt,
    /// Generate a random token (API tokens only).
    Generate,
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

    #[test]
    fn parses_config_get_and_set() {
        let cli = Cli::try_parse_from(["micromail", "config", "get", "smtp.listen"]).unwrap();
        match cli.command.unwrap() {
            Command::Config(args) => match args.command {
                ConfigCommand::Get { key } => assert_eq!(key, "smtp.listen"),
                _ => panic!("expected config get"),
            },
            _ => panic!("expected config command"),
        }

        let cli =
            Cli::try_parse_from(["micromail", "config", "set", "hostname", "mail.example.com"])
                .unwrap();
        match cli.command.unwrap() {
            Command::Config(args) => match args.command {
                ConfigCommand::Set { key, value } => {
                    assert_eq!(key, "hostname");
                    assert_eq!(value, "mail.example.com");
                }
                _ => panic!("expected config set"),
            },
            _ => panic!("expected config command"),
        }
    }

    #[test]
    fn parses_user_add_with_inline_password() {
        let cli = Cli::try_parse_from(["micromail", "user", "add", "app", "--password", "hunter2"])
            .unwrap();
        match cli.command.unwrap() {
            Command::User(args) => match args.command {
                UserCommand::Add { username, input } => {
                    assert_eq!(username, "app");
                    assert_eq!(input.source(), SecretSource::Inline("hunter2".into()));
                    assert!(!input.literal);
                }
                _ => panic!("expected user add"),
            },
            _ => panic!("expected user command"),
        }
    }

    #[test]
    fn user_password_sources_are_mutually_exclusive() {
        let err = Cli::try_parse_from([
            "micromail",
            "user",
            "add",
            "app",
            "--password",
            "x",
            "--password-stdin",
        ])
        .unwrap_err();
        assert!(err.kind() == clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn user_without_secret_flags_means_prompt() {
        let cli = Cli::try_parse_from(["micromail", "user", "passwd", "app"]).unwrap();
        match cli.command.unwrap() {
            Command::User(args) => match args.command {
                UserCommand::Passwd { username, input } => {
                    assert_eq!(username, "app");
                    assert_eq!(input.source(), SecretSource::Prompt);
                }
                _ => panic!("expected user passwd"),
            },
            _ => panic!("expected user command"),
        }
    }

    #[test]
    fn parses_token_add_generate() {
        let cli = Cli::try_parse_from(["micromail", "token", "add", "ci", "--generate"]).unwrap();
        match cli.command.unwrap() {
            Command::Token(args) => match args.command {
                TokenCommand::Add { name, input } => {
                    assert_eq!(name, "ci");
                    assert_eq!(input.source(), SecretSource::Generate);
                }
                _ => panic!("expected token add"),
            },
            _ => panic!("expected token command"),
        }
    }

    #[test]
    fn token_generate_conflicts_with_literal() {
        let err =
            Cli::try_parse_from(["micromail", "token", "add", "ci", "--generate", "--literal"])
                .unwrap_err();
        assert!(err.kind() == clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn parses_remove_commands() {
        let cli = Cli::try_parse_from(["micromail", "user", "remove", "app"]).unwrap();
        match cli.command.unwrap() {
            Command::User(args) => match args.command {
                UserCommand::Remove { username } => assert_eq!(username, "app"),
                _ => panic!("expected user remove"),
            },
            _ => panic!("expected user command"),
        }

        let cli = Cli::try_parse_from(["micromail", "token", "remove", "ci"]).unwrap();
        match cli.command.unwrap() {
            Command::Token(args) => match args.command {
                TokenCommand::Remove { name } => assert_eq!(name, "ci"),
                _ => panic!("expected token remove"),
            },
            _ => panic!("expected token command"),
        }
    }
}
