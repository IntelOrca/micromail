pub mod api;
pub mod cli;
pub mod config;
pub mod dkim;
pub mod dns;
pub mod error;
pub mod manage;
pub mod message;
pub mod queue;
pub mod secret;
pub mod send;
pub mod smtp;
pub mod smtp_auth;

pub use config::Config;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
