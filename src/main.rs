use clap::Parser;
use micromail::cli::{Cli, Command};
use micromail::config::Config;
use micromail::error::Result;
use micromail::message::Outgoing;
use micromail::queue::{self, Spool};
use micromail::send::Delivery;
use micromail::{api, smtp};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("micromail: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    if cli.version {
        println!("{}", micromail::VERSION);
        return Ok(());
    }

    let config_dir = cli
        .config
        .clone()
        .unwrap_or_else(micromail::config::default_config_dir);
    let config = Config::load(&config_dir)?;

    init_tracing(&config, cli.verbose);

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(config, config_dir).await,
        Command::Send(args) => send(*args, config, &config_dir).await,
    }
}

async fn serve(config: Config, config_dir: PathBuf) -> Result<()> {
    let config = Arc::new(config);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let (spool, worker_rx) = Spool::open(config.spool_dir(&config_dir))?;
    let delivery = Arc::new(Delivery::from_config(&config, &config_dir)?);

    if delivery.dkim().is_empty() {
        tracing::warn!(
            path = %config.dkim_dir(&config_dir).display(),
            "no DKIM keys found; outbound mail will not be signed"
        );
    }

    if !config.smtp.enabled && !config.api.enabled {
        tracing::warn!("neither SMTP nor REST API are enabled; nothing is listening");
    }

    let worker_task = tokio::spawn(queue::run_worker(
        worker_rx,
        spool.clone(),
        delivery,
        config.retry.clone(),
        shutdown_rx.clone(),
    ));

    let smtp_server = smtp::SmtpServer::new(config.clone(), spool.clone())?;
    let smtp_task = tokio::spawn(smtp_server.run(shutdown_rx.clone()));

    let api_task = if config.api.enabled {
        Some(tokio::spawn(api::run(config.clone(), spool.clone(), shutdown_rx.clone())))
    } else {
        None
    };

    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("shutdown signal received"),
        Err(e) => tracing::error!("failed to listen for shutdown signal: {e}"),
    }

    let _ = shutdown_tx.send(true);
    let _ = smtp_task.await;
    if let Some(task) = api_task {
        let _ = task.await;
    }
    let _ = worker_task.await;
    Ok(())
}

async fn send(args: micromail::cli::SendArgs, config: Config, config_dir: &std::path::Path) -> Result<()> {
    let delivery = Delivery::from_config(&config, config_dir)?;

    let text = match (args.text, args.text_file) {
        (Some(t), _) => Some(t),
        (None, Some(path)) => Some(std::fs::read_to_string(&path).map_err(|e| {
            micromail::error::Error::InvalidInput(format!(
                "cannot read {}: {e}",
                path.display()
            ))
        })?),
        (None, None) => None,
    };
    let html = match (args.html, args.html_file) {
        (Some(h), _) => Some(h),
        (None, Some(path)) => Some(std::fs::read_to_string(&path).map_err(|e| {
            micromail::error::Error::InvalidInput(format!(
                "cannot read {}: {e}",
                path.display()
            ))
        })?),
        (None, None) => None,
    };

    if text.is_none() && html.is_none() {
        return Err(micromail::error::Error::InvalidInput(
            "provide at least one of --text, --text-file, --html or --html-file".into(),
        ));
    }

    let mut recipients: Vec<String> = Vec::new();
    for (label, addrs) in [("--to", &args.to), ("--cc", &args.cc), ("--bcc", &args.bcc)] {
        for addr in addrs {
            if !micromail::message::is_valid_email(addr) {
                return Err(micromail::error::Error::InvalidInput(format!(
                    "invalid {label} address {addr:?}"
                )));
            }
            recipients.push(addr.trim().to_lowercase());
        }
    }
    if recipients.is_empty() {
        return Err(micromail::error::Error::InvalidInput(
            "at least one recipient is required".into(),
        ));
    }

    if !micromail::message::is_valid_email(&args.from) {
        return Err(micromail::error::Error::InvalidInput(format!(
            "invalid --from address {:?}",
            args.from
        )));
    }

    let outgoing = Outgoing {
        from: args.from.clone(),
        to: args.to.clone(),
        cc: args.cc.clone(),
        bcc: args.bcc.clone(),
        subject: args.subject,
        text,
        html,
    };
    let body = micromail::message::build(&outgoing)?;
    let from = args.from.trim().to_lowercase();

    delivery.deliver(&from, &recipients, &body).await?;
    println!("Message sent from {} to {} recipient(s)", from, recipients.len());
    Ok(())
}

fn init_tracing(config: &Config, verbose: bool) {
    let filter = match std::env::var("RUST_LOG") {
        Ok(_) => tracing_subscriber::EnvFilter::from_default_env(),
        Err(_) if verbose => tracing_subscriber::EnvFilter::new(
            "debug,\
             hickory_proto=warn,hickory_resolver=warn,hickory_net=warn,\
             rustls=warn,webpki=warn,hyper=info",
        ),
        Err(_) => tracing_subscriber::EnvFilter::new(&config.log),
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
