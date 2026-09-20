//! CLI management of `config.toml`.
//!
//! Supports reading and writing individual scalar settings plus adding,
//! updating and removing SMTP users and API tokens. All edits are performed
//! with `toml_edit` so comments and formatting survive, validated by
//! deserializing the edited document back into [`Config`] before it is
//! written atomically.

use crate::cli::{
    ConfigCommand, DkimCommand, DkimKeyAlgorithm, DnsCommand, SecretSource, TokenCommand,
    UserCommand,
};
use crate::config::{Config, SYSTEM_CONFIG_DIR};
use crate::dkim::{self, KeyKind};
use crate::dns::{self, DnsFormat};
use crate::error::{Error, Result};
use crate::secret;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

/// Config keys that hold credential values; never echoed back by `config get`.
const SECRET_KEYS: [&str; 3] = ["password", "token", "relay_password"];

/// Entry point for `micromail config ...`.
pub fn config_command(command: ConfigCommand, config_dir: &Path) -> Result<()> {
    match command {
        ConfigCommand::Get { key } => config_get(config_dir, &key),
        ConfigCommand::Set { key, value } => config_set(config_dir, &key, &value),
    }
}

/// Entry point for `micromail user ...`.
pub fn user_command(command: UserCommand, config_dir: &Path) -> Result<()> {
    match command {
        UserCommand::List => list_users(config_dir),
        UserCommand::Add { username, input } => {
            add_user(config_dir, &username, &input.source(), input.literal)
        }
        UserCommand::Passwd { username, input } => {
            change_user_password(config_dir, &username, &input.source(), input.literal)
        }
        UserCommand::Remove { username } => remove_user(config_dir, &username),
    }
}

/// Entry point for `micromail token ...`.
pub fn token_command(command: TokenCommand, config_dir: &Path) -> Result<()> {
    match command {
        TokenCommand::List => list_tokens(config_dir),
        TokenCommand::Add { name, input } => {
            add_token(config_dir, &name, &input.source(), input.literal)
        }
        TokenCommand::Rotate { name, input } => {
            rotate_token(config_dir, &name, &input.source(), input.literal)
        }
        TokenCommand::Remove { name } => remove_token(config_dir, &name),
    }
}

/// Entry point for `micromail dkim ...`.
pub fn dkim_command(command: DkimCommand, config_dir: &Path) -> Result<()> {
    match command {
        DkimCommand::Generate {
            domain,
            selector,
            algorithm,
            bits,
            force,
        } => generate_dkim(config_dir, &domain, &selector, algorithm, bits, force),
    }
}

/// Entry point for `micromail dns ...`.
pub fn dns_command(command: DnsCommand, config_dir: &Path) -> Result<()> {
    match command {
        DnsCommand::Dkim {
            domain,
            selector,
            format,
        } => dns_dkim(config_dir, &domain, &selector, format),
        DnsCommand::Spf {
            domain,
            ip,
            include,
            auto_ip,
            hostname,
            format,
        } => dns_spf(
            config_dir,
            &domain,
            &ip,
            &include,
            auto_ip,
            hostname.as_deref(),
            format,
        ),
    }
}

// ---------------------------------------------------------------------
// dkim generate
// ---------------------------------------------------------------------

fn generate_dkim(
    config_dir: &Path,
    domain: &str,
    selector: &str,
    algorithm: DkimKeyAlgorithm,
    bits: u32,
    force: bool,
) -> Result<()> {
    validate_domain(domain)?;
    if !dkim::is_valid_selector(selector) {
        return Err(Error::InvalidInput(format!(
            "selector {selector:?} is invalid; use 1-63 characters of A-Z, a-z, 0-9, '-' or '_'"
        )));
    }
    let kind = match algorithm {
        DkimKeyAlgorithm::Rsa => KeyKind::Rsa,
        DkimKeyAlgorithm::Ed25519 => KeyKind::Ed25519,
    };
    let (key, pem) = dkim::generate_key(kind, bits)?;

    let dir = config_dir.join("dkim").join(domain);
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let path = dir.join(selector);
    if path.exists() && !force {
        return Err(Error::InvalidInput(format!(
            "DKIM key {domain}/{selector} already exists at {}; use --force to overwrite",
            path.display()
        )));
    }
    write_secret_file(&path, pem.as_bytes())?;

    sync_default_selector(config_dir, selector)?;

    let value = dkim::public_key_dns(domain, selector, &key)?;
    let name = format!("_{selector}._domainkey.{domain}");
    println!("DKIM private key written to {}", path.display());
    print!("{}", dns::render_record(&name, &value, DnsFormat::Human));
    Ok(())
}

/// Write `contents` to `path` (creating parents) with 0o600 perms so the DKIM
/// loader accepts it (it rejects group/other-readable keys).
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Keep the runtime's `dkim_selector_default` consistent with the generated
/// key so the daemon signs with the same selector published in DNS. Best
/// effort: failures only warn rather than abort key generation.
fn sync_default_selector(config_dir: &Path, selector: &str) -> Result<()> {
    let path = config_file_path(config_dir);
    let mut document = match load_document(&path) {
        Ok(doc) => doc,
        Err(_) => {
            eprintln!(
                "warning: could not read {} to set dkim_selector_default; the daemon will \
                 sign with its configured selector. Set it with `micromail config set \
                 dkim_selector_default {selector}`",
                path.display()
            );
            return Ok(());
        }
    };
    match document.get("dkim_selector_default") {
        None => {
            document.insert("dkim_selector_default", value(selector));
            if let Err(e) = validate_document(&path, &document) {
                eprintln!("warning: could not update {}: {e}", path.display());
                return Ok(());
            }
            if let Err(e) = save_document(&path, &document) {
                eprintln!("warning: could not write {}: {e}", path.display());
                return Ok(());
            }
            println!(
                "set dkim_selector_default = {selector:?} in {}",
                path.display()
            );
        }
        Some(item) => {
            if let Some(existing) = item.as_str() {
                if existing != selector {
                    eprintln!(
                        "warning: config dkim_selector_default = {existing:?} differs from the \
                         generated selector {selector:?}; the daemon will sign with {existing:?}. \
                         Run `micromail config set dkim_selector_default {selector}` to match."
                    );
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// dns
// ---------------------------------------------------------------------

fn dns_dkim(config_dir: &Path, domain: &str, selector: &str, format: DnsFormat) -> Result<()> {
    let path = config_dir.join("dkim").join(domain).join(selector);
    if !path.exists() {
        return Err(Error::InvalidInput(format!(
            "no DKIM key at {} (run `micromail dkim generate {domain} --selector {selector}` first)",
            path.display()
        )));
    }
    let pem = std::fs::read(&path)?;
    let key = dkim::parse_key(&pem)?;
    let value = dkim::public_key_dns(domain, selector, &key)?;
    let name = format!("_{selector}._domainkey.{domain}");
    print!("{}", dns::render_record(&name, &value, format));
    Ok(())
}

fn dns_spf(
    config_dir: &Path,
    domain: &str,
    ips: &[String],
    includes: &[String],
    auto_ip: bool,
    hostname_override: Option<&str>,
    format: DnsFormat,
) -> Result<()> {
    let config = Config::load(config_dir)?;
    let hostname = hostname_override.unwrap_or(config.hostname.as_str());
    let value = dns::build_spf(domain, hostname, ips, includes, auto_ip)?;
    print!("{}", dns::render_record(domain, &value, format));
    Ok(())
}

fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty()
        || domain
            .chars()
            .any(|c| c.is_whitespace() || c == '/' || c == '\\')
    {
        return Err(Error::InvalidInput(
            "domain must be non-empty and contain no whitespace or path separators".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// config get / config set
// ---------------------------------------------------------------------

fn config_get(config_dir: &Path, key: &str) -> Result<()> {
    let config = Config::load(config_dir)?;
    let mut json = serde_json::to_value(&config)
        .map_err(|e| Error::Config(format!("cannot render config: {e}")))?;
    redact_secrets(&mut json);
    let value = resolve_path(&json, key)?;
    match value {
        serde_json::Value::String(text) => println!("{text}"),
        other => println!("{other}"),
    }
    Ok(())
}

fn config_set(config_dir: &Path, key: &str, raw_value: &str) -> Result<()> {
    let path = config_file_path(config_dir);
    let defaults = serde_json::to_value(Config::default())
        .map_err(|e| Error::Config(format!("cannot render defaults: {e}")))?;
    let expected = expect_scalar_path(&defaults, key)?;
    let item = coerce_value(expected, raw_value, key)?;

    let mut document = load_document(&path)?;
    apply_set(&mut document, key, item)?;
    validate_document(&path, &document)?;
    save_document(&path, &document)?;
    println!("{key} set in {}", path.display());
    Ok(())
}

/// Walk a dotted key through the serialized config, allowing numeric
/// indices for arrays.
fn resolve_path<'a>(root: &'a serde_json::Value, key: &str) -> Result<&'a serde_json::Value> {
    let mut current = root;
    for segment in key.split('.') {
        current = match current {
            serde_json::Value::Object(map) => {
                map.get(segment).ok_or_else(|| unknown_key_error(key))?
            }
            serde_json::Value::Array(items) => {
                let index: usize = segment.parse().map_err(|_| {
                    Error::InvalidInput(format!("{key:?}: {segment:?} is not a valid array index"))
                })?;
                items.get(index).ok_or_else(|| {
                    Error::InvalidInput(format!("{key:?}: index {index} is out of bounds"))
                })?
            }
            _ => {
                return Err(Error::InvalidInput(format!(
                    "{key:?}: cannot descend into a non-object at {segment:?}"
                )))
            }
        };
    }
    Ok(current)
}

/// Like [`resolve_path`], but rejects collections outright: scalar settings
/// are the domain of `config set`, while users/tokens belong to their own
/// commands.
fn expect_scalar_path<'a>(root: &'a serde_json::Value, key: &str) -> Result<&'a serde_json::Value> {
    let mut current = root;
    for segment in key.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(segment).ok_or_else(|| unknown_key_error(key))?;
            }
            serde_json::Value::Array(_) => {
                return Err(Error::InvalidInput(format!(
                    "{key:?}: lists are managed with the \"user\" and \"token\" commands"
                )));
            }
            _ => {
                return Err(Error::InvalidInput(format!(
                    "{key:?}: cannot descend into a non-object at {segment:?}"
                )))
            }
        }
    }
    match current {
        serde_json::Value::Array(_) => Err(Error::InvalidInput(format!(
            "{key:?}: lists are managed with the \"user\" and \"token\" commands"
        ))),
        serde_json::Value::Object(_) => Err(Error::InvalidInput(format!(
            "{key:?} is not a scalar setting"
        ))),
        scalar => Ok(scalar),
    }
}

/// Coerce the command-line string into a TOML item matching the type of the
/// existing (default) value for `key`.
fn coerce_value(expected: &serde_json::Value, raw: &str, key: &str) -> Result<Item> {
    match expected {
        serde_json::Value::Bool(_) => match raw {
            "true" => Ok(Item::Value(true.into())),
            "false" => Ok(Item::Value(false.into())),
            _ => Err(Error::InvalidInput(format!(
                "{key:?} expects \"true\" or \"false\", got {raw:?}"
            ))),
        },
        serde_json::Value::Number(number) => {
            if number.is_i64() || number.is_u64() {
                raw.parse::<i64>()
                    .map_err(|_| wrong_type_error(key, "an integer", raw))
                    .map(|v| Item::Value(v.into()))
            } else {
                raw.parse::<f64>()
                    .map_err(|_| wrong_type_error(key, "a number", raw))
                    .map(|v| Item::Value(v.into()))
            }
        }
        serde_json::Value::Null | serde_json::Value::String(_) => Ok(Item::Value(raw.into())),
        _ => Err(unknown_key_error(key)),
    }
}

/// Insert `item` at the dotted `key`, creating intermediate tables.
fn apply_set(document: &mut DocumentMut, key: &str, item: Item) -> Result<()> {
    let segments: Vec<&str> = key.split('.').collect();
    let (last, parents) = segments
        .split_last()
        .ok_or_else(|| unknown_key_error(key))?;

    let mut table = document.as_table_mut();
    for parent in parents {
        if table.get(parent).is_none() {
            let mut fresh = Table::new();
            fresh.set_implicit(true);
            table.insert(parent, Item::Table(fresh));
        }
        table = match table.get_mut(parent) {
            Some(Item::Table(inner)) => inner,
            Some(_) => {
                return Err(Error::Config(format!(
                    "{parent:?} already exists and is not a table"
                )))
            }
            None => return Err(internal_error("inserted table vanished")),
        };
    }
    set_table_value(table, last, item);
    Ok(())
}

/// Insert or replace `item` at `key`, keeping the existing key/value pair's
/// comments and formatting when the key is already present (toml_edit
/// attaches those to the pair's decor).
fn set_table_value(table: &mut Table, key: &str, item: Item) {
    match table.get_mut(key) {
        None => {
            table.insert(key, item);
        }
        Some(existing) => {
            let (prefix, suffix) = existing
                .as_value()
                .map(|v| (v.decor().prefix().cloned(), v.decor().suffix().cloned()))
                .unwrap_or_default();
            let mut item = item;
            if let Some(value) = item.as_value_mut() {
                if let Some(prefix) = prefix {
                    value.decor_mut().set_prefix(prefix);
                }
                if let Some(suffix) = suffix {
                    value.decor_mut().set_suffix(suffix);
                }
            }
            *existing = item;
        }
    }
}

/// Replace every credential string with a placeholder so secrets never
/// reach stdout via `config get`.
fn redact_secrets(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (name, entry) in map.iter_mut() {
                if SECRET_KEYS.contains(&name.as_str()) && entry.is_string() {
                    *entry = serde_json::Value::String("**redacted**".into());
                } else {
                    redact_secrets(entry);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_secrets(item);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------
// SMTP users
// ---------------------------------------------------------------------

fn list_users(config_dir: &Path) -> Result<()> {
    let config = Config::load(config_dir)?;
    let width = config
        .smtp
        .users
        .iter()
        .map(|u| u.username.len())
        .max()
        .unwrap_or(4)
        .max(4)
        + 2;
    for user in &config.smtp.users {
        println!("{:<width$}{}", user.username, user.password.scheme());
    }
    Ok(())
}

fn add_user(
    config_dir: &Path,
    username: &str,
    source: &SecretSource,
    store_literal: bool,
) -> Result<()> {
    validate_identifier(username, "username")?;
    let path = config_file_path(config_dir);
    let mut document = load_document(&path)?;
    {
        let users = collection_aot_mut(&mut document, "smtp", "users")?;
        if find_entry(users, "username", username, true).is_some() {
            return Err(Error::InvalidInput(format!(
                "SMTP user {username:?} already exists"
            )));
        }
        // When the name comes only from the merged (system) config, defining
        // it here would replace the entire system users list at runtime.
        if user_in_effective(config_dir, username) {
            return Err(Error::InvalidInput(format!(
                "SMTP user {username:?} is defined in the merged configuration \
                 (likely {}); adding it to {} would shadow the whole system users \
                 list — manage it with -c {}",
                SYSTEM_CONFIG_DIR,
                path.display(),
                SYSTEM_CONFIG_DIR
            )));
        }
        let stored = stored_secret(source, "Password", store_literal)?;
        let mut entry = Table::new();
        entry.insert("username", value(username));
        entry.insert("password", value(stored.as_str()));
        users.push(entry);
    }
    validate_document(&path, &document)?;
    save_document(&path, &document)?;
    println!("user {username:?} added to {}", path.display());
    Ok(())
}

fn change_user_password(
    config_dir: &Path,
    username: &str,
    source: &SecretSource,
    store_literal: bool,
) -> Result<()> {
    validate_identifier(username, "username")?;
    let path = config_file_path(config_dir);
    let mut document = load_document(&path)?;
    {
        let users = collection_aot_mut(&mut document, "smtp", "users")?;
        let index = find_entry(users, "username", username, true)
            .ok_or_else(|| user_not_found(config_dir, username))?;
        let stored = stored_secret(source, "Password", store_literal)?;
        replace_credential_field(users, index, "password", &stored)?;
    }
    validate_document(&path, &document)?;
    save_document(&path, &document)?;
    println!(
        "password for user {username:?} updated in {}",
        path.display()
    );
    Ok(())
}

fn remove_user(config_dir: &Path, username: &str) -> Result<()> {
    validate_identifier(username, "username")?;
    let path = config_file_path(config_dir);
    let mut document = load_document(&path)?;
    {
        let users = collection_aot_mut(&mut document, "smtp", "users")?;
        let index = find_entry(users, "username", username, true)
            .ok_or_else(|| user_not_found(config_dir, username))?;
        users.remove(index);
    }
    validate_document(&path, &document)?;
    save_document(&path, &document)?;
    println!("user {username:?} removed from {}", path.display());
    Ok(())
}

// ---------------------------------------------------------------------
// API tokens
// ---------------------------------------------------------------------

fn list_tokens(config_dir: &Path) -> Result<()> {
    let config = Config::load(config_dir)?;
    let width = config
        .api
        .tokens
        .iter()
        .map(|t| t.name.len())
        .max()
        .unwrap_or(4)
        .max(4)
        + 2;
    for token in &config.api.tokens {
        println!("{:<width$}{}", token.name, token.token.scheme());
    }
    Ok(())
}

fn add_token(
    config_dir: &Path,
    name: &str,
    source: &SecretSource,
    store_literal: bool,
) -> Result<()> {
    validate_identifier(name, "token name")?;
    let path = config_file_path(config_dir);
    let mut document = load_document(&path)?;
    let generated = {
        let tokens = collection_aot_mut(&mut document, "api", "tokens")?;
        if find_entry(tokens, "name", name, false).is_some() {
            return Err(Error::InvalidInput(format!(
                "API token {name:?} already exists"
            )));
        }
        if token_in_effective(config_dir, name) {
            return Err(Error::InvalidInput(format!(
                "API token {name:?} is defined in the merged configuration \
                 (likely {}); adding it to {} would shadow the whole system \
                 token list — manage it with -c {}",
                SYSTEM_CONFIG_DIR,
                path.display(),
                SYSTEM_CONFIG_DIR
            )));
        }
        let (stored, generated) = stored_token(source, "Token", store_literal)?;
        let mut entry = Table::new();
        entry.insert("name", value(name));
        entry.insert("token", value(stored.as_str()));
        tokens.push(entry);
        generated
    };
    validate_document(&path, &document)?;
    save_document(&path, &document)?;
    report_generated(name, &generated);
    println!("token {name:?} added to {}", path.display());
    Ok(())
}

fn rotate_token(
    config_dir: &Path,
    name: &str,
    source: &SecretSource,
    store_literal: bool,
) -> Result<()> {
    validate_identifier(name, "token name")?;
    let path = config_file_path(config_dir);
    let mut document = load_document(&path)?;
    let generated = {
        let tokens = collection_aot_mut(&mut document, "api", "tokens")?;
        let index = find_entry(tokens, "name", name, false)
            .ok_or_else(|| token_not_found(config_dir, name))?;
        let (stored, generated) = stored_token(source, "Token", store_literal)?;
        replace_credential_field(tokens, index, "token", &stored)?;
        generated
    };
    validate_document(&path, &document)?;
    save_document(&path, &document)?;
    report_generated(name, &generated);
    println!("token {name:?} rotated in {}", path.display());
    Ok(())
}

fn remove_token(config_dir: &Path, name: &str) -> Result<()> {
    validate_identifier(name, "token name")?;
    let path = config_file_path(config_dir);
    let mut document = load_document(&path)?;
    {
        let tokens = collection_aot_mut(&mut document, "api", "tokens")?;
        let index = find_entry(tokens, "name", name, false)
            .ok_or_else(|| token_not_found(config_dir, name))?;
        tokens.remove(index);
    }
    validate_document(&path, &document)?;
    save_document(&path, &document)?;
    println!("token {name:?} removed from {}", path.display());
    Ok(())
}

// ---------------------------------------------------------------------
// Secret plumbing
// ---------------------------------------------------------------------

/// Resolve a secret from its source and produce the prefixed config value
/// (`argon2:` unless `store_literal`).
fn stored_secret(source: &SecretSource, label: &str, store_literal: bool) -> Result<String> {
    if matches!(source, SecretSource::Generate) {
        return Err(Error::InvalidInput(
            "--generate is only supported for API tokens".into(),
        ));
    }
    let plaintext = resolve_plaintext(source, label)?;
    if store_literal {
        Ok(secret::literal_value(&plaintext))
    } else {
        secret::argon2_value(&plaintext)
    }
}

/// Resolve an API token, generating one when requested. Returns the stored
/// value plus the generated plaintext (printed once, never stored).
fn stored_token(
    source: &SecretSource,
    label: &str,
    store_literal: bool,
) -> Result<(String, Option<String>)> {
    if matches!(source, SecretSource::Generate) {
        let generated = secret::generate_token();
        let stored = secret::argon2_value(&generated)?;
        return Ok((stored, Some(generated)));
    }
    let stored = stored_secret(source, label, store_literal)?;
    Ok((stored, None))
}

fn resolve_plaintext(source: &SecretSource, label: &str) -> Result<String> {
    let plaintext = match source {
        SecretSource::Inline(value) => value.clone(),
        SecretSource::Stdin => read_line_from_stdin()?,
        SecretSource::File(path) => read_first_line(path)?,
        SecretSource::Prompt => {
            let first = rpassword::prompt_password(format!("{label}: "))?;
            let confirm_label = format!("Confirm {}: ", label.to_lowercase());
            let confirmed = rpassword::prompt_password(confirm_label)?;
            if first != confirmed {
                return Err(Error::InvalidInput("secrets do not match".into()));
            }
            first
        }
        SecretSource::Generate => {
            return Err(internal_error(
                "generate source reached password resolution",
            ))
        }
    };
    if plaintext.is_empty() {
        return Err(Error::InvalidInput("secret must not be empty".into()));
    }
    Ok(plaintext)
}

fn read_line_from_stdin() -> Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

fn read_first_line(path: &Path) -> Result<String> {
    let mut content = String::new();
    std::fs::File::open(path)?.read_to_string(&mut content)?;
    Ok(content.lines().next().unwrap_or_default().to_string())
}

fn report_generated(name: &str, generated: &Option<String>) {
    if let Some(token) = generated {
        println!("generated token for {name:?} (shown once; store it safely):");
        println!("{token}");
    }
}

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

fn config_file_path(config_dir: &Path) -> PathBuf {
    config_dir.join("config.toml")
}

/// Locate the `[[<section>.<key>]]` array of tables, creating the parent
/// table and the array itself when absent.
fn collection_aot_mut<'a>(
    document: &'a mut DocumentMut,
    section: &str,
    key: &str,
) -> Result<&'a mut ArrayOfTables> {
    let root = document.as_table_mut();
    if root.get(section).is_none() {
        let mut sub = Table::new();
        sub.set_implicit(true);
        root.insert(section, Item::Table(sub));
    }
    let section_table = match root.get_mut(section) {
        Some(Item::Table(table)) => table,
        Some(_) => {
            return Err(Error::Config(format!(
                "[{section}] already exists but is not a table"
            )))
        }
        None => return Err(internal_error("created section vanished")),
    };

    if section_table.get(key).is_none() {
        section_table.insert(key, Item::ArrayOfTables(ArrayOfTables::new()));
    }
    match section_table.get_mut(key) {
        Some(Item::ArrayOfTables(entries)) => Ok(entries),
        Some(_) => Err(Error::Config(format!(
            "[{section}] {key} already exists but is not a table array"
        ))),
        None => Err(internal_error("created table array vanished")),
    }
}

/// Find an entry whose string field matches. SMTP usernames compare ASCII
/// case-insensitively (matching AUTH behaviour); token names are exact.
fn find_entry(
    entries: &ArrayOfTables,
    field: &str,
    needle: &str,
    case_insensitive: bool,
) -> Option<usize> {
    entries.iter().position(|entry| {
        entry
            .get(field)
            .and_then(Item::as_str)
            .is_some_and(|value| {
                if case_insensitive {
                    value.eq_ignore_ascii_case(needle)
                } else {
                    value == needle
                }
            })
    })
}

/// Overwrite `field` on the entry at `index`, keeping its position, comments
/// and formatting.
fn replace_credential_field(
    entries: &mut ArrayOfTables,
    index: usize,
    field: &str,
    stored: &str,
) -> Result<()> {
    let entry = entries
        .get_mut(index)
        .ok_or_else(|| internal_error("matched entry is missing"))?;
    set_table_value(entry, field, value(stored));
    Ok(())
}

fn validate_identifier(value: &str, what: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(Error::InvalidInput(format!(
            "{what} must be non-empty, free of control characters, and neither start nor end with whitespace"
        )));
    }
    Ok(())
}

fn load_document(path: &Path) -> Result<DocumentMut> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .parse::<DocumentMut>()
            .map_err(|e| Error::Config(format!("invalid {}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DocumentMut::new()),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Round-trip the edited document through [`Config`] so invalid types,
/// malformed credentials or policy violations (e.g. Argon2 relay passwords)
/// are caught before anything touches disk.
fn validate_document(path: &Path, document: &DocumentMut) -> Result<()> {
    let text = document.to_string();
    let parsed: Config = toml::from_str(&text)
        .map_err(|e| Error::Config(format!("edit would make {} invalid: {e}", path.display())))?;
    parsed.validate()
}

fn save_document(path: &Path, document: &DocumentMut) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let file_name = path.file_name().map_or_else(
        || "config.toml".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let tmp = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    std::fs::write(&tmp, document.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map(|meta| meta.permissions().mode() & 0o777)
            .unwrap_or(0o600);
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }

    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn not_found_error(kind: &str, identifier: &str) -> Error {
    Error::InvalidInput(format!("{kind} {identifier:?} was not found"))
}

/// Load the effective (merged) config, best-effort. Returns `None` when the
/// config is currently invalid so write commands can still repair a broken
/// file.
fn effective_config(config_dir: &Path) -> Option<Config> {
    Config::load(config_dir).ok()
}

/// True when `username` is present in the effective (merged) configuration.
fn user_in_effective(config_dir: &Path, username: &str) -> bool {
    effective_config(config_dir).is_some_and(|config| {
        config
            .smtp
            .users
            .iter()
            .any(|user| user.username.eq_ignore_ascii_case(username))
    })
}

/// True when `name` is present in the effective (merged) configuration.
fn token_in_effective(config_dir: &Path, name: &str) -> bool {
    effective_config(config_dir)
        .is_some_and(|config| config.api.tokens.iter().any(|token| token.name == name))
}

fn user_not_found(config_dir: &Path, username: &str) -> Error {
    if user_in_effective(config_dir, username) {
        Error::InvalidInput(format!(
            "SMTP user {username:?} is not in {} but is defined in the merged \
             configuration (likely {}); manage it there or pass -c {}",
            config_dir.display(),
            SYSTEM_CONFIG_DIR,
            SYSTEM_CONFIG_DIR
        ))
    } else {
        not_found_error("SMTP user", username)
    }
}

fn token_not_found(config_dir: &Path, name: &str) -> Error {
    if token_in_effective(config_dir, name) {
        Error::InvalidInput(format!(
            "API token {name:?} is not in {} but is defined in the merged \
             configuration (likely {}); manage it there or pass -c {}",
            config_dir.display(),
            SYSTEM_CONFIG_DIR,
            SYSTEM_CONFIG_DIR
        ))
    } else {
        not_found_error("API token", name)
    }
}

fn unknown_key_error(key: &str) -> Error {
    Error::InvalidInput(format!(
        "unknown configuration key {key:?}; see config.toml.example for valid keys"
    ))
}

fn wrong_type_error(key: &str, expected: &str, got: &str) -> Error {
    Error::InvalidInput(format!("{key:?} expects {expected}, got {got:?}"))
}

fn internal_error(detail: &str) -> Error {
    Error::Config(format!("internal error: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::SecretSource;
    use tempfile::TempDir;

    fn temp_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    fn write_config(dir: &Path, contents: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("config.toml"), contents).unwrap();
    }

    fn read_config(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("config.toml")).unwrap()
    }

    fn loaded(dir: &Path) -> Config {
        Config::load(dir).unwrap()
    }

    // ----- config set -----

    #[test]
    fn set_creates_file_and_value() {
        let dir = temp_dir();
        config_set(dir.path(), "hostname", "mail.example.com").unwrap();
        assert_eq!(loaded(dir.path()).hostname, "mail.example.com");
        let text = read_config(dir.path());
        assert!(text.contains("hostname = \"mail.example.com\""), "{text}");
    }

    #[test]
    fn set_creates_intermediate_tables() {
        let dir = temp_dir();
        config_set(dir.path(), "retry.backoff_factor", "4").unwrap();
        assert_eq!(loaded(dir.path()).retry.backoff_factor, 4);
    }

    #[test]
    fn set_coerces_bools_and_integers() {
        let dir = temp_dir();
        config_set(dir.path(), "smtp.enabled", "true").unwrap();
        config_set(dir.path(), "max_message_size", "1024").unwrap();
        let config = loaded(dir.path());
        assert!(config.smtp.enabled);
        assert_eq!(config.max_message_size, 1024);

        let err = config_set(dir.path(), "smtp.enabled", "yes").unwrap_err();
        assert!(err.to_string().contains("true"), "{err}");
        let err = config_set(dir.path(), "max_message_size", "big").unwrap_err();
        assert!(err.to_string().contains("integer"), "{err}");
    }

    #[test]
    fn set_rejects_unknown_keys() {
        let dir = temp_dir();
        for key in ["hostnam", "smtp.listennn", "nope.nope.nope"] {
            let err = config_set(dir.path(), key, "x").unwrap_err();
            assert!(
                err.to_string().contains("unknown configuration key"),
                "{err}"
            );
        }
    }

    #[test]
    fn set_rejects_collections() {
        let dir = temp_dir();
        for key in ["smtp.users", "api.tokens", "smtp.users.0.username"] {
            let err = config_set(dir.path(), key, "x").unwrap_err();
            assert!(
                err.to_string().contains("user\" and \"token\""),
                "{key}: {err}"
            );
        }
    }

    #[test]
    fn set_preserves_comments_and_formatting() {
        let dir = temp_dir();
        write_config(
            dir.path(),
            "# my host\nhostname = \"old\" # trailing\n\n[smtp]\nenabled = false\n",
        );
        config_set(dir.path(), "hostname", "new.example.com").unwrap();
        let text = read_config(dir.path());
        assert!(text.contains("# my host"), "{text}");
        assert!(text.contains("# trailing"), "{text}");
        assert!(text.contains("enabled = false"), "{text}");
        assert!(text.contains("\"new.example.com\""), "{text}");
        // Still valid TOML that loads.
        assert_eq!(loaded(dir.path()).hostname, "new.example.com");
    }

    #[test]
    fn set_rejects_unprefixed_secret() {
        let dir = temp_dir();
        let err = config_set(dir.path(), "delivery.relay_password", "hunter2").unwrap_err();
        assert!(err.to_string().contains("literal:"), "{err}");
    }

    #[test]
    fn set_rejects_argon2_relay_password() {
        let dir = temp_dir();
        let err = config_set(
            dir.path(),
            "delivery.relay_password",
            "argon2:$argon2id$bad",
        )
        .unwrap_err();
        assert!(err.to_string().contains("relay_password"), "{err}");
        // The file must not have been written with the rejected value.
        assert!(!dir.path().join("config.toml").exists());
    }

    // ----- users -----

    const INLINE: fn(&str) -> SecretSource = |pw| SecretSource::Inline(pw.to_string());

    #[test]
    fn user_add_stores_argon2_hash() {
        let dir = temp_dir();
        add_user(dir.path(), "app", &INLINE("hunter2"), false).unwrap();
        let text = read_config(dir.path());
        assert!(text.starts_with("[[smtp.users]]"), "{text}");
        let config = loaded(dir.path());
        assert_eq!(config.smtp.users.len(), 1);
        let user = &config.smtp.users[0];
        assert_eq!(user.username, "app");
        assert_eq!(user.password.scheme(), "argon2");
        assert!(user.password.verify("hunter2"));
        assert!(!user.password.verify("wrong"));
    }

    #[test]
    fn user_add_literal_opt_out() {
        let dir = temp_dir();
        add_user(dir.path(), "app", &INLINE("hunter2"), true).unwrap();
        let text = read_config(dir.path());
        assert!(text.contains("password = \"literal:hunter2\""), "{text}");
        assert!(loaded(dir.path()).smtp.users[0].password.verify("hunter2"));
    }

    #[test]
    fn user_add_appends_to_existing_array() {
        let dir = temp_dir();
        write_config(
            dir.path(),
            "# keep me\n[smtp]\nenabled = true\n\n[[smtp.users]]\nusername = \"first\"\npassword = \"literal:a\"\n",
        );
        add_user(dir.path(), "second", &INLINE("b"), false).unwrap();
        let text = read_config(dir.path());
        assert!(text.contains("# keep me"), "{text}");
        assert!(
            text.contains("\"first\"") && text.contains("\"second\""),
            "{text}"
        );
        // The whole file must still be structurally valid.
        let config = loaded(dir.path());
        assert_eq!(config.smtp.users.len(), 2);
        assert!(config.smtp.enabled);
    }

    #[test]
    fn user_add_rejects_duplicates_case_insensitively() {
        let dir = temp_dir();
        write_config(
            dir.path(),
            "[[smtp.users]]\nusername = \"App\"\npassword = \"literal:x\"\n",
        );
        let err = add_user(dir.path(), "APP", &INLINE("y"), false).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn user_passwd_replaces_hash() {
        let dir = temp_dir();
        add_user(dir.path(), "app", &INLINE("one"), false).unwrap();
        change_user_password(dir.path(), "app", &INLINE("two"), false).unwrap();
        let config = loaded(dir.path());
        assert_eq!(config.smtp.users.len(), 1);
        assert!(config.smtp.users[0].password.verify("two"));
        assert!(!config.smtp.users[0].password.verify("one"));

        let err = change_user_password(dir.path(), "ghost", &INLINE("x"), false).unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[test]
    fn credential_updates_preserve_line_comments() {
        let dir = temp_dir();
        write_config(
            dir.path(),
            "[[smtp.users]]\nusername = \"app\"\npassword = \"literal:one\" # rotate me\n",
        );
        change_user_password(dir.path(), "app", &INLINE("two"), true).unwrap();
        let text = read_config(dir.path());
        assert!(text.contains("# rotate me"), "{text}");
        assert!(
            text.contains("password = \"literal:two\" # rotate me"),
            "{text}"
        );
        assert!(loaded(dir.path()).smtp.users[0].password.verify("two"));

        let dir = temp_dir();
        write_config(
            dir.path(),
            "[[api.tokens]]\nname = \"ci\"\ntoken = \"literal:one\" # rotate me\n",
        );
        rotate_token(dir.path(), "ci", &INLINE("two"), true).unwrap();
        let text = read_config(dir.path());
        assert!(text.contains("# rotate me"), "{text}");
        assert!(
            text.contains("token = \"literal:two\" # rotate me"),
            "{text}"
        );
        assert!(loaded(dir.path()).api.tokens[0].token.verify("two"));
    }

    #[test]
    fn user_remove_works() {
        let dir = temp_dir();
        add_user(dir.path(), "app", &INLINE("x"), false).unwrap();
        remove_user(dir.path(), "APP").unwrap();
        assert!(loaded(dir.path()).smtp.users.is_empty());

        let err = remove_user(dir.path(), "app").unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[test]
    fn user_identifier_is_validated() {
        let dir = temp_dir();
        let err = add_user(dir.path(), "", &INLINE("x"), false).unwrap_err();
        assert!(err.to_string().contains("username"), "{err}");
        let err = add_user(dir.path(), " spaced ", &INLINE("x"), false).unwrap_err();
        assert!(err.to_string().contains("username"), "{err}");
    }

    #[test]
    fn generate_source_rejected_for_users() {
        let dir = temp_dir();
        let err = add_user(dir.path(), "app", &SecretSource::Generate, false).unwrap_err();
        assert!(err.to_string().contains("--generate"), "{err}");
    }

    // ----- tokens -----

    #[test]
    fn token_add_generate_stores_only_hash() {
        let dir = temp_dir();
        let (stored, generated) = stored_token(&SecretSource::Generate, "Token", false).unwrap();
        assert!(generated.is_some());
        let token_text = generated.as_deref().unwrap();
        assert_eq!(token_text.len(), 43, "{token_text}");
        assert!(
            token_text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{token_text}"
        );
        assert!(stored.starts_with("argon2:"));

        add_token(dir.path(), "ci", &SecretSource::Generate, false).unwrap();
        let config = loaded(dir.path());
        assert_eq!(config.api.tokens.len(), 1);
        assert_eq!(config.api.tokens[0].token.scheme(), "argon2");

        // A generated token is never stored as plaintext.
        let text = read_config(dir.path());
        assert!(
            !text.contains(token_text),
            "generated token leaked into config"
        );
    }

    #[test]
    fn token_lifecycle() {
        let dir = temp_dir();
        add_token(dir.path(), "ci", &INLINE("tok-1"), true).unwrap();
        let config = loaded(dir.path());
        assert_eq!(config.api.tokens.len(), 1);
        assert!(config.api.tokens[0].token.verify("tok-1"));

        rotate_token(dir.path(), "ci", &INLINE("tok-2"), true).unwrap();
        let config = loaded(dir.path());
        assert_eq!(config.api.tokens.len(), 1);
        assert!(config.api.tokens[0].token.verify("tok-2"));
        assert!(!config.api.tokens[0].token.verify("tok-1"));

        remove_token(dir.path(), "ci").unwrap();
        assert!(loaded(dir.path()).api.tokens.is_empty());

        let err = rotate_token(dir.path(), "gone", &INLINE("t"), true).unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[test]
    fn token_names_are_case_sensitive() {
        let dir = temp_dir();
        add_token(dir.path(), "ci", &INLINE("a"), true).unwrap();
        add_token(dir.path(), "CI", &INLINE("b"), true).unwrap();
        assert_eq!(loaded(dir.path()).api.tokens.len(), 2);
        assert_eq!(loaded(dir.path()).api.tokens[0].name, "ci");
        assert_eq!(loaded(dir.path()).api.tokens[1].name, "CI");
    }

    // ----- get / redaction -----

    #[test]
    fn resolve_path_walks_objects_arrays_and_scalars() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"smtp": {"listen": ":587", "users": [{"username": "app"}], "enabled": true}}"#,
        )
        .unwrap();
        assert_eq!(
            resolve_path(&json, "smtp.listen").unwrap(),
            &serde_json::json!(":587")
        );
        assert_eq!(
            resolve_path(&json, "smtp.users.0.username").unwrap(),
            &serde_json::json!("app")
        );
        assert!(resolve_path(&json, "smtp.missing").is_err());
        assert!(resolve_path(&json, "smtp.listen.deeper").is_err());
        assert!(resolve_path(&json, "smtp.users.zero").is_err());
        assert!(resolve_path(&json, "smtp.users.9").is_err());
    }

    #[test]
    fn redaction_hides_credential_strings() {
        let mut json: serde_json::Value = serde_json::from_str(
            r#"{
                "delivery": {"relay_password": "literal:p"},
                "smtp": {"users": [{"username": "app", "password": "argon2:h"}]},
                "api": {"tokens": [{"name": "ci", "token": "literal:t"}]}
            }"#,
        )
        .unwrap();
        redact_secrets(&mut json);
        let rendered = serde_json::to_string(&json).unwrap();
        assert!(!rendered.contains("literal:p"), "{rendered}");
        assert!(!rendered.contains("argon2:h"), "{rendered}");
        assert!(!rendered.contains("literal:t"), "{rendered}");
        assert!(rendered.contains("**redacted**"), "{rendered}");
        assert!(rendered.contains("\"app\""), "{rendered}");
    }

    // ----- dkim generate / dns -----
    #[test]
    fn dkim_generate_writes_loadable_key() {
        use crate::cli::{DkimCommand, DkimKeyAlgorithm};
        use crate::dkim::DkimManager;

        let dir = temp_dir();
        dkim_command(
            DkimCommand::Generate {
                domain: "example.com".into(),
                selector: "mail".into(),
                algorithm: DkimKeyAlgorithm::Rsa,
                bits: 2048,
                force: false,
            },
            dir.path(),
        )
        .unwrap();

        let path = dir.path().join("dkim/example.com/mail");
        assert!(path.exists(), "key not written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key must be 0o600");
        }

        // The daemon must be able to load it under the default selector.
        let manager = DkimManager::load(&dir.path().join("dkim"), "mail").unwrap();
        assert!(manager.has_signer("example.com"));

        // dns dkim must print the published record.
        dns_command(
            crate::cli::DnsCommand::Dkim {
                domain: "example.com".into(),
                selector: "mail".into(),
                format: crate::dns::DnsFormat::Human,
            },
            dir.path(),
        )
        .unwrap();
    }

    #[test]
    fn dkim_generate_refuses_existing_without_force() {
        use crate::cli::DkimCommand;
        let dir = temp_dir();
        let build = || DkimCommand::Generate {
            domain: "example.com".into(),
            selector: "mail".into(),
            algorithm: crate::cli::DkimKeyAlgorithm::Rsa,
            bits: 2048,
            force: false,
        };
        dkim_command(build(), dir.path()).unwrap();
        let err = dkim_command(build(), dir.path()).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");

        // --force overwrites.
        dkim_command(
            DkimCommand::Generate {
                domain: "example.com".into(),
                selector: "mail".into(),
                algorithm: crate::cli::DkimKeyAlgorithm::Rsa,
                bits: 2048,
                force: true,
            },
            dir.path(),
        )
        .unwrap();
    }

    #[test]
    fn dkim_generate_ed25519_roundtrips() {
        use crate::dkim::parse_key;
        let dir = temp_dir();
        dkim_command(
            crate::cli::DkimCommand::Generate {
                domain: "example.com".into(),
                selector: "mail".into(),
                algorithm: crate::cli::DkimKeyAlgorithm::Ed25519,
                bits: 2048,
                force: false,
            },
            dir.path(),
        )
        .unwrap();
        let pem = std::fs::read(dir.path().join("dkim/example.com/mail")).unwrap();
        assert!(parse_key(&pem).is_ok());
    }

    #[test]
    fn dkim_generate_rejects_invalid_selector() {
        use crate::cli::DkimCommand;
        let dir = temp_dir();
        let err = dkim_command(
            DkimCommand::Generate {
                domain: "example.com".into(),
                selector: "bad.selector".into(),
                algorithm: crate::cli::DkimKeyAlgorithm::Rsa,
                bits: 2048,
                force: false,
            },
            dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid"), "{err}");
        assert!(!dir.path().join("dkim/example.com").exists());
    }

    #[test]
    fn dns_dkim_errors_when_key_missing() {
        let dir = temp_dir();
        let err = dns_command(
            crate::cli::DnsCommand::Dkim {
                domain: "nope.com".into(),
                selector: "mail".into(),
                format: crate::dns::DnsFormat::Human,
            },
            dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("no DKIM key"), "{err}");
    }

    #[test]
    fn dns_spf_renders_record() {
        let dir = temp_dir();
        dns_command(
            crate::cli::DnsCommand::Spf {
                domain: "example.com".into(),
                ip: vec!["1.2.3.4".into()],
                include: vec![],
                auto_ip: false,
                hostname: Some("mail.example.com".into()),
                format: crate::dns::DnsFormat::Human,
            },
            dir.path(),
        )
        .unwrap();
    }
}
