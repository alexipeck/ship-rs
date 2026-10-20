use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ship::config::{self, Config};
use ship::deploy;
use ship::envfile;
use ship::generate;
use ship::secrets;
use ship::server;
use ship::version;

#[derive(Parser)]
#[command(name = "ship-rs", disable_help_flag = true, disable_version_flag = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "")]
        config: String,
        #[arg(long, default_value = "")]
        env_file: String,
    },
    Generate {
        #[arg(long, default_value = "")]
        config: String,
        #[arg(long, default_value = "")]
        caddyfile: String,
        #[arg(long, default_value = "")]
        hub: String,
    },
    Deploy {
        #[arg(long, default_value = "")]
        config: String,
        #[arg(long, default_value = "")]
        caddyfile: String,
        #[arg(long, default_value = "")]
        hub: String,
        #[arg(long)]
        reload: bool,
    },
    Validate {
        #[arg(long, default_value = "")]
        config: String,
    },
    Version,
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage(&mut io::stderr());
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            usage(&mut io::stderr());
            return ExitCode::SUCCESS;
        }
        "version" | "-version" | "--version" if args.len() == 1 => {
            println!("{}", version::version());
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    if args[0] == "serve" || args[0] == "generate" || args[0] == "deploy" || args[0] == "validate" {
        let config_from_env = env::var("SHIP_CONFIG").unwrap_or_default();
        if !config_from_env.is_empty() && !args.iter().any(|a| a == "--config" || a.starts_with("--config=")) {
            args.insert(1, "--config".into());
            args.insert(2, config_from_env);
        }
    }
    let cli = match Cli::try_parse_from(std::iter::once("ship-rs".to_string()).chain(args)) {
        Ok(cli) => cli,
        Err(err) => {
            let _ = write!(io::stderr(), "{err}");
            let code = if err.use_stderr() { 2 } else { 0 };
            return ExitCode::from(code);
        }
    };
    let result = match cli.command {
        Command::Serve { config, env_file } => serve(&config, &env_file).await,
        Command::Generate { config, caddyfile, hub } => generate_cmd(&config, &caddyfile, &hub),
        Command::Deploy { config, caddyfile, hub, reload } => deploy_cmd(&config, &caddyfile, &hub, reload),
        Command::Validate { config } => validate_cmd(&config),
        Command::Version => {
            println!("{}", version::version());
            Ok(())
        }
    };
    if let Err(err) = result {
        let _ = writeln!(io::stderr(), "ship-rs: {err}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn usage(out: &mut impl Write) {
    let _ = writeln!(
        out,
        "ship-rs {version}

Usage:
  ship-rs serve --config PATH [--env-file PATH]
  ship-rs generate --config PATH [--caddyfile PATH] [--hub PATH]
  ship-rs deploy --config PATH [--caddyfile PATH] [--hub PATH] [--reload]
  ship-rs validate --config PATH
  ship-rs version

--config is the installation's sites.toml, for example /etc/ship-rs/sites.toml.
Secrets come from the environment or --env-file, never from the TOML file.",
        version = version::version()
    );
}

async fn serve(config_path: &str, env_file: &str) -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .init();
    if !env_file.is_empty() {
        envfile::load(Path::new(env_file)).map_err(|e| e.to_string())?;
    }
    if config_path.trim().is_empty() {
        return Err("set --config or SHIP_CONFIG".into());
    }
    let sec = secrets::from_env(|k| env::var(k).unwrap_or_default())?;
    if sec.allow_unsafe {
        tracing::warn!("unsafe OAuth endpoint overrides are enabled; do not use this on a public server");
    }
    if !sec.google_enabled() && !sec.github_enabled() {
        tracing::warn!("no OAuth providers configured; protected sites cannot be signed into");
    }
    let store = config::Store::open(Path::new(config_path))?;
    let cfg = store.current();
    let addr = if sec.listen.is_empty() {
        cfg.auth_upstream.clone()
    } else if sec.listen != cfg.auth_upstream {
        return Err(format!("SHIP_LISTEN {} does not match auth_upstream {}", sec.listen, cfg.auth_upstream));
    } else {
        sec.listen.clone()
    };
    let svc = server::Service::new(store, sec);
    tracing::info!(version = version::version(), config = %cfg.path.display(), domain = %cfg.base_domain, "ship-rs");
    svc.run(&addr).await
}

fn generate_cmd(config_path: &str, caddyfile: &str, hub: &str) -> Result<(), String> {
    let cfg = must_config(config_path, caddyfile, hub)?;
    generate::write(&cfg)?;
    println!("wrote {}", cfg.caddyfile.display());
    println!("wrote {}", cfg.hub.deploy.join("index.html").display());
    Ok(())
}

fn deploy_cmd(config_path: &str, caddyfile: &str, hub: &str, reload: bool) -> Result<(), String> {
    let cfg = must_config(config_path, caddyfile, hub)?;
    deploy::deploy(&cfg, reload)?;
    println!("deployed from {}", cfg.path.display());
    Ok(())
}

fn validate_cmd(config_path: &str) -> Result<(), String> {
    let cfg = must_config(config_path, "", "")?;
    println!("base domain: {}", cfg.base_domain);
    println!("tls: {}", cfg.tls);
    println!("http port: {}", cfg.http_port);
    println!("https port: {}", cfg.https_port);
    println!("auth upstream: {}", cfg.auth_upstream);
    println!("auth origin: {}", cfg.auth_origin());
    println!("admins: {}", cfg.admins.join(", "));
    println!("hub: {}", cfg.hub.deploy.display());
    println!("caddyfile: {}", cfg.caddyfile.display());
    if !cfg.preview_addr.is_empty() {
        println!("preview: http://{}", cfg.preview_addr);
    }
    for site in &cfg.sites {
        let access = if site.public { "public" } else { "protected" };
        let state = if site.enabled { "enabled" } else { "disabled" };
        let mut extra = String::new();
        if site.spa {
            extra.push_str(" spa");
        }
        if site.unlisted {
            extra.push_str(" unlisted");
        }
        println!("  {} {} {} {} allow={}{}", site.slug, state, access, cfg.site_origin(site), site.allow.len(), extra);
        println!("    deploy {}", site.deploy.display());
        if let Some(source) = &site.source {
            println!("    source {}", source.display());
        }
    }
    Ok(())
}

fn must_config(path: &str, caddyfile: &str, hub: &str) -> Result<Config, String> {
    if path.trim().is_empty() {
        return Err("set --config or SHIP_CONFIG".into());
    }
    let mut cfg = config::load(Path::new(path))?;
    if !caddyfile.is_empty() {
        cfg.caddyfile = config::abs_path(Path::new(caddyfile)).map_err(|e| e.to_string())?;
    }
    if !hub.is_empty() {
        cfg.hub.deploy = config::abs_path(Path::new(hub)).map_err(|e| e.to_string())?;
    }
    if cfg.caddyfile.as_os_str().is_empty() {
        return Err("set caddyfile in sites.toml or pass --caddyfile".into());
    }
    Ok(cfg)
}
