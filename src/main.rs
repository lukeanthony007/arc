use std::io::{self, BufRead, IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{Result, ensure};
use arc_store::{app, format};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "arc",
    version,
    about = "Experimental encrypted snapshots and offline transfer (arc-exp-1)"
)]
struct Cli {
    /// Read one password line from standard input instead of a terminal prompt.
    #[arg(long, global = true)]
    password_stdin: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a NEW private node. Prints the trusted genesis ID to retain separately.
    Init { node: PathBuf },
    /// Capture a directory into an encrypted snapshot; source symlinks/special files are rejected.
    Capture { node: PathBuf, source: PathBuf },
    /// Check signatures, ancestry and ciphertext coverage; --decrypt also checks file bytes.
    Verify {
        node: PathBuf,
        snapshot: String,
        #[arg(long)]
        decrypt: bool,
    },
    /// Restore an exact snapshot into a NEW directory; never overwrite an existing destination.
    Restore {
        node: PathBuf,
        snapshot: String,
        destination: PathBuf,
    },
    /// Export ciphertext, trusted genesis and ancestry descriptors; excludes secret keys.
    Export {
        node: PathBuf,
        snapshot: String,
        destination: PathBuf,
    },
    /// Import opaque objects without changing collection identity or selecting a current head.
    Import { node: PathBuf, source: PathBuf },
    /// Export the existing password-protected root/data keys; carries NO file content.
    RecoveryExport { node: PathBuf, destination: PathBuf },
    /// Recover a node using an encrypted kit and a separately trusted genesis ID.
    /// Restores the SAME device identity; keep the old writer offline.
    Recover {
        node: PathBuf,
        kit: PathBuf,
        #[arg(long)]
        trust_genesis: String,
    },
}

fn password(from_stdin: bool, confirm: bool) -> Result<Zeroizing<String>> {
    let value = if from_stdin {
        let mut line = Zeroizing::new(String::new());
        let count = io::stdin().lock().take(4098).read_line(&mut line)?;
        ensure!(
            count > 0 && count <= 4097,
            "missing or oversized password input"
        );
        while line.ends_with(['\n', '\r']) {
            line.pop();
        }
        line
    } else {
        ensure!(
            io::stdin().is_terminal(),
            "use --password-stdin explicitly when piping a password"
        );
        let first = Zeroizing::new(rpassword::prompt_password("Password: ")?);
        if confirm {
            let second = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
            ensure!(*first == *second, "passwords do not match");
        }
        first
    };
    ensure!(
        !value.is_empty() && value.len() <= 4096,
        "password must contain 1–4096 bytes"
    );
    Ok(value)
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { node } => {
            let secret = password(cli.password_stdin, true)?;
            let genesis = app::init(&node, &secret)?;
            println!("genesis {}", format::display_id(&genesis));
        }
        Command::Capture { node, source } => {
            let secret = password(cli.password_stdin, false)?;
            let id = app::capture(&node, &source, &secret)?;
            println!("snapshot {}", format::display_id(&id));
        }
        Command::Verify {
            node,
            snapshot,
            decrypt,
        } => {
            let secret = if decrypt {
                Some(password(cli.password_stdin, false)?)
            } else {
                None
            };
            let result = app::verify(
                &node,
                &format::parse_id(&snapshot)?,
                secret.as_ref().map(|s| s.as_str()),
            )?;
            println!("snapshot {}", format::display_id(&result.snapshot));
            println!("genesis {}", format::display_id(&result.genesis));
            println!(
                "ciphertext_closure complete objects={} bytes={}",
                result.objects, result.bytes
            );
            println!("ancestry verified descriptors={}", result.ancestors);
            println!(
                "plaintext {}",
                if result.materialized {
                    "verified"
                } else {
                    "not_checked"
                }
            );
            println!("global_freshness unknown");
        }
        Command::Restore {
            node,
            snapshot,
            destination,
        } => {
            let secret = password(cli.password_stdin, false)?;
            app::restore(&node, &format::parse_id(&snapshot)?, &destination, &secret)?;
            println!("restored selected snapshot into new destination");
        }
        Command::Export {
            node,
            snapshot,
            destination,
        } => {
            app::export(&node, &format::parse_id(&snapshot)?, &destination)?;
            println!("exported selected ciphertext closure and ancestry; keys excluded");
        }
        Command::Import { node, source } => {
            let count = app::import(&node, &source)?;
            println!(
                "imported objects={count}; identity and head unchanged; snapshot authorization not checked"
            );
        }
        Command::RecoveryExport { node, destination } => {
            app::export_recovery(&node, &destination)?;
            println!("exported password-protected root/data keys; file content excluded");
        }
        Command::Recover {
            node,
            kit,
            trust_genesis,
        } => {
            let secret = password(cli.password_stdin, false)?;
            app::recover(&node, &kit, &format::parse_id(&trust_genesis)?, &secret)?;
            println!(
                "recovered same single-device identity; no data imported and no current head selected"
            );
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("arc: {error:#}");
        std::process::exit(1);
    }
}
