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
    about = "Experimental encrypted storage, recoverable membership and resumable sync"
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
    /// Export an authenticated encrypted backup of retained objects, identity, policy and keys.
    RecoveryExport { node: PathBuf, destination: PathBuf },
    /// Recover a node using an encrypted kit and a separately trusted genesis ID.
    /// Restores the SAME device identity; keep the old writer offline.
    Recover {
        node: PathBuf,
        kit: PathBuf,
        #[arg(long)]
        trust_genesis: String,
    },
    /// Explain local identity, working version, branches and incomplete work without unlocking.
    Status { node: PathBuf },
    /// Check local ciphertext integrity and report actionable findings; never repairs or decrypts.
    Doctor { node: PathBuf },
    /// List locally known snapshots and their status.
    History { node: PathBuf },
    /// Compare two authorized snapshots.
    Diff {
        node: PathBuf,
        older: String,
        newer: String,
    },
    /// Deliberately select an imported/recovered version as the working base.
    Select { node: PathBuf, snapshot: String },
    /// Capture an explicitly resolved directory with every resolved head as a parent.
    Merge {
        node: PathBuf,
        source: PathBuf,
        #[arg(long, required = true, num_args = 2..)]
        parents: Vec<String>,
    },
    /// Create an independent password-protected transport identity.
    NetworkIdentity { destination: PathBuf },
    /// Exchange opaque node objects with a pinned peer; keys/head excluded.
    Sync {
        node: PathBuf,
        address: std::net::SocketAddr,
        identity: PathBuf,
        peer_key: String,
    },
    /// Serve one authenticated exchange in the foreground, then exit.
    ServeOnce {
        node: PathBuf,
        address: std::net::SocketAddr,
        identity: PathBuf,
        peer_key: String,
    },
    /// Exchange encrypted objects through an explicitly prepared Linux /dev/rfcommN endpoint.
    BluetoothSync {
        node: PathBuf,
        endpoint: PathBuf,
        identity: PathBuf,
        peer_key: String,
        /// Act as the Noise responder; the peer must act as initiator.
        #[arg(long)]
        respond: bool,
    },
    /// Complete an authenticated interrupted membership transaction; never erase an unknown guard.
    Repair { node: PathBuf },
    /// Discard one incomplete object's staged fragments, leaving verified objects unchanged.
    PartialDiscard { node: PathBuf, object: String },
    /// Activate signed device policy on an administrator node.
    EnablePolicy { node: PathBuf },
    /// Generate independent signing/envelope keys and a public enrollment request.
    DeviceRequest {
        private_key: PathBuf,
        request: PathBuf,
    },
    /// Grant a reviewed public device request reader or writer permission.
    Grant {
        node: PathBuf,
        request: PathBuf,
        invitation: PathBuf,
        #[arg(value_enum)]
        role: Access,
    },
    /// Join using an invitation and a separately verified genesis ID.
    Join {
        node: PathBuf,
        private_key: PathBuf,
        invitation: PathBuf,
        #[arg(long)]
        trust_genesis: String,
    },
    /// Revoke a device and rotate keys for the remaining supplied public requests.
    Revoke {
        node: PathBuf,
        device_key: String,
        rotation: PathBuf,
        #[arg(long)]
        requests: Vec<PathBuf>,
    },
    /// Apply a signed successor policy and this device's fresh key envelope.
    ApplyPolicy {
        node: PathBuf,
        private_key: PathBuf,
        rotation: PathBuf,
    },
    /// Distribute the current policy and keys to existing members after enrollment.
    Refresh {
        node: PathBuf,
        package: PathBuf,
        #[arg(long, required = true)]
        requests: Vec<PathBuf>,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum Access {
    Reader,
    Writer,
}

fn read_request(path: &std::path::Path) -> Result<arc_store::enrollment::Request> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    ensure!(file.metadata()?.is_file(), "request must be a regular file");
    let mut bytes = Vec::new();
    file.take(257).read_to_end(&mut bytes)?;
    arc_store::enrollment::Request::decode(&bytes)
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

fn inventory(store: &arc_store::store::Store) -> Result<Vec<format::Id>> {
    let mut ids = Vec::new();
    let mut scanned = 0;
    for entry in std::fs::read_dir(store.path().join("objects"))? {
        scanned += 1;
        ensure!(scanned <= 16_384, "object inventory exceeds transfer limit");
        let name = entry?.file_name();
        if let Some(name) = name.to_str()
            && let Ok(id) = format::parse_id(name)
        {
            store.get(&id)?;
            ids.push(id);
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
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
            let secret = password(cli.password_stdin, false)?;
            app::export_recovery(&node, &destination, &secret)?;
            println!(
                "exported authenticated recovery backup; keep it private and retire the original identity before recovery"
            );
        }
        Command::Recover {
            node,
            kit,
            trust_genesis,
        } => {
            let secret = password(cli.password_stdin, false)?;
            app::recover(&node, &kit, &format::parse_id(&trust_genesis)?, &secret)?;
            println!(
                "recovered the backed-up device identity; policy freshness beyond the backup is unknown; retire the original device before publishing"
            );
        }
        Command::Status { node } => {
            println!("{}", arc_store::diagnostics::status(&node)?);
        }
        Command::Doctor { node } => {
            let report = arc_store::diagnostics::doctor(&node)?;
            print!("{report}");
            ensure!(
                !report.has_errors(),
                "node diagnostics found errors; no changes made"
            );
        }
        Command::History { node } => {
            for entry in arc_store::history::list(&node)? {
                let parents = entry
                    .parents
                    .iter()
                    .map(format::display_id)
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "{} head={} selected={} parents={}",
                    format::display_id(&entry.id),
                    entry.is_head,
                    entry.is_selected,
                    parents
                );
            }
        }
        Command::Diff { node, older, newer } => {
            let secret = password(cli.password_stdin, false)?;
            for change in arc_store::history::diff(
                &node,
                &format::parse_id(&older)?,
                &format::parse_id(&newer)?,
                &secret,
            )? {
                println!("{:?} {}", change.kind, change.path);
            }
        }
        Command::Select { node, snapshot } => {
            arc_store::history::select(&node, &format::parse_id(&snapshot)?)?;
            println!("selected explicit working base; competing heads retained");
        }
        Command::Merge {
            node,
            source,
            parents,
        } => {
            let secret = password(cli.password_stdin, false)?;
            let parents: Vec<_> = parents
                .iter()
                .map(|p| format::parse_id(p))
                .collect::<Result<_>>()?;
            let id = app::merge_capture(&node, &source, &parents, &secret)?;
            println!("snapshot {}", format::display_id(&id));
        }
        Command::NetworkIdentity { destination } => {
            let secret = password(cli.password_stdin, true)?;
            let public = arc_store::network::identity_create(&destination, &secret)?;
            println!("transport_public {}", hex::encode(public));
        }
        Command::Sync {
            node,
            address,
            identity,
            peer_key,
        } => {
            let password = password(cli.password_stdin, false)?;
            let secret = arc_store::network::identity_load(&identity, &password)?;
            let peer = format::parse_id(&peer_key)?;
            let store = arc_store::store::Store::open(&node)?;
            let report = arc_store::network::sync_client(
                address,
                &store,
                &*secret,
                &peer,
                &inventory(&store)?,
            )?;
            println!("{report:?}; imported bytes do not change trust or selected head");
        }
        Command::ServeOnce {
            node,
            address,
            identity,
            peer_key,
        } => {
            let password = password(cli.password_stdin, false)?;
            let secret = arc_store::network::identity_load(&identity, &password)?;
            let peer = format::parse_id(&peer_key)?;
            let store = arc_store::store::Store::open(&node)?;
            let listener = std::net::TcpListener::bind(address)?;
            println!("listening {}", listener.local_addr()?);
            let report = arc_store::network::serve_once(
                &listener,
                &store,
                &*secret,
                &peer,
                &inventory(&store)?,
            )?;
            println!("{report:?}; imported bytes do not change trust or selected head");
        }
        Command::BluetoothSync {
            node,
            endpoint,
            identity,
            peer_key,
            respond,
        } => {
            let password = password(cli.password_stdin, false)?;
            let secret = arc_store::network::identity_load(&identity, &password)?;
            let peer = format::parse_id(&peer_key)?;
            let store = arc_store::store::Store::open(&node)?;
            let ids = inventory(&store)?;
            let report = if respond {
                arc_store::bluetooth::accept(&endpoint, &store, &*secret, &peer, &ids)?
            } else {
                arc_store::bluetooth::connect(&endpoint, &store, &*secret, &peer, &ids)?
            };
            println!("{report:?}; imported bytes do not change trust or selected head");
        }
        Command::Repair { node } => {
            let secret = password(cli.password_stdin, false)?;
            arc_store::devices::repair(&node, &secret)?;
            println!(
                "membership transaction repaired or no pending transaction; unknown guards remain blocked"
            );
        }
        Command::PartialDiscard { node, object } => {
            let store = arc_store::store::Store::open(&node)?;
            let receiver = arc_store::fragments::Receiver::open(&store.path().join("incoming"))?;
            receiver.discard(&format::parse_id(&object)?)?;
            println!("discarded selected incomplete object state; verified objects unchanged");
        }
        Command::EnablePolicy { node } => {
            let secret = password(cli.password_stdin, false)?;
            arc_store::devices::enable(&node, &secret)?;
            println!("enabled signed membership policy");
        }
        Command::DeviceRequest {
            private_key,
            request,
        } => {
            let secret = password(cli.password_stdin, true)?;
            let request = arc_store::devices::create_request(&private_key, &request, &secret)?;
            println!("device_public {}", hex::encode(request.signing));
        }
        Command::Grant {
            node,
            request,
            invitation,
            role,
        } => {
            let secret = password(cli.password_stdin, false)?;
            let role = match role {
                Access::Reader => arc_store::policy::Role::Reader,
                Access::Writer => arc_store::policy::Role::Writer,
            };
            arc_store::devices::grant(&node, &request, &invitation, role, &secret)?;
            println!("created recipient-bound invitation");
        }
        Command::Join {
            node,
            private_key,
            invitation,
            trust_genesis,
        } => {
            let secret = password(cli.password_stdin, false)?;
            arc_store::devices::join_node(
                &node,
                &private_key,
                &invitation,
                format::parse_id(&trust_genesis)?,
                &secret,
            )?;
            println!("joined collection with independent device keys");
        }
        Command::Revoke {
            node,
            device_key,
            rotation,
            requests,
        } => {
            let secret = password(cli.password_stdin, false)?;
            let requests = requests
                .iter()
                .map(|p| read_request(p))
                .collect::<Result<Vec<_>>>()?;
            arc_store::devices::revoke(
                &node,
                format::parse_id(&device_key)?,
                &requests,
                &rotation,
                &secret,
            )?;
            println!("created revocation and key rotation package; offline peers must receive it");
        }
        Command::ApplyPolicy {
            node,
            private_key,
            rotation,
        } => {
            let secret = password(cli.password_stdin, false)?;
            arc_store::devices::apply(&node, &private_key, &rotation, &secret)?;
            println!("applied signed successor policy and device key envelope");
        }
        Command::Refresh {
            node,
            package,
            requests,
        } => {
            let secret = password(cli.password_stdin, false)?;
            let requests = requests
                .iter()
                .map(|p| read_request(p))
                .collect::<Result<Vec<_>>>()?;
            arc_store::devices::refresh(&node, &requests, &package, &secret)?;
            println!("created recipient-bound policy refresh package");
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
