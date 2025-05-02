pub mod vrrp;

use clap::Parser;
use log::{error, info};
use tokio::runtime::Builder;
use tokio::sync::mpsc::channel;
use vrrp::{start_vrouter_cfile, start_listener};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of network interface, defaults to lo. Required for Read Only mode (without -r flag) only.
    #[arg(short, default_value_t = String::from("eth0"))]
    interface: String,
    /// Option to run in Virtual Router mode, defaults to false. Multicast advertise packet if set, otherwise just print received VRRPv2 packet on the specified interface.
    #[arg(short, default_value_t = false)]
    router: bool,
    /// Path to the virtual router config file, defaults to vrrp.toml in working dir. Required for Virtual Router mode only.
    #[arg(short, default_value_t = String::from("vrrp.toml"))]
    config_file_path: String,
    /// Enable verbose log output.
    #[arg(short('v'), default_value_t = false)]
    verbose: bool,
    #[arg(short('d'))]
    debug: bool,
}

fn main() {
    let args = Args::parse();

    std::env::set_var("RUST_LOG", if args.verbose { "debug" } else { "info" });

    env_logger::init();

    if args.debug {
        /* Test code here */
        return;
    }

    let (shutdown_tx, shutdown_rx) = channel::<()>(1);

    match args.router {
        true => {
            let runtime = match Builder::new_multi_thread()
                .enable_all()
                .worker_threads(5)
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    error!("runtime creation failed: {}", err.to_string());
                    return;
                }
            };

            ctrlc::set_handler(move || {
                info!("received shutdown signal..");
                _ = shutdown_tx.blocking_send(());
            })
            .expect("failed to setup signal handler");

            match runtime.block_on(start_vrouter_cfile(
                format!("{}", &args.config_file_path),
                shutdown_rx,
            )) {
                Ok(()) => {
                    info!("Gracefully stopping router..");
                },
                Err(err) => {
                    error!("{}", err);
                },
            }

            info!("Shutting Down Router...");
        }
        false => {
            let runtime = match Builder::new_multi_thread()
                .enable_all()
                .worker_threads(5)
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    error!("runtime creation failed: {}", err.to_string());
                    return;
                }
            };

            ctrlc::set_handler(move || {
                info!("received shutdown signal..");
                _ = shutdown_tx.blocking_send(());
            })
            .expect("failed to setup signal handler");

            match runtime.block_on(start_listener(args.interface, shutdown_rx)) {
                Ok(()) => {
                    info!("Gracefully stopping listener..");
                },
                Err(err) => {
                    error!("{}", err);
                },
            }

            info!("Shutting Down Runtime...");
        }
    };
}
