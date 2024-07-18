use clap::Parser;
use log::error;
use tokio::runtime::Builder;
use vrrp_test::{debugger, start_vrouter_cfile_async, start_vrrp_listener};

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
        debugger(&args.interface);
        return;
    }

    match args.router {
        true => {
            // start_virutal_router(&args.config_file_path);
            // let runtime = match Builder::new_current_thread()
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

            runtime.block_on(start_vrouter_cfile_async(&args.config_file_path));
        }
        false => {
            start_vrrp_listener(args.interface);
        }
    };
}
