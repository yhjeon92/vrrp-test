pub mod vrrp;

use aes_gcm::{
    aead::{Aead, AeadMut, Nonce, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use log::{error, info};
use nix::libc::newlocale;
use tokio::runtime::Builder;
use tokio::sync::mpsc::channel;
use vrrp::{start_vrouter_cfile, start_vrrp_listener};

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
        let key_str = "very_strong_line_of_password_pad";
        let key = Key::<Aes256Gcm>::from_slice(key_str.as_bytes());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let plaintext = "zalando";
        let cipher = Aes256Gcm::new(key);
        let ciphered_data = match cipher.encrypt(&nonce, plaintext.as_bytes()) {
            Ok(ciphered) => ciphered,
            Err(err) => {
                error!("{}", err.to_string());
                return;
            }
        };

        let mut encrypted_data: Vec<u8> = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphered_data);

        let encoded = BASE64_STANDARD.encode(encrypted_data);
        info!("{}", encoded);

        let decoded = BASE64_STANDARD
            .decode(encoded)
            .expect("failed to decode password string");

        let (nonce_arr, ciphered_arr) = decoded.split_at(12);

        let plaintext = cipher
            .decrypt(&nonce, ciphered_arr)
            .expect("failed to decrypt given password string");

        info!(
            "decoded: {}",
            String::from_utf8(plaintext).expect("failed to encode decrypted password string")
        );

        return;
    }

    match args.router {
        true => {
            let (shutdown_tx, shutdown_rx) = channel::<()>(1);

            let runtime = match Builder::new_multi_thread()
                .enable_all()
                .worker_threads(3)
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
                _ = shutdown_tx.clone().blocking_send(());
                _ = shutdown_tx.clone().blocking_send(());
            })
            .expect("failed to setup signal handler");

            runtime.block_on(start_vrouter_cfile(
                format!("{}", &args.config_file_path),
                shutdown_rx,
            ));
        }
        false => {
            start_vrrp_listener(args.interface);
        }
    };
}
