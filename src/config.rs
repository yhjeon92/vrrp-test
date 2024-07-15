use std::{fs::File, io::Read, net::Ipv4Addr};

use log::{error, info};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VRouterConfig {
    pub interface: String,
    pub router_id: u8,
    pub priority: u8,
    pub advert_int: u8,
    pub virtual_ip: Ipv4Addr,
}

impl VRouterConfig {
    pub fn dummy() -> VRouterConfig {
        VRouterConfig {
            interface: String::new(),
            router_id: 0,
            priority: 0,
            advert_int: 255,
            virtual_ip: Ipv4Addr::new(0, 0, 0, 0),
        }
    }

    pub fn from_file(path: &str) -> Option<VRouterConfig> {
        let mut contents = String::new();
        let mut file_handle = match File::open(path) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Failed to open configuration file {}: {}",
                    path,
                    err.to_string()
                );
                return None;
            }
        };

        match file_handle.read_to_string(&mut contents) {
            Ok(_) => {}
            Err(err) => {
                error!(
                    "Failed to read configuration file {}: {}",
                    path,
                    err.to_string()
                );
                return None;
            }
        }

        match toml::from_str::<VRouterConfig>(&contents) {
            Ok(config) => {
                info!("Router configured:");
                info!("\tInterface       {}", config.interface);
                info!("\tRouter ID       {}", config.router_id);
                info!("\tPriority        {}", config.priority);
                info!("\tAdvert Interval {}s", config.advert_int);
                info!("\tVirtual IP      {}", config.virtual_ip.to_string());
                Some(config)
            }
            Err(err) => {
                error!(
                    "Failed to parse configuration from given file {}: {}",
                    path,
                    err.to_string()
                );
                None
            }
        }
    }
}
