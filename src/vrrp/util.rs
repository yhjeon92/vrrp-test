use std::process::Command;

use log::{info, warn};

pub fn execute_command(command: String) -> Result<(), String> {
    let mut elements = command.split_whitespace();

    match elements.next() {
        Some(program) => {
            let mut cmd = Command::new(program);
            elements.by_ref().for_each(|arg| {
                cmd.arg(arg);
            });

            match cmd.output() {
                Ok(output) => {
                    match output.status.code().unwrap() {
                        0 => {
                            info!(
                                "Command {} returned {} with status code 0",
                                command,
                                String::from_utf8(output.stdout).unwrap().trim_end()
                            );
                        }
                        code => {
                            warn!(
                                "Command {} failed with status code {}: {}",
                                command,
                                code,
                                String::from_utf8(output.stderr).unwrap().trim_end()
                            );
                        }
                    }

                    Ok(())
                }
                Err(err) => {
                    warn!("Command {} failed: {}", command, err.to_string());
                    Err(err.to_string())
                }
            }
        }
        None => {
            warn!(
                "Command {} seems to be empty. Check your configuration.",
                command
            );
            Ok(())
        }
    }
}

pub fn byte_array_into_string(buf: &[u8]) -> String {
    format!(
        "{}",
        buf.iter()
            .map(|byte| format!("{:02X?} ", byte))
            .collect::<String>()
    )
}
