pub mod engine;
pub mod pipe_server;

pub fn service_identity() -> String {
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "SYSTEM".to_owned());
    let machine = machine_name();
    format!("{user}@{machine}")
}

pub fn machine_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "LOCALHOST".to_owned())
}
