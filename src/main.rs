use vulnera_adapter::{Config, run_stdio};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("VULNERA_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_thread_ids(false)
        .init();

    let config = Config::from_env();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        api_url = %config.api_url,
        "vulnera-adapter starting"
    );

    if let Err(err) = run_stdio(config).await {
        tracing::error!(%err, "vulnera-adapter fatal error");
        std::process::exit(1);
    }
}
