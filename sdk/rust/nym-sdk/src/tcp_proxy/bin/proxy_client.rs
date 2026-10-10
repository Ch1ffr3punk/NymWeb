use anyhow::Result;
use clap::Parser;
use nym_sdk::tcp_proxy;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, default_value_t = 30)]
    close_timeout: u64,

    #[clap(long, default_value = "127.0.0.1")]
    listen_address: String,

    #[clap(long, default_value = "8080")]
    listen_port: String,

    #[clap(short, long)]
    env_path: Option<String>,

    #[clap(long, default_value_t = 2)]
    client_pool_reserve: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    nym_bin_common::logging::setup_tracing_logger();
    let args = Args::parse();

    let proxy_client = tcp_proxy::NymProxyClient::new(
        &args.listen_address,
        &args.listen_port,
        args.close_timeout,
        args.env_path.clone(),
        args.client_pool_reserve,
    )
    .await?;

    proxy_client.run().await?;
    Ok(())
}
