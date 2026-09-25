//! glmcli — the CLI EXECUTION HOST over the shared client engine
//! [W13 step 2: one shared engine, CLI + service as execution hosts;
//! the tray is a service client and never hosts engine logic].
//! This bin owns the tokio runtime and nothing else.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    aztna_client::run().await
}
