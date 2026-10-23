use clap::Parser;
use openshell_attestation_observer::{Observer, proto::kbs_plugin_server::KbsPluginServer};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(about = "Read existing Trustee sessions and serve display-only reports through KBS")]
struct Args {
    #[arg(long)]
    sessions: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    as_public_key: PathBuf,
    #[arg(long, default_value = "127.0.0.1:50005")]
    listen: SocketAddr,
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..))]
    interval_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if !args.listen.ip().is_loopback() {
        return Err("the plugin must listen on Trustee's loopback interface".into());
    }
    tracing_subscriber::fmt().init();
    let observer = Observer::with_key_file(args.sessions, args.output, args.as_public_key)?;
    let poller = observer.clone();
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(args.interval_seconds));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            poller.scan().await;
        }
    });
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    notify_ready()?;
    let result = tonic::transport::Server::builder()
        .add_service(KbsPluginServer::new(observer))
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(listener),
            async {
                let _ = tokio::signal::ctrl_c().await;
            },
        )
        .await;
    task.abort();
    result?;
    Ok(())
}

fn notify_ready() -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixDatagram},
    };
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let bytes = path.as_os_str().as_bytes();
    let address = if bytes.first() == Some(&b'@') {
        SocketAddr::from_abstract_name(&bytes[1..])?
    } else {
        SocketAddr::from_pathname(path)?
    };
    UnixDatagram::unbound()?.send_to_addr(b"READY=1", &address)?;
    Ok(())
}
