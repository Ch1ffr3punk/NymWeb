// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::client_pool::ClientPool;
use crate::mixnet::{IncludedSurbs, MixnetClientBuilder, MixnetMessageSender, NymNetworkDetails};
use crate::tcp_proxy::http_connect::{try_http_connect, ConnectOutcome};
use crate::tcp_proxy::utils::{MessageBuffer, Payload, ProxiedMessage};
use anyhow::Result;
use dashmap::DashSet;
use nym_network_defaults::setup_env;
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument};

const DEFAULT_CLOSE_TIMEOUT: u64 = 60;
const DEFAULT_LISTEN_HOST: &str = "127.0.0.1";
const DEFAULT_LISTEN_PORT: &str = "8080";
const DEFAULT_CLIENT_POOL_SIZE: usize = 2;

#[derive(Clone)]
pub struct NymProxyClient {
    listen_address: String,
    listen_port: String,
    close_timeout: u64,
    conn_pool: ClientPool,
    cancel_token: CancellationToken,
}

impl NymProxyClient {
    pub async fn new(
        listen_address: &str,
        listen_port: &str,
        close_timeout: u64,
        env: Option<String>,
        default_client_amount: usize,
    ) -> Result<Self> {
        debug!("Loading env file: {:?}", env);
        setup_env(env);

        Ok(NymProxyClient {
            listen_address: listen_address.to_string(),
            listen_port: listen_port.to_string(),
            close_timeout,
            conn_pool: ClientPool::new(default_client_amount),
            cancel_token: CancellationToken::new(),
        })
    }

    pub async fn new_with_defaults(env: Option<String>) -> Result<Self> {
        NymProxyClient::new(
            DEFAULT_LISTEN_HOST,
            DEFAULT_LISTEN_PORT,
            DEFAULT_CLOSE_TIMEOUT,
            env,
            DEFAULT_CLIENT_POOL_SIZE,
        )
        .await
    }

    pub async fn run(&self) -> Result<()> {
        info!("NymProxyClient running in HTTP proxy mode only");

        let listener =
            TcpListener::bind(format!("{}:{}", self.listen_address, self.listen_port)).await?;
        let client_maker = self.conn_pool.clone();
        tokio::spawn(async move {
            client_maker.start().await?;
            Ok::<(), anyhow::Error>(())
        });

        loop {
            tokio::select! {
                stream = listener.accept() => {
                    let (stream, peer) = stream?;
                    info!("Accepted connection from {}", peer);
                    let close_timeout = self.close_timeout;
                    let pool = self.conn_pool.clone();
                    let cancel = self.cancel_token.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_incoming(
                            stream, close_timeout, pool, cancel,
                        ).await {
                            tracing::warn!("session terminated with error: {e:#}");
                        }
                    });
                }
                _ = self.cancel_token.cancelled() => {
                    break Ok(());
                }
            }
        }
    }

    pub async fn disconnect(&self) {
        self.cancel_token.cancel();
        self.conn_pool.disconnect_pool().await;
    }

    #[instrument(skip(stream, close_timeout, conn_pool, cancel_token))]
    async fn handle_incoming(
        stream: TcpStream,
        close_timeout: u64,
        conn_pool: ClientPool,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        // Nur HTTP-Proxy-Anfragen werden verarbeitet
        let (server_addr, stream) = match try_http_connect(stream).await? {
            ConnectOutcome::Tunneled { target, stream } => {
                info!("HTTP proxy to {}", target);
                (target, stream)
            }
        };

        let session_id = uuid::Uuid::new_v4();
        let (tx, mut rx) = oneshot::channel();
        info!("Starting session: {}", session_id);

        let mut client = match conn_pool.get_mixnet_client().await {
            Some(c) => {
                info!("Grabbed client {} from pool", c.nym_address());
                c
            }
            None => {
                info!("Creating ephemeral mixnet client");
                let net = NymNetworkDetails::new_from_env();
                let c = MixnetClientBuilder::new_ephemeral()
                    .network_details(net)
                    .build()?
                    .connect_to_mixnet()
                    .await?;
                info!("Ephemeral client: {}", c.nym_address());
                c
            }
        };

        let (read, mut write) = stream.into_split();
        let codec = BytesCodec::new();
        let mut framed_read = FramedRead::new(read, codec);
        let sender = client.split_sender();
        let server_addr_static = server_addr;
        let messages_account = Arc::new(DashSet::new());
        let sent_messages_account = Arc::clone(&messages_account);

        tokio::spawn(async move {
            let mut message_id = 0u16;
            while let Some(Ok(bytes)) = framed_read.next().await {
                message_id = message_id.wrapping_add(1);
                sent_messages_account.insert(message_id);
                let message =
                    ProxiedMessage::new(Payload::Data(bytes.to_vec()), session_id, message_id);
                let coded = bincode::serialize(&message)?;
                sender
                    .send_message(server_addr_static, &coded, IncludedSurbs::Amount(100))
                    .await?;
                info!(
                    "Sent msg {} for session {} ({} bytes)",
                    message_id, session_id, bytes.len()
                );
            }
            message_id = message_id.wrapping_add(1);
            let close_msg = ProxiedMessage::new(Payload::Close, session_id, message_id);
            let coded = bincode::serialize(&close_msg)?;
            sender
                .send_message(server_addr_static, &coded, IncludedSurbs::Amount(100))
                .await?;
            info!("Closing read end of session {}", session_id);
            tx.send(true).map_err(|_| anyhow::anyhow!("close signal failed"))?;
            Ok::<(), anyhow::Error>(())
        });

        tokio::spawn(async move {
            let mut msg_buffer = MessageBuffer::new();
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        info!("Closing write end of session {} in {}s", session_id, close_timeout);
                        break;
                    }
                    Some(message) = client.next() => {
                        let message = bincode::deserialize::<ProxiedMessage>(&message.message)?;
                        msg_buffer.push(message);
                        msg_buffer.tick(&mut write).await?;
                    },
                    _ = cancel_token.cancelled() => {
                        info!("CTRL_C in thread, shutting down");
                        break;
                    },
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        msg_buffer.tick(&mut write).await?;
                    }
                }
            }
            loop {
                tokio::select! {
                    Some(message) = client.next() => {
                        let message = bincode::deserialize::<ProxiedMessage>(&message.message)?;
                        msg_buffer.push(message);
                        msg_buffer.tick(&mut write).await?;
                    },
                    _ = cancel_token.cancelled() => {
                        info!("CTRL_C, disconnecting client");
                        client.disconnect().await;
                        return Ok::<(), anyhow::Error>(());
                    },
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(close_timeout)) => {
                        info!("Idle timeout for session {}", session_id);
                        client.disconnect().await;
                        return Ok::<(), anyhow::Error>(());
                    },
                }
            }
        });

        Ok(())
    }
}
