use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_acl::{AclRequirement, AuthContext, TokenValidator};
use shroudb_protocol_wire::Resp3Frame;
use shroudb_server_tcp::ServerProtocol;
use shroudb_veil_engine::engine::VeilEngine;
use shroudb_veil_protocol::commands::{VeilCommand, parse_command};
use shroudb_veil_protocol::dispatch::dispatch;
use shroudb_veil_protocol::response::VeilResponse;

pub struct VeilProtocol;

impl ServerProtocol for VeilProtocol {
    type Command = VeilCommand;
    type Response = VeilResponse;
    type Engine = VeilEngine<shroudb_storage::EmbeddedStore>;

    fn engine_name(&self) -> &str {
        "veil"
    }

    fn parse_command(&self, args: &[&str]) -> Result<Self::Command, String> {
        parse_command(args)
    }

    fn auth_token(cmd: &Self::Command) -> Option<&str> {
        if let VeilCommand::Auth { token } = cmd {
            Some(token)
        } else {
            None
        }
    }

    fn acl_requirement(cmd: &Self::Command) -> AclRequirement {
        cmd.acl_requirement()
    }

    fn dispatch<'a>(
        &'a self,
        engine: &'a Self::Engine,
        cmd: Self::Command,
        auth: Option<&'a AuthContext>,
    ) -> Pin<Box<dyn Future<Output = Self::Response> + Send + 'a>> {
        Box::pin(dispatch(engine, cmd, auth))
    }

    fn response_to_frame(&self, response: &Self::Response) -> Resp3Frame {
        match response {
            VeilResponse::Ok(data) => {
                let json = serde_json::to_string(data).unwrap_or_default();
                Resp3Frame::BulkString(json.into_bytes())
            }
            VeilResponse::Error(msg) => Resp3Frame::SimpleError(format!("ERR {msg}")),
        }
    }

    fn error_response(&self, msg: String) -> Self::Response {
        VeilResponse::error(msg)
    }

    fn ok_response(&self) -> Self::Response {
        VeilResponse::ok_simple()
    }
}

pub async fn run_tcp(
    listener: tokio::net::TcpListener,
    engine: Arc<VeilEngine<shroudb_storage::EmbeddedStore>>,
    token_validator: Option<Arc<dyn TokenValidator>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
) {
    shroudb_server_tcp::run_tcp_tls(
        listener,
        engine,
        Arc::new(VeilProtocol),
        token_validator,
        shutdown_rx,
        tls_acceptor,
    )
    .await;
}
