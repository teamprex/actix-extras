//! WebSockets for Actix Web, without actors.
//!
//! For usage, see documentation on [`handle()`].

#![warn(missing_docs)]
#![doc(html_logo_url = "https://actix.rs/img/logo.png")]
#![doc(html_favicon_url = "https://actix.rs/favicon.ico")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub use actix_http::ws::{CloseCode, CloseReason, Item, Message, ProtocolError};
use actix_http::{
    body::{BodyStream, MessageBody},
    ws::handshake,
};
use actix_web::{web, HttpRequest, HttpResponse};
use tokio::sync::mpsc::channel;

mod aggregated;
#[cfg(feature = "compress-deflate")]
mod deflate;
mod session;
mod stream;

#[cfg(feature = "compress-deflate")]
pub use self::deflate::{
    DeflateCodec, DeflateCompressionContext, DeflateConfig, DeflateDecompressionContext,
    DeflateHandshakeError,
};
pub use self::{
    aggregated::{AggregatedMessage, AggregatedMessageStream},
    session::{Closed, Session},
    stream::{MessageStream, StreamingBody},
};

/// Begin handling websocket traffic
///
/// ```no_run
/// use std::io;
/// use actix_web::{middleware::Logger, web, App, HttpRequest, HttpServer, Responder};
/// use actix_ws::Message;
/// use futures_util::StreamExt as _;
///
/// async fn ws(req: HttpRequest, body: web::Payload) -> actix_web::Result<impl Responder> {
///     let (response, mut session, mut msg_stream) = actix_ws::handle(&req, body)?;
///
///     actix_web::rt::spawn(async move {
///         while let Some(Ok(msg)) = msg_stream.next().await {
///             match msg {
///                 Message::Ping(bytes) => {
///                     if session.pong(&bytes).await.is_err() {
///                         return;
///                     }
///                 }
///
///                 Message::Text(msg) => println!("Got text: {msg}"),
///                 _ => break,
///             }
///         }
///
///         let _ = session.close(None).await;
///     });
///
///     Ok(response)
/// }
///
/// #[tokio::main(flavor = "current_thread")]
/// async fn main() -> io::Result<()> {
///     HttpServer::new(move || {
///         App::new()
///             .route("/ws", web::get().to(ws))
///             .wrap(Logger::default())
///     })
///     .bind(("127.0.0.1", 8080))?
///     .run()
///     .await
/// }
/// ```
pub fn handle(
    req: &HttpRequest,
    body: web::Payload,
) -> Result<(HttpResponse, Session, MessageStream), actix_web::Error> {
    let mut response = handshake(req.head())?;
    let (tx, rx) = channel(32);

    Ok((
        response
            .message_body(BodyStream::new(StreamingBody::new(rx)).boxed())?
            .into(),
        Session::new(tx),
        MessageStream::new(body.into_inner()),
    ))
}

/// Begin handling websocket traffic with `permessage-deflate` extension.
#[cfg(feature = "compress-deflate")]
pub fn handle_with_permessage_deflate(
    req: &HttpRequest,
    body: web::Payload,
    config: &deflate::DeflateConfig,
) -> Result<(HttpResponse, Session, MessageStream), actix_web::Error> {
    let mut response = handshake(req.head())?;
    let deflate = config.create_session(req)?;

    let (tx, rx) = channel(32);

    let session = Session::new(tx);

    let (message_stream, streaming_body) = if let Some((
        DeflateCodec {
            compress,
            decompress,
        },
        header_pair,
    )) = deflate
    {
        response.append_header(header_pair);
        (
            MessageStream::new_deflate(body.into_inner(), decompress),
            StreamingBody::new_deflate(rx, compress),
        )
    } else {
        (
            MessageStream::new(body.into_inner()),
            StreamingBody::new(rx),
        )
    };

    let response = response
        .message_body(BodyStream::new(streaming_body).boxed())?
        .into();

    Ok((response, session, message_stream))
}
