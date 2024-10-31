use actix_http::header::{self, HeaderValue};
use actix_http::header::{HeaderName, SEC_WEBSOCKET_EXTENSIONS};
use actix_http::ws::{Codec, Frame, Item, Message, OpCode, Parser, ProtocolError, RsvBits};
use actix_web::web::BytesMut;
use actix_web::HttpRequest;
use tokio_util::codec::{Decoder, Encoder};

const MAX_WINDOW_BITS_RANGE: std::ops::RangeInclusive<u8> = 9..=15;
const DEFAULT_WINDOW_BITS: u8 = 15;
const BUF_SIZE: usize = 2048;

const RSV_BIT_DEFLATE_FLAG: RsvBits = RsvBits::RSV1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeflateHandshakeError {
    InvalidExtensionHeader,
    UnknownWebSocketParameters(Vec<String>),
    DuplicateParameter(&'static str),
    MaxWindowBitsOutOfRange,
    NoSuitableConfigurationFound,
    ServerNoContextTakeoverExpected,
}

impl std::fmt::Display for DeflateHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidExtensionHeader => write!(f, "Invalid `Sec-WebSocket-extension` header."),
            Self::UnknownWebSocketParameters(p) => {
                write!(
                    f,
                    "Unknown WebSocket `permessage-deflate` parameters: {}",
                    p.join(", ")
                )
            }
            Self::DuplicateParameter(p) => {
                write!(f, "Duplicate WebSocket `permessage-deflate` parameter: {p}")
            }
            Self::MaxWindowBitsOutOfRange => write!(
                f,
                "Max window bits out of range. ({} to {} expected)",
                MAX_WINDOW_BITS_RANGE.start(),
                MAX_WINDOW_BITS_RANGE.end()
            ),
            Self::NoSuitableConfigurationFound => write!(
                f,
                "No suitable WebSocket `permedia-deflate` parameter configurations found."
            ),
            Self::ServerNoContextTakeoverExpected => write!(
                f,
                "Expected `server_no_context_takeover` option in `permessage-deflate` extension."
            ),
        }
    }
}

impl std::error::Error for DeflateHandshakeError {}

impl actix_web::error::ResponseError for DeflateHandshakeError {
    fn status_code(&self) -> actix_http::StatusCode {
        actix_http::StatusCode::BAD_REQUEST
    }
}

enum ClientMaxWindowBits {
    NotSpecified,
    Specified(u8),
}

struct DeflateSessionParameters {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: Option<u8>,
    client_max_window_bits: Option<ClientMaxWindowBits>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeflateConfig {
    pub server_no_context_takeover: bool,
    pub client_no_context_takeover: bool,
    pub server_max_window_bits: Option<u8>,
    pub client_max_window_bits: Option<u8>,
}

impl Default for DeflateConfig {
    fn default() -> Self {
        Self {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: None,
            client_max_window_bits: None,
        }
    }
}

impl DeflateConfig {
    fn get_parameters_from_header<'a>(
        extension_frags: impl Iterator<Item = &'a str>,
    ) -> Result<DeflateSessionParameters, DeflateHandshakeError> {
        let mut client_max_window_bits = None;
        let mut server_max_window_bits = None;
        let mut client_no_context_takeover = None;
        let mut server_no_context_takeover = None;

        let mut unknown_parameters = vec![];

        for fragment in extension_frags {
            if fragment == "client_max_window_bits" {
                if client_max_window_bits.is_some() {
                    return Err(DeflateHandshakeError::DuplicateParameter(
                        "client_max_window_bits",
                    ));
                }
                client_max_window_bits = Some(ClientMaxWindowBits::NotSpecified);
            } else if let Some(value) = fragment.strip_prefix("client_max_window_bits=") {
                if client_max_window_bits.is_some() {
                    return Err(DeflateHandshakeError::DuplicateParameter(
                        "client_max_window_bits",
                    ));
                }
                let bits = value
                    .parse::<u8>()
                    .map_err(|_| DeflateHandshakeError::MaxWindowBitsOutOfRange)?;
                if !MAX_WINDOW_BITS_RANGE.contains(&bits) {
                    return Err(DeflateHandshakeError::MaxWindowBitsOutOfRange);
                }
                client_max_window_bits = Some(ClientMaxWindowBits::Specified(bits));
            } else if let Some(value) = fragment.strip_prefix("server_max_window_bits=") {
                if server_max_window_bits.is_some() {
                    return Err(DeflateHandshakeError::DuplicateParameter(
                        "server_max_window_bits",
                    ));
                }
                let bits = value
                    .parse::<u8>()
                    .map_err(|_| DeflateHandshakeError::MaxWindowBitsOutOfRange)?;
                if !MAX_WINDOW_BITS_RANGE.contains(&bits) {
                    return Err(DeflateHandshakeError::MaxWindowBitsOutOfRange);
                }
                server_max_window_bits = Some(bits);
            } else if fragment == "server_no_context_takeover" {
                if server_no_context_takeover.is_some() {
                    return Err(DeflateHandshakeError::DuplicateParameter(
                        "server_no_context_takeover",
                    ));
                }
                server_no_context_takeover = Some(true);
            } else if fragment == "client_no_context_takeover" {
                if client_no_context_takeover.is_some() {
                    return Err(DeflateHandshakeError::DuplicateParameter(
                        "client_no_context_takeover",
                    ));
                }
                client_no_context_takeover = Some(true);
            } else {
                unknown_parameters.push(fragment.to_owned());
            }
        }

        if !unknown_parameters.is_empty() {
            Err(DeflateHandshakeError::UnknownWebSocketParameters(
                unknown_parameters,
            ))
        } else {
            Ok(DeflateSessionParameters {
                server_no_context_takeover: server_no_context_takeover.unwrap_or(false),
                client_no_context_takeover: client_no_context_takeover.unwrap_or(false),
                server_max_window_bits,
                client_max_window_bits,
            })
        }
    }

    fn query_session_parameters(
        request: &HttpRequest,
    ) -> Result<Option<DeflateSessionParameters>, DeflateHandshakeError> {
        let headers = request.headers().get_all(header::SEC_WEBSOCKET_EXTENSIONS);

        for header in headers {
            let header = header
                .to_str()
                .map_err(|_| DeflateHandshakeError::InvalidExtensionHeader)?
                .to_lowercase();

            for extension in header.split(',').map(str::trim) {
                let mut fragments = extension.split(';').map(str::trim);
                if fragments.next() == Some("permessage-deflate") {
                    return Ok(Some(Self::get_parameters_from_header(fragments)?));
                }
            }
        }

        Ok(None)
    }

    pub fn create_session(
        &self,
        request: &HttpRequest,
    ) -> Result<Option<(DeflateCodec, (HeaderName, HeaderValue))>, DeflateHandshakeError> {
        let Some(params) = Self::query_session_parameters(request)? else {
            return Ok(None);
        };

        let server_no_context_takeover =
            if self.server_no_context_takeover && !params.server_no_context_takeover {
                true
            } else {
                params.server_no_context_takeover
            };

        let client_no_context_takeover =
            if self.client_no_context_takeover && !params.client_no_context_takeover {
                true
            } else {
                params.client_no_context_takeover
            };

        let server_max_window_bits =
            match (self.server_max_window_bits, params.server_max_window_bits) {
                (None, value) => value,
                (Some(config_value), None) => Some(config_value),
                (Some(config_value), Some(value)) => {
                    if value > config_value {
                        Some(config_value)
                    } else {
                        Some(value)
                    }
                }
            };

        let client_max_window_bits =
            match (self.client_max_window_bits, params.client_max_window_bits) {
                (None, None | Some(ClientMaxWindowBits::NotSpecified)) => None,
                (None, Some(ClientMaxWindowBits::Specified(value))) => Some(value),
                (Some(_), None) => None,
                (Some(config_value), Some(ClientMaxWindowBits::NotSpecified)) => Some(config_value),
                (Some(config_value), Some(ClientMaxWindowBits::Specified(value))) => {
                    if value > config_value {
                        Some(config_value)
                    } else {
                        Some(value)
                    }
                }
            };

        // Build response parameter
        let mut response_extension = vec!["permessage-deflate".to_owned()];
        if server_no_context_takeover {
            response_extension.push("server_no_context_takeover".to_owned());
        }
        if client_no_context_takeover {
            response_extension.push("client_no_context_takeover".to_owned());
        }
        if let Some(server_max_window_bits) = server_max_window_bits {
            response_extension.push(format!("server_max_window_bits={server_max_window_bits}"));
        }
        if let Some(client_max_window_bits) = client_max_window_bits {
            response_extension.push(format!("client_max_window_bits={client_max_window_bits}"));
        }

        let response_header_pair = (
            SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_str(response_extension.join("; ").as_str()).unwrap(),
        );

        let client_max_window_bits = client_max_window_bits.unwrap_or(DEFAULT_WINDOW_BITS);
        let server_max_window_bits = server_max_window_bits.unwrap_or(DEFAULT_WINDOW_BITS);

        let compression_context = DeflateCompressionContext {
            codec: Codec::new(),

            client_no_context_takeover,

            compress: flate2::Compress::new_with_window_bits(
                Default::default(),
                false,
                client_max_window_bits,
            ),
            total_bytes_written: 0,
            total_bytes_read: 0,
        };

        let decompression_context = DeflateDecompressionContext {
            codec: Codec::new(),

            server_no_context_takeover,

            decompress: flate2::Decompress::new_with_window_bits(false, server_max_window_bits),

            decode_continuation: false,
            total_bytes_written: 0,
            total_bytes_read: 0,
        };

        Ok(Some((
            DeflateCodec {
                compress: compression_context,
                decompress: decompression_context,
            },
            response_header_pair,
        )))
    }
}

pub struct DeflateDecompressionContext {
    codec: Codec,

    server_no_context_takeover: bool,

    decompress: flate2::Decompress,

    decode_continuation: bool,
    total_bytes_written: u64,
    total_bytes_read: u64,
}

impl DeflateDecompressionContext {
    pub(super) fn max_size(mut self, max_size: usize) -> Self {
        self.codec = self.codec.max_size(max_size);
        self.decode_continuation = false;
        self.reset();

        self
    }

    fn reset(&mut self) {
        self.decompress.reset(false);
        self.total_bytes_read = 0;
        self.total_bytes_written = 0;
    }
}

impl Decoder for DeflateDecompressionContext {
    type Item = Frame;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let x = src.clone();

        let frame = self.codec.decode(src)?;
        let Some(mut frame) = frame else {
            return Ok(None);
        };

        println!("{frame:?} {x:?}");

        let rsv_bits = self.codec.get_inbound_rsv_bits().unwrap_or_default();
        if !rsv_bits.contains(RSV_BIT_DEFLATE_FLAG) {
            return Ok(Some(frame));
        }

        let fin = matches!(
            frame,
            Frame::Binary(_) | Frame::Text(_) | Frame::Continuation(Item::Last(_))
        );

        match frame {
            Frame::Continuation(_) => {
                if !self.decode_continuation {
                    // If current continuation is without compression, return as is.
                    return Ok(Some(frame));
                }
                if fin {
                    self.decode_continuation = false;
                }
            }
            Frame::Text(_) | Frame::Binary(_) => {
                if !rsv_bits.contains(RSV_BIT_DEFLATE_FLAG) {
                    // The frame is not compressed. return as is.
                    return Ok(Some(frame));
                }
                if !fin {
                    self.decode_continuation = true;
                }
            }
            _ => return Ok(Some(frame)),
        }

        let bytes = match &mut frame {
            Frame::Text(ref mut bytes) => bytes,
            Frame::Binary(ref mut bytes) => bytes,
            Frame::Continuation(Item::FirstBinary(ref mut bytes)) => bytes,
            Frame::Continuation(Item::FirstText(ref mut bytes)) => bytes,
            Frame::Continuation(Item::Continue(ref mut bytes)) => bytes,
            Frame::Continuation(Item::Last(ref mut bytes)) => bytes,
            _ => unreachable!(),
        };

        let mut output: Vec<u8> = vec![];
        let mut buf = [0u8; BUF_SIZE];

        let mut offset: usize = 0;
        loop {
            let res = if offset >= bytes.len() {
                self.decompress
                    .decompress(
                        &[0x00, 0x00, 0xff, 0xff],
                        &mut buf,
                        flate2::FlushDecompress::Finish,
                    )
                    .map_err(|e| {
                        self.reset();
                        ProtocolError::Io(e.into())
                    })?
            } else {
                self.decompress
                    .decompress(&bytes[offset..], &mut buf, flate2::FlushDecompress::None)
                    .map_err(|e| {
                        self.reset();
                        ProtocolError::Io(e.into())
                    })?
            };

            let read = self.decompress.total_in() - self.total_bytes_read;
            let written = self.decompress.total_out() - self.total_bytes_written;

            offset += read as usize;
            self.total_bytes_read += read;
            if written > 0 {
                output.extend(buf.iter().take(written as usize));
                self.total_bytes_written += written;
            }

            if res != flate2::Status::Ok {
                break;
            }
        }

        *bytes = output.into();

        if fin && self.server_no_context_takeover {
            self.reset();
        }

        Ok(Some(frame))
    }
}

pub struct DeflateCompressionContext {
    codec: Codec,

    client_no_context_takeover: bool,

    compress: flate2::Compress,
    total_bytes_written: u64,
    total_bytes_read: u64,
}

impl DeflateCompressionContext {
    fn reset(&mut self) {
        self.compress.reset();
        self.total_bytes_read = 0;
        self.total_bytes_written = 0;
    }
}

impl Encoder<Message> for DeflateCompressionContext {
    type Error = ProtocolError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match &item {
            Message::Text(ref byte_string) => byte_string.as_bytes(),
            Message::Binary(ref bytes) => bytes,
            Message::Continuation(Item::FirstText(ref bytes)) => bytes,
            Message::Continuation(Item::FirstBinary(ref bytes)) => bytes,
            Message::Continuation(Item::Continue(ref bytes)) => bytes,
            Message::Continuation(Item::Last(ref bytes)) => bytes,
            _ => {
                // Reset RSV flag for control frame.
                self.codec.set_outbound_rsv_bits(RsvBits::empty());
                return self.codec.encode(item, dst);
            }
        };

        let mut output = vec![];
        let mut buf = [0u8; BUF_SIZE];

        loop {
            let total_in = self.compress.total_in() - self.total_bytes_read;
            let res = if total_in >= bytes.len() as u64 {
                self.compress
                    .compress(&[], &mut buf, flate2::FlushCompress::Sync)
                    .map_err(|e| {
                        self.reset();
                        ProtocolError::Io(e.into())
                    })?
            } else {
                self.compress
                    .compress(&bytes, &mut buf, flate2::FlushCompress::None)
                    .map_err(|e| {
                        self.reset();
                        ProtocolError::Io(e.into())
                    })?
            };

            let written = self.compress.total_out() - self.total_bytes_written;
            if written > 0 {
                output.extend(buf.iter().take(written as usize));
                self.total_bytes_written += written;
            }

            if res != flate2::Status::Ok {
                break;
            }
        }
        self.total_bytes_read = self.compress.total_in();

        if output.iter().rev().take(4).eq(&[0xff, 0xff, 0x00, 0x00]) {
            output.drain(output.len() - 4..);
        }

        // Set RSV flag accordingly when sending compress payload.
        self.codec.set_outbound_rsv_bits(RSV_BIT_DEFLATE_FLAG);

        match item {
            Message::Text(_) => {
                // We can't just defer to `Codec::encode()` in this case as `Message::Text` accepts `ByteString` which only allows valid UTF-8.
                Parser::write_message(dst, output, OpCode::Text, RSV_BIT_DEFLATE_FLAG, true, false);
            }
            Message::Binary(_) => {
                self.codec.encode(Message::Binary(output.into()), dst)?;
            }
            Message::Continuation(Item::FirstText(_)) => {
                self.codec
                    .encode(Message::Continuation(Item::FirstText(output.into())), dst)?;
            }
            Message::Continuation(Item::FirstBinary(_)) => {
                self.codec
                    .encode(Message::Continuation(Item::FirstBinary(output.into())), dst)?;
            }
            Message::Continuation(Item::Continue(_)) => {
                self.codec
                    .encode(Message::Continuation(Item::Continue(output.into())), dst)?;
            }
            Message::Continuation(Item::Last(_)) => {
                self.codec
                    .encode(Message::Continuation(Item::Last(output.into())), dst)?;
            }
            _ => unreachable!(),
        }

        let fin = matches!(
            item,
            Message::Text(_) | Message::Binary(_) | Message::Continuation(Item::Last(_))
        );

        if fin && self.client_no_context_takeover {
            self.reset();
        }

        Ok(())
    }
}

pub struct DeflateCodec {
    pub compress: DeflateCompressionContext,
    pub decompress: DeflateDecompressionContext,
}

impl Encoder<Message> for DeflateCodec {
    type Error = ProtocolError;

    #[inline]
    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.compress.encode(item, dst)
    }
}

impl Decoder for DeflateCodec {
    type Item = Frame;
    type Error = ProtocolError;

    #[inline]
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decompress.decode(src)
    }
}
