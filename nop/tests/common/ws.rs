// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::HttpServer;
use awc::ws::{Frame as ClientFrame, Message as ClientMessage};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use nop::management::ws::{RequestFrame, ResponseFrame, WsFrame, decode_frame, encode_frame};
use nop::management::{WireDecode, WireEncode, WireReader, WireWriter};
use std::net::TcpListener;

pub async fn start_test_server(bundle: super::AppBundle) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    actix_web::rt::spawn(async move {
        let _ = HttpServer::new(move || super::build_test_app(bundle.clone()))
            .listen(listener)
            .expect("listen")
            .run()
            .await;
    });

    format!("http://{}", addr)
}

pub async fn read_ws_frame<S, E>(framed: &mut S) -> WsFrame
where
    S: Stream<Item = Result<ClientFrame, E>> + Sink<ClientMessage, Error = E> + Unpin,
    E: std::fmt::Debug,
{
    loop {
        let frame = framed.next().await.expect("ws frame").expect("ws ok");
        match frame {
            ClientFrame::Binary(bytes) => {
                return decode_frame(&bytes).expect("decode frame");
            }
            ClientFrame::Ping(bytes) => {
                framed.send(ClientMessage::Pong(bytes)).await.expect("pong");
            }
            ClientFrame::Close(_) => panic!("WebSocket closed"),
            _ => {}
        }
    }
}

pub async fn send_request<S, E>(
    framed: &mut S,
    workflow_id: u32,
    domain_id: u32,
    action_id: u32,
    payload: Vec<u8>,
) -> ResponseFrame
where
    S: Stream<Item = Result<ClientFrame, E>> + Sink<ClientMessage, Error = E> + Unpin,
    E: std::fmt::Debug,
{
    let frame = WsFrame::Request(RequestFrame {
        domain_id,
        action_id,
        workflow_id,
        payload,
    });
    let bytes = encode_frame(&frame).expect("encode frame");
    framed
        .send(ClientMessage::Binary(bytes.into()))
        .await
        .expect("send frame");

    loop {
        match read_ws_frame(framed).await {
            WsFrame::Response(response) if response.workflow_id == workflow_id => return response,
            WsFrame::Error(err) => panic!("ws error: {}", err.message),
            WsFrame::AuthErr(err) => panic!("auth error: {}", err.message),
            _ => {}
        }
    }
}

pub fn encode_payload<T: WireEncode>(payload: &T) -> Vec<u8> {
    let mut writer = WireWriter::new();
    payload.encode(&mut writer).expect("encode payload");
    writer.into_bytes()
}

pub fn decode_payload<T: WireDecode>(bytes: &[u8]) -> T {
    let mut reader = WireReader::new(bytes);
    let payload = T::decode(&mut reader).expect("decode payload");
    reader
        .ensure_fully_consumed()
        .expect("payload fully consumed");
    payload
}
