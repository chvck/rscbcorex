use crate::memdx::codec::KeyValueCodec;
use crate::memdx::dispatcher::Dispatcher;
use crate::memdx::error::{CancellationErrorKind, Error};
use crate::memdx::packet::{RequestPacket, ResponsePacket};
use crate::memdx::pendingop::ClientPendingOp;
use futures::{SinkExt, StreamExt};
use log::{debug, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::{mpsc, oneshot, Mutex, Semaphore};
use tokio_rustls::client::TlsStream;
use tokio_util::codec::{FramedRead, FramedWrite};
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, Error>;
pub type ResponseSender = Sender<Result<ClientResponse>>;
type OpaqueMap = HashMap<u32, Arc<ResponseSender>>;
pub(crate) type CancellationSender = UnboundedSender<(u32, CancellationErrorKind)>;

#[derive(Debug)]
pub(crate) struct ClientResponse {
    packet: ResponsePacket,
    has_more_sender: oneshot::Sender<bool>,
}

impl ClientResponse {
    pub fn new(packet: ResponsePacket, has_more_sender: oneshot::Sender<bool>) -> Self {
        Self {
            packet,
            has_more_sender,
        }
    }

    pub fn packet(&self) -> &ResponsePacket {
        &self.packet
    }

    pub fn send_has_more(self) {
        match self.has_more_sender.send(true) {
            Ok(_) => {}
            Err(_e) => {}
        };
    }
}

#[derive(Debug)]
pub enum Connection {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
}

static HANDLER_INVOKE_PERMITS: Semaphore = Semaphore::const_new(1);

#[derive(Debug)]
pub struct Client {
    current_opaque: u32,
    opaque_map: Arc<Mutex<OpaqueMap>>,

    client_id: String,

    writer: FramedWrite<WriteHalf<TcpStream>, KeyValueCodec>,

    cancel_tx: CancellationSender,
}

impl Client {
    pub fn new(conn: Connection) -> Self {
        let (r, w) = match conn {
            Connection::Tcp(stream) => tokio::io::split(stream),
            Connection::Tls(stream) => {
                let (tcp, _) = stream.into_inner();
                tokio::io::split(tcp)
            }
        };

        let codec = KeyValueCodec::default();
        let reader = FramedRead::new(r, codec);
        let writer = FramedWrite::new(w, codec);

        let uuid = Uuid::new_v4().to_string();

        let (cancel_tx, cancel_rx) = mpsc::unbounded_channel();

        let client = Self {
            current_opaque: 1,
            opaque_map: Arc::new(Mutex::new(OpaqueMap::default())),
            client_id: uuid.clone(),

            cancel_tx,

            writer,
        };

        let read_opaque_map = Arc::clone(&client.opaque_map);
        tokio::spawn(async move {
            Client::read_loop(reader, read_opaque_map, uuid).await;
        });

        let cancel_opaque_map = Arc::clone(&client.opaque_map);
        tokio::spawn(async move {
            Client::cancel_loop(cancel_rx, cancel_opaque_map).await;
        });

        client
    }

    async fn register_handler(&mut self, handler: Arc<ResponseSender>) -> u32 {
        let requests = Arc::clone(&self.opaque_map);
        let mut map = requests.lock().await;

        let opaque = self.current_opaque;
        self.current_opaque += 1;

        map.insert(opaque, handler);

        opaque
    }

    async fn cancel_loop(
        mut cancel_rx: UnboundedReceiver<(u32, CancellationErrorKind)>,
        opaque_map: Arc<Mutex<OpaqueMap>>,
    ) {
        loop {
            match cancel_rx.recv().await {
                Some(cancel_info) => {
                    let permit = HANDLER_INVOKE_PERMITS.acquire().await.unwrap();
                    let requests: Arc<Mutex<OpaqueMap>> = Arc::clone(&opaque_map);
                    let mut map = requests.lock().await;

                    let t = map.remove(&cancel_info.0);

                    if let Some(map_entry) = t {
                        let sender = Arc::clone(&map_entry);
                        drop(map);

                        sender
                            .send(Err(Error::Cancelled(cancel_info.1)))
                            .await
                            .unwrap();
                    } else {
                        drop(map);
                    }

                    drop(requests);
                    drop(permit);
                }
                None => {
                    return;
                }
            }
        }
    }

    async fn read_loop(
        mut stream: FramedRead<ReadHalf<TcpStream>, KeyValueCodec>,
        opaque_map: Arc<Mutex<OpaqueMap>>,
        client_id: String,
    ) {
        loop {
            if let Some(input) = stream.next().await {
                match input {
                    Ok(packet) => {
                        trace!(
                            "Resolving response on {}. Opcode={}. Opaque={}. Status={}",
                            client_id,
                            packet.op_code(),
                            packet.opaque(),
                            packet.status(),
                        );

                        let opaque = packet.opaque();

                        let permit = HANDLER_INVOKE_PERMITS.acquire().await.unwrap();
                        let requests: Arc<Mutex<OpaqueMap>> = Arc::clone(&opaque_map);
                        let map = requests.lock().await;

                        // We remove and then re-add if there are more packets so that we don't have
                        // to hold the opaque map mutex across the callback.
                        let t = map.get(&opaque);

                        if let Some(map_entry) = t {
                            let sender = Arc::clone(map_entry);
                            drop(map);
                            let (more_tx, more_rx) = oneshot::channel();
                            let resp = ClientResponse::new(packet, more_tx);
                            match sender.send(Ok(resp)).await {
                                Ok(_) => {}
                                Err(e) => {
                                    debug!("Sending response to caller failed: {}", e);
                                }
                            };
                            drop(sender);

                            match more_rx.await {
                                Ok(has_more_packets) => {
                                    if !has_more_packets {
                                        let mut map = requests.lock().await;
                                        map.remove(&opaque);
                                        drop(map);
                                    }
                                }
                                Err(_) => {
                                    // If the response gets dropped then the receiver will be closed,
                                    // which we treat as an implicit !has_more_packets.
                                    let mut map = requests.lock().await;
                                    map.remove(&opaque);
                                    drop(map);
                                }
                            }
                        } else {
                            drop(map);
                            warn!(
                                "{} has no entry in request map for {}",
                                client_id,
                                &packet.opaque()
                            );
                        }
                        drop(requests);
                        drop(permit);
                    }
                    Err(e) => {
                        warn!("{} failed to read frame {}", client_id, e.to_string());
                    }
                }
            }
        }
    }
}

impl Dispatcher for Client {
    async fn dispatch(&mut self, mut packet: RequestPacket) -> Result<ClientPendingOp> {
        let (response_tx, response_rx) = mpsc::channel(1);
        let opaque = self.register_handler(Arc::new(response_tx)).await;
        packet.opaque = Some(opaque);
        let op_code = packet.op_code;

        match self.writer.send(packet).await {
            Ok(_) => Ok(ClientPendingOp::new(
                opaque,
                self.cancel_tx.clone(),
                response_rx,
            )),
            Err(e) => {
                debug!(
                    "{} failed to write packet {} {} {}",
                    self.client_id, opaque, op_code, e
                );

                let requests: Arc<Mutex<OpaqueMap>> = Arc::clone(&self.opaque_map);
                let mut map = requests.lock().await;
                map.remove(&opaque);

                Err(Error::Dispatch(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::memdx::auth_mechanism::AuthMechanism;
    use crate::memdx::client::{Client, Connection};
    use crate::memdx::dispatcher::Dispatcher;
    use crate::memdx::hello_feature::HelloFeature;
    use crate::memdx::magic::Magic;
    use crate::memdx::op_bootstrap::{BootstrapOptions, OpBootstrap};
    use crate::memdx::opcode::OpCode;
    use crate::memdx::ops_core::OpsCore;
    use crate::memdx::packet::{RequestPacket, ResponsePacket};
    use crate::memdx::request::{
        GetErrorMapRequest, HelloRequest, SASLAuthRequest, SelectBucketRequest,
    };
    use bytes::BufMut;
    use std::ops::Add;
    use std::sync::mpsc;
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio::time::Instant;
    use tokio_util::bytes::BytesMut;
    use tokio_util::sync::CancellationToken;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roundtrip_a_request() {
        let _ = env_logger::try_init();

        let socket = TcpStream::connect("127.0.0.1:11210")
            .await
            .expect("could not connect");
        socket.set_nodelay(false).unwrap();

        let conn = Connection::Tcp(socket);
        let mut client = Client::new(conn);

        let username = "Administrator";
        let password = "password";

        let mut auth_payload: Vec<u8> = Vec::new();
        auth_payload.push(0);
        auth_payload.extend_from_slice(username.as_ref());
        auth_payload.push(0);
        auth_payload.extend_from_slice(password.as_ref());

        let instant = Instant::now().add(Duration::new(7, 0));

        let bootstrap_result = OpBootstrap::bootstrap(
            OpsCore {},
            &mut client,
            BootstrapOptions {
                hello: Some(HelloRequest {
                    client_name: "test-client".into(),
                    requested_features: vec![
                        HelloFeature::AltRequests,
                        HelloFeature::Collections,
                        HelloFeature::Duplex,
                        HelloFeature::SelectBucket,
                    ],
                }),
                get_error_map: Some(GetErrorMapRequest { version: 2 }),
                auth: Some(SASLAuthRequest {
                    payload: auth_payload,
                    auth_mechanism: AuthMechanism::Plain,
                }),
                select_bucket: Some(SelectBucketRequest {
                    bucket_name: "default".into(),
                }),
                deadline: instant,
            },
        )
        .await
        .unwrap();
        dbg!(&bootstrap_result.hello);

        let hello_result = bootstrap_result.hello.unwrap();
        assert_eq!(4, hello_result.enabled_features.len());

        let mut req = RequestPacket::new(Magic::Req, OpCode::Set);
        req = req.set_key(make_uleb128_32("test".as_bytes().into(), 0x00));

        req = req.set_extras(vec![0, 0, 0, 0, 0, 0, 0, 0]);

        let mut op = match client.dispatch(req).await {
            Ok(r) => r,
            Err(e) => panic!("Failed to dispatch request {}", e),
        };

        let result = op.recv().await.unwrap();

        dbg!(result);
    }

    fn make_uleb128_32(key: Vec<u8>, collection_id: u32) -> Vec<u8> {
        let mut cid = collection_id;
        let mut builder = BytesMut::with_capacity(key.len() + 5);
        loop {
            let mut c: u8 = (cid & 0x7f) as u8;
            cid >>= 7;
            if cid != 0 {
                c |= 0x80;
            }

            builder.put_u8(c);
            if c & 0x80 == 0 {
                break;
            }
        }
        for k in key {
            builder.put_u8(k);
        }

        builder.freeze().to_vec()
    }
}
