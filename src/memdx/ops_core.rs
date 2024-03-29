use std::io::Write;

use byteorder::{BigEndian, WriteBytesExt};

use crate::memdx::auth_mechanism::AuthMechanism;
use crate::memdx::client::Result;
use crate::memdx::dispatcher::Dispatcher;
use crate::memdx::error::Error;
use crate::memdx::magic::Magic;
use crate::memdx::op_bootstrap::{OpAuthEncoder, OpBootstrapEncoder};
use crate::memdx::opcode::OpCode;
use crate::memdx::packet::{RequestPacket, ResponsePacket};
use crate::memdx::pendingop::StandardPendingOp;
use crate::memdx::request::{
    GetErrorMapRequest, HelloRequest, SASLAuthRequest, SASLListMechsRequest, SASLStepRequest,
    SelectBucketRequest,
};
use crate::memdx::status::Status;

pub struct OpsCore {}

impl OpsCore {
    pub(crate) fn decode_error(resp: &ResponsePacket) -> Error {
        let status = resp.status;
        if status == Status::NotMyVbucket {
            Error::NotMyVbucket
        } else if status == Status::TmpFail {
            Error::TmpFail
        } else {
            Error::Unknown(format!("{}", status))
        }

        // TODO: decode error context
    }
}

impl OpBootstrapEncoder for OpsCore {
    async fn hello<D>(&self, dispatcher: &mut D, request: HelloRequest) -> Result<StandardPendingOp>
    where
        D: Dispatcher,
    {
        let mut features: Vec<u8> = Vec::new();
        for feature in request.requested_features {
            features.write_u16::<BigEndian>(feature.into()).unwrap();
        }

        let op = dispatcher
            .dispatch(RequestPacket {
                magic: Magic::Req,
                op_code: OpCode::Hello,
                datatype: 0,
                vbucket_id: None,
                cas: None,
                extras: None,
                key: None,
                value: Some(features),
                framing_extras: None,
                opaque: None,
            })
            .await?;

        Ok(StandardPendingOp::new(op))
    }

    async fn get_error_map<D>(
        &self,
        dispatcher: &mut D,
        request: GetErrorMapRequest,
    ) -> Result<StandardPendingOp>
    where
        D: Dispatcher,
    {
        let mut value = Vec::new();
        value.write_u16::<BigEndian>(request.version).unwrap();

        let op = dispatcher
            .dispatch(RequestPacket {
                magic: Magic::Req,
                op_code: OpCode::GetErrorMap,
                datatype: 0,
                vbucket_id: None,
                cas: None,
                extras: None,
                key: None,
                value: Some(value),
                framing_extras: None,
                opaque: None,
            })
            .await?;

        Ok(StandardPendingOp::new(op))
    }

    async fn select_bucket<D>(
        &self,
        dispatcher: &mut D,
        request: SelectBucketRequest,
    ) -> Result<StandardPendingOp>
    where
        D: Dispatcher,
    {
        let mut key = Vec::new();
        key.write_all(request.bucket_name.as_bytes()).unwrap();

        let op = dispatcher
            .dispatch(RequestPacket {
                magic: Magic::Req,
                op_code: OpCode::SelectBucket,
                datatype: 0,
                vbucket_id: None,
                cas: None,
                extras: None,
                key: Some(key),
                value: None,
                framing_extras: None,
                opaque: None,
            })
            .await?;

        Ok(StandardPendingOp::new(op))
    }

    async fn sasl_list_mechs<D>(
        &self,
        dispatcher: &mut D,
        _request: SASLListMechsRequest,
    ) -> Result<StandardPendingOp>
    where
        D: Dispatcher,
    {
        let op = dispatcher
            .dispatch(RequestPacket {
                magic: Magic::Req,
                op_code: OpCode::SASLListMechs,
                datatype: 0,
                vbucket_id: None,
                cas: None,
                extras: None,
                key: None,
                value: None,
                framing_extras: None,
                opaque: None,
            })
            .await?;

        Ok(StandardPendingOp::new(op))
    }
}

impl OpAuthEncoder for OpsCore {
    async fn sasl_auth<D>(
        &self,
        dispatcher: &mut D,
        request: SASLAuthRequest,
    ) -> Result<StandardPendingOp>
    where
        D: Dispatcher,
    {
        // TODO: Support more than PLAIN
        if request.auth_mechanism != AuthMechanism::Plain {
            return Err(Error::Unknown("not implemented".into()));
        }
        let mut value = Vec::new();
        value.write_all(request.payload.as_slice()).unwrap();

        let op = dispatcher
            .dispatch(RequestPacket {
                magic: Magic::Req,
                op_code: OpCode::SASLAuth,
                datatype: 0,
                vbucket_id: None,
                cas: None,
                extras: None,
                key: Some(request.auth_mechanism.into()),
                value: Some(value),
                framing_extras: None,
                opaque: None,
            })
            .await?;

        Ok(StandardPendingOp::new(op))
    }

    async fn sasl_step<D>(
        &self,
        dispatcher: &mut D,
        request: SASLStepRequest,
    ) -> Result<StandardPendingOp>
    where
        D: Dispatcher,
    {
        let mut value = Vec::new();
        value.write_all(request.payload.as_slice()).unwrap();

        let op = dispatcher
            .dispatch(RequestPacket {
                magic: Magic::Req,
                op_code: OpCode::SASLStep,
                datatype: 0,
                vbucket_id: None,
                cas: None,
                extras: None,
                key: Some(request.auth_mechanism.into()),
                value: Some(value),
                framing_extras: None,
                opaque: None,
            })
            .await?;

        Ok(StandardPendingOp::new(op))
    }
}
