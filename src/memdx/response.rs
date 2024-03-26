use crate::memdx::auth_mechanism::AuthMechanism;
use crate::memdx::client::ClientResponse;
use crate::memdx::error::Error;
use crate::memdx::hello_feature::HelloFeature;
use crate::memdx::ops_core::OpsCore;
use crate::memdx::ops_crud::OpsCrud;
use crate::memdx::status::Status;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;
use std::time::Duration;

pub trait TryFromClientResponse: Sized {
    fn try_from(resp: ClientResponse) -> Result<Self, Error>;
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct HelloResponse {
    pub enabled_features: Vec<HelloFeature>,
}

impl TryFromClientResponse for HelloResponse {
    fn try_from(resp: ClientResponse) -> Result<Self, Error> {
        let packet = resp.packet();
        let status = packet.status();
        if status != Status::Success {
            return Err(OpsCore::decode_error(packet));
        }

        let mut features: Vec<HelloFeature> = Vec::new();
        if let Some(value) = packet.value() {
            if value.len() % 2 != 0 {
                return Err(Error::Protocol("invalid hello features length".into()));
            }

            let mut cursor = Cursor::new(value);
            while let Ok(code) = cursor.read_u16::<BigEndian>() {
                features.push(HelloFeature::from(code));
            }
        }
        let response = HelloResponse {
            enabled_features: features,
        };

        Ok(response)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GetErrorMapResponse {
    pub error_map: Vec<u8>,
}

impl TryFromClientResponse for GetErrorMapResponse {
    fn try_from(resp: ClientResponse) -> Result<Self, Error> {
        let packet = resp.packet();
        let status = packet.status();
        if status != Status::Success {
            return Err(OpsCore::decode_error(packet));
        }

        // TODO: Clone?
        let value = packet.value().clone().unwrap_or_default();
        let response = GetErrorMapResponse { error_map: value };

        Ok(response)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SelectBucketResponse {}

impl TryFromClientResponse for SelectBucketResponse {
    fn try_from(resp: ClientResponse) -> Result<Self, Error> {
        let packet = resp.packet();
        let status = packet.status();
        if status != Status::Success {
            return Err(OpsCore::decode_error(packet));
        }

        Ok(SelectBucketResponse {})
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SASLAuthResponse {
    pub needs_more_steps: bool,
    pub payload: Vec<u8>,
}

impl TryFromClientResponse for SASLAuthResponse {
    fn try_from(resp: ClientResponse) -> Result<Self, Error> {
        let packet = resp.packet();
        let status = packet.status();
        if status == Status::SASLAuthContinue {
            // TODO: clone?
            let value = packet.value().clone();
            return Ok(SASLAuthResponse {
                needs_more_steps: true,
                payload: value.unwrap_or_default(),
            });
        }

        if status != Status::Success {
            return Err(OpsCore::decode_error(packet));
        }

        Ok(SASLAuthResponse {
            needs_more_steps: false,
            // TODO: clone?
            payload: packet.value().clone().unwrap_or_default(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SASLStepResponse {
    pub needs_more_steps: bool,
    pub payload: Vec<u8>,
}

impl TryFromClientResponse for SASLStepResponse {
    fn try_from(resp: ClientResponse) -> Result<Self, Error> {
        let packet = resp.packet();
        let status = packet.status();
        if status != Status::Success {
            return Err(OpsCore::decode_error(packet));
        }

        Ok(SASLStepResponse {
            needs_more_steps: false,
            // TODO: clone?
            payload: packet.value().clone().unwrap_or_default(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SASLListMechsResponse {
    pub available_mechs: Vec<AuthMechanism>,
}

impl TryFromClientResponse for SASLListMechsResponse {
    fn try_from(resp: ClientResponse) -> Result<Self, Error> {
        let packet = resp.packet();
        let status = packet.status();
        if status != Status::Success {
            return Err(OpsCore::decode_error(packet));
        }

        // TODO: Clone?
        let value = packet.value().clone().unwrap_or_default();
        let mechs_list_string = match String::from_utf8(value) {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::Protocol(e.to_string()));
            }
        };
        let mechs_list_split = mechs_list_string.split(' ');
        let mut mechs_list = Vec::new();
        for item in mechs_list_split {
            mechs_list.push(AuthMechanism::try_from(item)?);
        }

        Ok(SASLListMechsResponse {
            available_mechs: mechs_list,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BootstrapResult {
    pub hello: Option<HelloResponse>,
    pub error_map: Option<GetErrorMapResponse>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MutationToken {
    pub vbuuid: u64,
    pub seqno: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SetResponse {
    pub cas: u64,
    pub mutation_token: MutationToken,
    pub server_duration: Option<Duration>,
}

impl TryFromClientResponse for SetResponse {
    fn try_from(resp: ClientResponse) -> Result<Self, Error> {
        let packet = resp.packet();
        let status = packet.status();

        if status == Status::TooBig {
            return Err(Error::TooBig);
        } else if status == Status::Locked {
            return Err(Error::Locked);
        } else if status == Status::KeyExists {
            return Err(Error::KeyExists);
        } else if status != Status::Success {
            return Err(Error::Unknown(
                OpsCrud::decode_common_error(resp.packet()).to_string(),
            ));
        }

        let mut_token = if let Some(extras) = packet.extras() {
            if extras.len() != 16 {
                return Err(Error::Protocol("Bad extras length".to_string()));
            }

            let mut extras = Cursor::new(extras);

            MutationToken {
                vbuuid: extras
                    .read_u64::<BigEndian>()
                    .map_err(|e| Error::Unknown(e.to_string()))?,
                seqno: extras
                    .read_u64::<BigEndian>()
                    .map_err(|e| Error::Unknown(e.to_string()))?,
            }
        } else {
            return Err(Error::Protocol("Bad extras length".to_string()));
        };

        Ok(SetResponse {
            cas: packet.cas().unwrap_or_default(),
            mutation_token: mut_token,
            server_duration: None,
        })
    }
}
