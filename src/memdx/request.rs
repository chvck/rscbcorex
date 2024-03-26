use crate::memdx::auth_mechanism::AuthMechanism;
use crate::memdx::durability_level::DurabilityLevel;
use crate::memdx::hello_feature::HelloFeature;
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct HelloRequest {
    pub client_name: Vec<u8>,
    pub requested_features: Vec<HelloFeature>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GetErrorMapRequest {
    pub version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SelectBucketRequest {
    pub bucket_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SASLAuthRequest {
    pub auth_mechanism: AuthMechanism,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SASLStepRequest {
    pub auth_mechanism: AuthMechanism,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SASLListMechsRequest {}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SetRequest {
    collection_id: u32,
    key: Vec<u8>,
    vbucket_id: u16,
    flags: u32,
    value: Vec<u8>,
    datatype: u8,
    expiry: Option<u32>,
    preserve_expiry: Option<bool>,
    cas: Option<u64>,
    on_behalf_of: Option<String>,
    durability_level: Option<DurabilityLevel>,
    durability_level_timeout: Option<Duration>,
}

// TODO: clones
impl SetRequest {
    pub fn collection_id(&self) -> u32 {
        self.collection_id
    }
    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }
    pub fn vbucket_id(&self) -> u16 {
        self.vbucket_id
    }
    pub fn flags(&self) -> u32 {
        self.flags
    }
    pub fn value(&self) -> Vec<u8> {
        self.value.clone()
    }
    pub fn datatype(&self) -> u8 {
        self.datatype
    }
    pub fn expiry(&self) -> Option<u32> {
        self.expiry
    }
    pub fn preserve_expiry(&self) -> Option<bool> {
        self.preserve_expiry
    }
    pub fn cas(&self) -> Option<u64> {
        self.cas
    }
    pub fn on_behalf_of(&self) -> Option<String> {
        self.on_behalf_of.clone()
    }
    pub fn durability_level(&self) -> Option<DurabilityLevel> {
        self.durability_level
    }
    pub fn durability_level_timeout(&self) -> Option<Duration> {
        self.durability_level_timeout
    }
}
