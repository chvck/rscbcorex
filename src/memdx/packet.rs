use crate::memdx::magic::Magic;
use crate::memdx::opcode::OpCode;
use crate::memdx::status::Status;
use std::fmt::Debug;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResponsePacket {
    magic: Magic,
    op_code: OpCode,
    datatype: u8,
    status: Status,
    opaque: u32,
    vbucket_id: Option<u16>,
    cas: Option<u64>,
    extras: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
    value: Option<Vec<u8>>,
    framing_extras: Option<Vec<u8>>,
}

impl ResponsePacket {
    pub fn new(magic: Magic, op_code: OpCode, datatype: u8, status: Status, opaque: u32) -> Self {
        Self {
            magic,
            op_code,
            datatype,
            status,
            opaque,
            vbucket_id: None,
            cas: None,
            extras: None,
            key: None,
            value: None,
            framing_extras: None,
        }
    }

    pub fn set_vbucket_id(&mut self, vbucket_id: u16) {
        self.vbucket_id = Some(vbucket_id);
    }

    pub fn set_cas(&mut self, cas: u64) {
        self.cas = Some(cas);
    }

    pub fn set_extras(&mut self, extras: Vec<u8>) {
        self.extras = Some(extras);
    }

    pub fn set_key(&mut self, key: Vec<u8>) {
        self.key = Some(key);
    }

    pub fn set_value(&mut self, value: Vec<u8>) {
        self.value = Some(value);
    }

    pub fn set_framing_extras(&mut self, framing_extras: Vec<u8>) {
        self.framing_extras = Some(framing_extras);
    }
    pub fn magic(&self) -> Magic {
        self.magic
    }
    pub fn op_code(&self) -> OpCode {
        self.op_code
    }
    pub fn datatype(&self) -> u8 {
        self.datatype
    }
    pub fn status(&self) -> Status {
        self.status
    }
    pub fn opaque(&self) -> u32 {
        self.opaque
    }
    pub fn vbucket_id(&self) -> Option<u16> {
        self.vbucket_id
    }
    pub fn cas(&self) -> Option<u64> {
        self.cas
    }
    pub fn extras(&self) -> &Option<Vec<u8>> {
        &self.extras
    }
    pub fn key(&self) -> &Option<Vec<u8>> {
        &self.key
    }
    pub fn value(&self) -> &Option<Vec<u8>> {
        &self.value
    }
    pub fn framing_extras(&self) -> &Option<Vec<u8>> {
        &self.framing_extras
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestPacket {
    pub magic: Magic,
    pub op_code: OpCode,
    pub datatype: u8,
    pub vbucket_id: Option<u16>,
    pub cas: Option<u64>,
    pub extras: Option<Vec<u8>>,
    pub key: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
    pub framing_extras: Option<Vec<u8>>,

    pub opaque: Option<u32>,
}
