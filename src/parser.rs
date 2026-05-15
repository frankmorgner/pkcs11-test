#![allow(dead_code)]

use serde::Deserialize;
use strum_macros::Display;

#[derive(Debug, Deserialize)]
pub struct PKCS11 {
    #[serde(rename = "$value")]
    pub steps: Option<Vec<TestStep>>,
}

#[derive(Debug, Display, Deserialize)]
#[allow(non_camel_case_types)]
pub enum TestStep {
    C_GetFunctionList {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        /* TODO
        #[serde(rename = "FunctionList")]
        function_list: Option<XXX>,
        */
    },
    C_GetInterface {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "InterfaceName")]
        interface_name: Option<XmlValue>,
        #[serde(rename = "Version")]
        version: Option<Version>,
        /* TODO
        #[serde(rename = "Interface")]
        interface: Option<XXX>,
        */
        #[serde(rename = "Flags")]
        flags: Option<XmlValue>,
    },
    C_Initialize {
        #[serde(rename = "@rv")]
        rv: Option<String>,
    },
    C_Finalize {
        #[serde(rename = "@rv")]
        rv: Option<String>,
    },
    C_GetSlotList {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "TokenPresent")]
        token_present: Option<XmlValue>,
        #[serde(rename = "SlotList")]
        slot_list: Box<SlotList>,
    },
    C_GetSlotInfo {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "SlotID")]
        slot_id: Option<XmlValue>,
        #[serde(rename = "Info")]
        info: Option<Box<SlotInfo>>,
        #[serde(rename = "SlotInfo")]
        slot_info: Option<Box<SlotInfo>>,
    },
    C_GetInfo {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Info")]
        info: Option<Info>,
    },
    C_GetTokenInfo {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "SlotID")]
        slot_id: Option<XmlValue>,
        #[serde(rename = "Info")]
        info: Option<Box<InfoTokenInfo>>,
        #[serde(rename = "TokenInfo")]
        token_info: Option<Box<TokenInfo>>,
    },
    C_OpenSession {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "SlotID")]
        slot_id: Option<XmlValue>,
        #[serde(rename = "Flags")]
        flags: Option<XmlValue>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
    },
    C_SessionCancel {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Flags")]
        flags: Option<XmlValue>,
    },
    C_FindObjectsInit {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Template", default)]
        template: Option<Box<Template>>,
    },
    C_FindObjects {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Object", default)]
        objects: Option<Box<ObjectList>>,
    },
    C_FindObjectsFinal {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
    },
    C_CreateObject {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Template", default)]
        template: Option<Box<Template>>,
        #[serde(rename = "Object")]
        object: Option<XmlValue>,
    },
    C_CopyObject {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Object")]
        object: Option<XmlValue>,
        #[serde(rename = "Template", default)]
        template: Option<Box<Template>>,
        #[serde(rename = "NewObject")]
        new_object: Option<XmlValue>,
    },
    C_DestroyObject {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Object")]
        object: Option<XmlValue>,
    },
    C_GetObjectSize {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Object")]
        object: Option<XmlValue>,
        #[serde(rename = "Size")]
        size: Option<XmlValue>,
    },
    C_CloseSession {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
    },
    C_CloseAllSessions {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "SlotID")]
        slot_id: Option<XmlValue>,
    },
    C_Login {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "UserType")]
        user_type: Option<XmlValue>,
        #[serde(rename = "Pin")]
        pin: Option<XmlValue>,
    },
    C_LoginUser {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "UserType")]
        user_type: Option<XmlValue>,
        #[serde(rename = "Pin")]
        pin: Option<XmlValue>,
        #[serde(rename = "Username")]
        username: Option<XmlValue>,
    },
    C_Logout {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
    },
    C_GetAttributeValue {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Object", default)]
        object: Option<XmlValue>,
        #[serde(rename = "Template", default)]
        template: Option<Box<Template>>,
    },
    C_SetAttributeValue {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Object", default)]
        object: Option<XmlValue>,
        #[serde(rename = "Template", default)]
        template: Option<Box<Template>>,
    },
    C_GetMechanismList {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "SlotID")]
        slot_id: Option<XmlValue>,
        #[serde(rename = "MechanismList")]
        mechanism_list: Box<MechanismList>,
    },
    C_GetMechanismInfo {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "SlotID")]
        slot_id: Option<XmlValue>,
        #[serde(rename = "Type")]
        mechanism: Option<XmlValue>,
        #[serde(rename = "Info")]
        info: Option<Box<InfoMechanismInfo>>,
        #[serde(rename = "MechanismInfo")]
        mechanism_info: Option<Box<MechanismInfo>>,
    },
    C_SignInit {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Mechanism")]
        mechanism: Option<Mechanism>,
        #[serde(rename = "Key")]
        key: Option<XmlValue>,
    },
    C_Sign {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Data")]
        data: Option<XmlValue>,
        #[serde(rename = "Signature")]
        signature: Option<XmlLengthValue>,
    },
    C_SignUpdate {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Part")]
        part: Option<XmlValue>,
    },
    C_SignFinal {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Signature")]
        signature: Option<XmlLengthValue>,
    },
    C_SignRecoverInit {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Mechanism")]
        mechanism: Option<Mechanism>,
        #[serde(rename = "Key")]
        key: Option<XmlValue>,
    },
    C_SignRecover {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Data")]
        data: Option<XmlValue>,
        #[serde(rename = "Signature")]
        signature: Option<XmlLengthValue>,
    },
    C_MessageSignInit {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Mechanism")]
        mechanism: Option<Mechanism>,
        #[serde(rename = "Key")]
        key: Option<XmlValue>,
    },
    C_SignMessage {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Parameter")]
        parameter: Option<XmlValue>,
        #[serde(rename = "Data")]
        data: Option<XmlValue>,
        #[serde(rename = "Signature")]
        signature: Option<XmlLengthValue>,
    },
    C_EncryptInit {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Mechanism")]
        mechanism: Option<Box<Mechanism>>,
        #[serde(rename = "Key")]
        key: Option<XmlValue>,
    },
    C_Encrypt {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Data")]
        data: Option<XmlValue>,
        #[serde(rename = "EncryptedData")]
        encrypted_data: Option<XmlLengthValue>,
    },
    C_EncryptUpdate {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Part")]
        part: Option<XmlValue>,
        #[serde(rename = "EncryptedPart")]
        encrypted_part: Option<XmlLengthValue>,
    },
    C_EncryptFinal {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "LastEncryptedPart")]
        last_encrypted_part: Option<XmlLengthValue>,
    },
    C_DecryptInit {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Mechanism")]
        mechanism: Option<Box<Mechanism>>,
        #[serde(rename = "Key")]
        key: Option<XmlValue>,
    },
    C_Decrypt {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Data")]
        data: Option<XmlValue>,
        #[serde(rename = "DecryptedData")]
        decrypted_data: Option<XmlLengthValue>,
    },
    C_DecryptUpdate {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Part")]
        part: Option<XmlValue>,
        #[serde(rename = "DecryptedPart")]
        decrypted_part: Option<XmlLengthValue>,
    },
    C_DecryptFinal {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "LastDecryptedPart")]
        last_decrypted_part: Option<XmlLengthValue>,
    },
    C_DigestInit {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Mechanism")]
        mechanism: Option<Box<Mechanism>>,
    },
    C_Digest {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Data")]
        data: Option<XmlValue>,
        #[serde(rename = "Digest")]
        digest: Option<XmlLengthValue>,
    },
    C_DigestUpdate {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Part")]
        part: Option<XmlValue>,
    },
    C_DigestKey {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Mechanism")]
        key: Option<XmlValue>,
    },
    C_DigestFinal {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Digest")]
        digest: Option<XmlLengthValue>,
    },
    C_InitToken {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "SlotID")]
        slot_id: Option<XmlValue>,
        #[serde(rename = "Pin")]
        pin: Option<XmlValue>,
        #[serde(rename = "Label")]
        label: Option<XmlValue>,
    },
    C_InitPIN {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Pin")]
        pin: Option<XmlValue>,
    },
    C_SetPIN {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "OldPin")]
        old_pin: Option<XmlValue>,
        #[serde(rename = "NewPin")]
        new_pin: Option<XmlValue>,
    },
    C_GenerateKeyPair {
        #[serde(rename = "@rv")]
        rv: Option<String>,
        #[serde(rename = "Session")]
        session: Option<XmlValue>,
        #[serde(rename = "Mechanism")]
        key: Option<Mechanism>,
        #[serde(rename = "PublicKeyTemplate", default)]
        public_template: Option<Box<Template>>,
        #[serde(rename = "PrivateKeyTemplate", default)]
        private_template: Option<Box<Template>>,
        #[serde(rename = "PublicKey")]
        public_key: Option<XmlValue>,
        #[serde(rename = "PrivateKey")]
        private_key: Option<XmlValue>,
    },
}

#[derive(Debug, Deserialize, Default)]
pub struct ObjectList {
    #[serde(rename = "@length")]
    pub length: Option<String>,

    #[serde(rename = "Object", default)]
    pub object: Option<Vec<XmlValue>>,
}

#[derive(Debug, Deserialize)]
pub struct Template {
    #[serde(rename = "Attribute", default)]
    pub attribute: Option<Vec<Attribute>>,
}

#[derive(Debug, Deserialize)]
pub struct Attribute {
    #[serde(rename = "@type")]
    pub typ: String,
    #[serde(rename = "@value")]
    pub value: Option<String>,
    #[serde(rename = "@length")]
    pub length: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Mechanism {
    #[serde(rename = "Type")]
    pub typ: XmlValue,
    #[serde(rename = "Parameter")]
    pub parameter: Option<Parameter>,
}

#[derive(Debug, Deserialize)]
pub struct Parameter {
    #[serde(rename = "@length")]
    pub length: String,
    // TODO add CK_*_PARAMS
}

#[derive(Debug, Deserialize, Default)]
pub struct SlotList {
    #[serde(rename = "@length")]
    pub length: Option<String>,

    #[serde(rename = "SlotID", default)]
    pub slot_ids: Option<Vec<XmlValue>>,
}

#[derive(Debug, Deserialize, Default)]
pub struct MechanismList {
    #[serde(rename = "@length")]
    pub length: Option<String>,

    #[serde(rename = "Type", default)]
    pub typ: Option<Vec<XmlValue>>,
}

#[derive(Debug, Deserialize)]
pub struct Info {
    #[serde(rename = "CryptokiVersion")]
    pub cryptoki_version: Version,
    #[serde(rename = "ManufacturerID")]
    pub manufacturer_id: XmlValue,
    #[serde(rename = "Flags")]
    pub flags: XmlValue,
    #[serde(rename = "LibraryDescription")]
    pub library_description: XmlValue,
    #[serde(rename = "LibraryVersion")]
    pub library_version: Version,
}

#[derive(Debug, Deserialize)]
pub struct SlotInfo {
    #[serde(rename = "SlotDescription")]
    pub slot_description: XmlValue,
    #[serde(rename = "ManufacturerID")]
    pub manufacturer_id: XmlValue,
    #[serde(rename = "Flags")]
    pub flags: XmlValue,
    #[serde(rename = "HardwareVersion")]
    pub hardware_version: Version,
    #[serde(rename = "FirmwareVersion")]
    pub firmware_version: Version,
}

#[derive(Debug, Deserialize)]
pub struct InfoTokenInfo {
    #[serde(rename = "@MaxSessionCount")]
    pub max_session_count: String,
    #[serde(rename = "@SessionCount")]
    pub session_count: String,
    #[serde(rename = "@MaxRwSessionCount")]
    pub max_rw_session_count: String,
    #[serde(rename = "@RwSessionCount")]
    pub rw_session_count: String,
    #[serde(rename = "@MaxPinLen")]
    pub max_pin_len: String,
    #[serde(rename = "@MinPinLen")]
    pub min_pin_len: String,
    #[serde(rename = "@TotalPublicMemory")]
    pub total_public_memory: String,
    #[serde(rename = "@FreePublicMemory")]
    pub free_public_memory: String,
    #[serde(rename = "@TotalPrivateMemory")]
    pub total_private_memory: String,
    #[serde(rename = "@FreePrivateMemory")]
    pub free_private_memory: String,
    #[serde(rename = "label")]
    pub label: XmlValue,
    #[serde(rename = "ManufacturerID")]
    pub manufacturer_id: XmlValue,
    #[serde(rename = "model")]
    pub model: XmlValue,
    #[serde(rename = "serialNumber")]
    pub serial_number: XmlValue,
    #[serde(rename = "Flags")]
    pub flags: XmlValue,
    #[serde(rename = "HardwareVersion")]
    pub hardware_version: Version,
    #[serde(rename = "FirmwareVersion")]
    pub firmware_version: Version,
    #[serde(rename = "utcTime")]
    pub utc_time: XmlValue,
}

#[derive(Debug, Deserialize)]
pub struct TokenInfo {
    #[serde(rename = "MaxSessionCount")]
    pub max_session_count: XmlValue,
    #[serde(rename = "SessionCount")]
    pub session_count: XmlValue,
    #[serde(rename = "MaxRwSessionCount")]
    pub max_rw_session_count: XmlValue,
    #[serde(rename = "RwSessionCount")]
    pub rw_session_count: XmlValue,
    #[serde(rename = "MaxPinLen")]
    pub max_pin_len: XmlValue,
    #[serde(rename = "MinPinLen")]
    pub min_pin_len: XmlValue,
    #[serde(rename = "TotalPublicMemory")]
    pub total_public_memory: XmlValue,
    #[serde(rename = "FreePublicMemory")]
    pub free_public_memory: XmlValue,
    #[serde(rename = "TotalPrivateMemory")]
    pub total_private_memory: XmlValue,
    #[serde(rename = "FreePrivateMemory")]
    pub free_private_memory: XmlValue,
    #[serde(rename = "label")]
    pub label: XmlValue,
    #[serde(rename = "ManufacturerID")]
    pub manufacturer_id: XmlValue,
    #[serde(rename = "model")]
    pub model: XmlValue,
    #[serde(rename = "serialNumber")]
    pub serial_number: XmlValue,
    #[serde(rename = "Flags")]
    pub flags: XmlValue,
    #[serde(rename = "HardwareVersion")]
    pub hardware_version: Version,
    #[serde(rename = "FirmwareVersion")]
    pub firmware_version: Version,
    #[serde(rename = "utcTime")]
    pub utc_time: XmlValue,
}

#[derive(Debug, Deserialize)]
pub struct MechanismInfo {
    #[serde(rename = "Flags")]
    pub flags: XmlValue,
    #[serde(rename = "MinKeySize")]
    pub min_key_size: XmlValue,
    #[serde(rename = "MaxKeySize")]
    pub max_key_size: XmlValue,
}

#[derive(Debug, Deserialize)]
pub struct InfoMechanismInfo {
    #[serde(rename = "Flags")]
    pub flags: XmlValue,
    #[serde(rename = "@MinKeySize")]
    pub min_key_size: String,
    #[serde(rename = "@MaxKeySize")]
    pub max_key_size: String,
}

#[derive(Debug, Deserialize)]
pub struct Version {
    #[serde(rename = "@major")]
    pub major: String,
    #[serde(rename = "@minor")]
    pub minor: String,
}

#[derive(Debug, Deserialize)]
pub struct XmlValue {
    #[serde(rename = "@value")]
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct XmlLengthValue {
    #[serde(rename = "@value")]
    pub value: Option<String>,
    #[serde(rename = "@length")]
    pub length: Option<String>,
}
