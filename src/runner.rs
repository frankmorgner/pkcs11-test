use crate::parser;
use crate::report;

use parser::PKCS11;

use cryptoki_sys::*;

use std::any::Any;
use std::collections::HashMap;
use std::ptr;
use num_traits::Num;

#[derive(Debug)]
pub enum NativeValue {
    Bool(CK_BBOOL),
    Bytes(Vec<u8>),
    Ulong(CK_ULONG),
}

#[macro_export]
macro_rules! log_mismatches {
    ( $( $f:expr, $e:expr ),* ) => {
        $crate::report::record_result($crate::report::StepResult::Mismatch(vec![
            $(
                $crate::report::Mismatch {
                    field: $f.to_string(),
                    error: $e.to_string(),
                }
            ),*
        ]))
    };
}

fn parse_numeric<T: Num>(
    numeric: &str,
) -> Result<T, T::FromStrRadixErr> {
    let stripped = numeric
        .strip_prefix("0x")
        .or_else(|| numeric.strip_prefix("0X"))
        .unwrap_or(numeric);
    let radix = if numeric.starts_with("0x") || numeric.starts_with("0X") { 16 } else { 10 };

    T::from_str_radix(stripped, radix)
}

fn parse_binary(
    binary: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !binary.is_ascii() || binary.len() % 2 != 0 {
        return Err("Invalid hex string length or contains non-ascii".into());
    }

    binary.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let s = std::str::from_utf8(chunk)?;
            u8::from_str_radix(s, 16).map_err(|e| e.into())
        })
        .collect()
}

fn parse_boolean(
    boolean: &str,
) -> Result<CK_BBOOL, Box<dyn std::error::Error>> {
    parse_numeric::<CK_BBOOL>(boolean).or(
        match boolean.trim().to_lowercase().as_str() {
            "true"  => Ok(CK_TRUE),
            "false" => Ok(CK_FALSE),
            b       => Err(format!("Could not parse CK_BBOOL {:?}", b).into()),
        }
    )
}

fn parse_limit(
    limit: &str,
) -> Result<CK_ULONG, Box<dyn std::error::Error>> {
    parse_numeric::<CK_ULONG>(limit).or(
        match limit {
            "UNAVAILABLE_INFORMATION"  => Ok(CK_UNAVAILABLE_INFORMATION),
            "EFFECTIVELY_INFINITE" => Ok(CK_EFFECTIVELY_INFINITE),
            b       => Err(format!("Could not parse limit {:?}", b).into()),
        }
    )
}

fn parse_ck_user_type(
    user_type: &str,
) -> Result<CK_USER_TYPE, Box<dyn std::error::Error>> {
    parse_numeric::<CK_USER_TYPE>(user_type).or(
        match user_type {
            "SO" => Ok(CKU_SO),
            "USER" => Ok(CKU_USER),
            "CONTEXT_SPECIFIC" => Ok(CKU_CONTEXT_SPECIFIC),
            r => Err(format!("Could not parse CK_USER_TYPE {:?}", r).into()),
        }
    )
}

fn parse_ck_rv(
    rv: &str,
) -> Result<CK_RV, Box<dyn std::error::Error>> {
    parse_numeric::<CK_RV>(rv).or(
        match rv {
            "OK" => Ok(CKR_OK),
            "CANCEL" => Ok(CKR_CANCEL),
            "HOST_MEMORY" => Ok(CKR_HOST_MEMORY),
            "SLOT_ID_INVALID" => Ok(CKR_SLOT_ID_INVALID),
            "GENERAL_ERROR" => Ok(CKR_GENERAL_ERROR),
            "FUNCTION_FAILED" => Ok(CKR_FUNCTION_FAILED),
            "ARGUMENTS_BAD" => Ok(CKR_ARGUMENTS_BAD),
            "NO_EVENT" => Ok(CKR_NO_EVENT),
            "NEED_TO_CREATE_THREADS" => Ok(CKR_NEED_TO_CREATE_THREADS),
            "CANT_LOCK" => Ok(CKR_CANT_LOCK),
            "ATTRIBUTE_READ_ONLY" => Ok(CKR_ATTRIBUTE_READ_ONLY),
            "ATTRIBUTE_SENSITIVE" => Ok(CKR_ATTRIBUTE_SENSITIVE),
            "ATTRIBUTE_TYPE_INVALID" => Ok(CKR_ATTRIBUTE_TYPE_INVALID),
            "ATTRIBUTE_VALUE_INVALID" => Ok(CKR_ATTRIBUTE_VALUE_INVALID),
            "ACTION_PROHIBITED" => Ok(CKR_ACTION_PROHIBITED),
            "DATA_INVALID" => Ok(CKR_DATA_INVALID),
            "DATA_LEN_RANGE" => Ok(CKR_DATA_LEN_RANGE),
            "DEVICE_ERROR" => Ok(CKR_DEVICE_ERROR),
            "DEVICE_MEMORY" => Ok(CKR_DEVICE_MEMORY),
            "DEVICE_REMOVED" => Ok(CKR_DEVICE_REMOVED),
            "ENCRYPTED_DATA_INVALID" => Ok(CKR_ENCRYPTED_DATA_INVALID),
            "ENCRYPTED_DATA_LEN_RANGE" => Ok(CKR_ENCRYPTED_DATA_LEN_RANGE),
            "AEAD_DECRYPT_FAILED" => Ok(CKR_AEAD_DECRYPT_FAILED),
            "FUNCTION_CANCELED" => Ok(CKR_FUNCTION_CANCELED),
            "FUNCTION_NOT_PARALLEL" => Ok(CKR_FUNCTION_NOT_PARALLEL),
            "FUNCTION_NOT_SUPPORTED" => Ok(CKR_FUNCTION_NOT_SUPPORTED),
            "KEY_HANDLE_INVALID" => Ok(CKR_KEY_HANDLE_INVALID),
            "KEY_SIZE_RANGE" => Ok(CKR_KEY_SIZE_RANGE),
            "KEY_TYPE_INCONSISTENT" => Ok(CKR_KEY_TYPE_INCONSISTENT),
            "KEY_NOT_NEEDED" => Ok(CKR_KEY_NOT_NEEDED),
            "KEY_CHANGED" => Ok(CKR_KEY_CHANGED),
            "KEY_NEEDED" => Ok(CKR_KEY_NEEDED),
            "KEY_INDIGESTIBLE" => Ok(CKR_KEY_INDIGESTIBLE),
            "KEY_FUNCTION_NOT_PERMITTED" => Ok(CKR_KEY_FUNCTION_NOT_PERMITTED),
            "KEY_NOT_WRAPPABLE" => Ok(CKR_KEY_NOT_WRAPPABLE),
            "KEY_UNEXTRACTABLE" => Ok(CKR_KEY_UNEXTRACTABLE),
            "MECHANISM_INVALID" => Ok(CKR_MECHANISM_INVALID),
            "MECHANISM_PARAM_INVALID" => Ok(CKR_MECHANISM_PARAM_INVALID),
            "OBJECT_HANDLE_INVALID" => Ok(CKR_OBJECT_HANDLE_INVALID),
            "OPERATION_ACTIVE" => Ok(CKR_OPERATION_ACTIVE),
            "OPERATION_NOT_INITIALIZED" => Ok(CKR_OPERATION_NOT_INITIALIZED),
            "PIN_INCORRECT" => Ok(CKR_PIN_INCORRECT),
            "PIN_INVALID" => Ok(CKR_PIN_INVALID),
            "PIN_LEN_RANGE" => Ok(CKR_PIN_LEN_RANGE),
            "PIN_EXPIRED" => Ok(CKR_PIN_EXPIRED),
            "PIN_LOCKED" => Ok(CKR_PIN_LOCKED),
            "SESSION_CLOSED" => Ok(CKR_SESSION_CLOSED),
            "SESSION_COUNT" => Ok(CKR_SESSION_COUNT),
            "SESSION_HANDLE_INVALID" => Ok(CKR_SESSION_HANDLE_INVALID),
            "SESSION_PARALLEL_NOT_SUPPORTED" => Ok(CKR_SESSION_PARALLEL_NOT_SUPPORTED),
            "SESSION_READ_ONLY" => Ok(CKR_SESSION_READ_ONLY),
            "SESSION_EXISTS" => Ok(CKR_SESSION_EXISTS),
            "SESSION_READ_ONLY_EXISTS" => Ok(CKR_SESSION_READ_ONLY_EXISTS),
            "SESSION_READ_WRITE_SO_EXISTS" => Ok(CKR_SESSION_READ_WRITE_SO_EXISTS),
            "SIGNATURE_INVALID" => Ok(CKR_SIGNATURE_INVALID),
            "SIGNATURE_LEN_RANGE" => Ok(CKR_SIGNATURE_LEN_RANGE),
            "TEMPLATE_INCOMPLETE" => Ok(CKR_TEMPLATE_INCOMPLETE),
            "TEMPLATE_INCONSISTENT" => Ok(CKR_TEMPLATE_INCONSISTENT),
            "TOKEN_NOT_PRESENT" => Ok(CKR_TOKEN_NOT_PRESENT),
            "TOKEN_NOT_RECOGNIZED" => Ok(CKR_TOKEN_NOT_RECOGNIZED),
            "TOKEN_WRITE_PROTECTED" => Ok(CKR_TOKEN_WRITE_PROTECTED),
            "UNWRAPPING_KEY_HANDLE_INVALID" => Ok(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
            "UNWRAPPING_KEY_SIZE_RANGE" => Ok(CKR_UNWRAPPING_KEY_SIZE_RANGE),
            "UNWRAPPING_KEY_TYPE_INCONSISTENT" => Ok(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT),
            "USER_ALREADY_LOGGED_IN" => Ok(CKR_USER_ALREADY_LOGGED_IN),
            "USER_NOT_LOGGED_IN" => Ok(CKR_USER_NOT_LOGGED_IN),
            "USER_PIN_NOT_INITIALIZED" => Ok(CKR_USER_PIN_NOT_INITIALIZED),
            "USER_TYPE_INVALID" => Ok(CKR_USER_TYPE_INVALID),
            "USER_ANOTHER_ALREADY_LOGGED_IN" => Ok(CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
            "USER_TOO_MANY_TYPES" => Ok(CKR_USER_TOO_MANY_TYPES),
            "WRAPPED_KEY_INVALID" => Ok(CKR_WRAPPED_KEY_INVALID),
            "WRAPPED_KEY_LEN_RANGE" => Ok(CKR_WRAPPED_KEY_LEN_RANGE),
            "WRAPPING_KEY_HANDLE_INVALID" => Ok(CKR_WRAPPING_KEY_HANDLE_INVALID),
            "WRAPPING_KEY_SIZE_RANGE" => Ok(CKR_WRAPPING_KEY_SIZE_RANGE),
            "WRAPPING_KEY_TYPE_INCONSISTENT" => Ok(CKR_WRAPPING_KEY_TYPE_INCONSISTENT),
            "RANDOM_SEED_NOT_SUPPORTED" => Ok(CKR_RANDOM_SEED_NOT_SUPPORTED),
            "RANDOM_NO_RNG" => Ok(CKR_RANDOM_NO_RNG),
            "DOMAIN_PARAMS_INVALID" => Ok(CKR_DOMAIN_PARAMS_INVALID),
            "CURVE_NOT_SUPPORTED" => Ok(CKR_CURVE_NOT_SUPPORTED),
            "BUFFER_TOO_SMALL" => Ok(CKR_BUFFER_TOO_SMALL),
            "SAVED_STATE_INVALID" => Ok(CKR_SAVED_STATE_INVALID),
            "INFORMATION_SENSITIVE" => Ok(CKR_INFORMATION_SENSITIVE),
            "STATE_UNSAVEABLE" => Ok(CKR_STATE_UNSAVEABLE),
            "CRYPTOKI_NOT_INITIALIZED" => Ok(CKR_CRYPTOKI_NOT_INITIALIZED),
            "CRYPTOKI_ALREADY_INITIALIZED" => Ok(CKR_CRYPTOKI_ALREADY_INITIALIZED),
            "MUTEX_BAD" => Ok(CKR_MUTEX_BAD),
            "MUTEX_NOT_LOCKED" => Ok(CKR_MUTEX_NOT_LOCKED),
            "NEW_PIN_MODE" => Ok(CKR_NEW_PIN_MODE),
            "NEXT_OTP" => Ok(CKR_NEXT_OTP),
            "EXCEEDED_MAX_ITERATIONS" => Ok(CKR_EXCEEDED_MAX_ITERATIONS),
            "FIPS_SELF_TEST_FAILED" => Ok(CKR_FIPS_SELF_TEST_FAILED),
            "LIBRARY_LOAD_FAILED" => Ok(CKR_LIBRARY_LOAD_FAILED),
            "PIN_TOO_WEAK" => Ok(CKR_PIN_TOO_WEAK),
            "PUBLIC_KEY_INVALID" => Ok(CKR_PUBLIC_KEY_INVALID),
            "FUNCTION_REJECTED" => Ok(CKR_FUNCTION_REJECTED),
            "TOKEN_RESOURCE_EXCEEDED" => Ok(CKR_TOKEN_RESOURCE_EXCEEDED),
            "OPERATION_CANCEL_FAILED" => Ok(CKR_OPERATION_CANCEL_FAILED),
            "KEY_EXHAUSTED" => Ok(CKR_KEY_EXHAUSTED),
            "PENDING" => Ok(CKR_PENDING),
            "SESSION_ASYNC_NOT_SUPPORTED" => Ok(CKR_SESSION_ASYNC_NOT_SUPPORTED),
            "SEED_RANDOM_REQUIRED" => Ok(CKR_SEED_RANDOM_REQUIRED),
            "OPERATION_NOT_VALIDATED" => Ok(CKR_OPERATION_NOT_VALIDATED),
            "TOKEN_NOT_INITIALIZED" => Ok(CKR_TOKEN_NOT_INITIALIZED),
            "PARAMETER_SET_NOT_SUPPORTED" => Ok(CKR_PARAMETER_SET_NOT_SUPPORTED),
            "VENDOR_DEFINED" => Ok(CKR_VENDOR_DEFINED),
            r => Err(format!("Could not parse CK_RV {:?}", r).into()),
        }
    )
}

fn parse_ck_flag(
    flag: &str,
) -> Result<CK_FLAGS, Box<dyn std::error::Error>> {
    match flag {
        "LIBRARY_CANT_CREATE_OS_THREADS" => Ok(CKF_LIBRARY_CANT_CREATE_OS_THREADS),
        "OS_LOCKING_OK" => Ok(CKF_OS_LOCKING_OK),
        "HKDF_SALT_NULL" => Ok(CKF_HKDF_SALT_NULL),
        "HKDF_SALT_DATA" => Ok(CKF_HKDF_SALT_DATA),
        "HKDF_SALT_KEY" => Ok(CKF_HKDF_SALT_KEY),
        "INTERFACE_FORK_SAFE" => Ok(CKF_INTERFACE_FORK_SAFE),
        "HW" => Ok(CKF_HW),
        "MESSAGE_ENCRYPT" => Ok(CKF_MESSAGE_ENCRYPT),
        "MESSAGE_DECRYPT" => Ok(CKF_MESSAGE_DECRYPT),
        "MESSAGE_SIGN" => Ok(CKF_MESSAGE_SIGN),
        "MESSAGE_VERIFY" => Ok(CKF_MESSAGE_VERIFY),
        "MULTI_MESSAGE" => Ok(CKF_MULTI_MESSAGE),
        "FIND_OBJECTS" => Ok(CKF_FIND_OBJECTS),
        "ENCRYPT" => Ok(CKF_ENCRYPT),
        "DECRYPT" => Ok(CKF_DECRYPT),
        "DIGEST" => Ok(CKF_DIGEST),
        "SIGN" => Ok(CKF_SIGN),
        "SIGN_RECOVER" => Ok(CKF_SIGN_RECOVER),
        "VERIFY" => Ok(CKF_VERIFY),
        "VERIFY_RECOVER" => Ok(CKF_VERIFY_RECOVER),
        "GENERATE" => Ok(CKF_GENERATE),
        "GENERATE_KEY_PAIR" => Ok(CKF_GENERATE_KEY_PAIR),
        "WRAP" => Ok(CKF_WRAP),
        "UNWRAP" => Ok(CKF_UNWRAP),
        "DERIVE" => Ok(CKF_DERIVE),
        "EC_F_P" => Ok(CKF_EC_F_P),
        "EC_F_2M" => Ok(CKF_EC_F_2M),
        "EC_ECPARAMETERS" => Ok(CKF_EC_ECPARAMETERS),
        "EC_OID" => Ok(CKF_EC_OID),
        "EC_UNCOMPRESS" => Ok(CKF_EC_UNCOMPRESS),
        "EC_COMPRESS" => Ok(CKF_EC_COMPRESS),
        "EC_CURVENAME" => Ok(CKF_EC_CURVENAME),
        "ENCAPSULATE" => Ok(CKF_ENCAPSULATE),
        "DECAPSULATE" => Ok(CKF_DECAPSULATE),
        "EXTENSION" => Ok(CKF_EXTENSION),
        "EC_NAMEDCURVE" => Ok(CKF_EC_NAMEDCURVE),
        "END_OF_MESSAGE" => Ok(CKF_END_OF_MESSAGE),
        "NEXT_OTP" => Ok(CKF_NEXT_OTP),
        "EXCLUDE_TIME" => Ok(CKF_EXCLUDE_TIME),
        "EXCLUDE_COUNTER" => Ok(CKF_EXCLUDE_COUNTER),
        "EXCLUDE_CHALLENGE" => Ok(CKF_EXCLUDE_CHALLENGE),
        "EXCLUDE_PIN" => Ok(CKF_EXCLUDE_PIN),
        "USER_FRIENDLY_OTP" => Ok(CKF_USER_FRIENDLY_OTP),
        "DONT_BLOCK" => Ok(CKF_DONT_BLOCK),
        "RW_SESSION" => Ok(CKF_RW_SESSION),
        "SERIAL_SESSION" => Ok(CKF_SERIAL_SESSION),
        "ASYNC_SESSION" => Ok(CKF_ASYNC_SESSION),
        "TOKEN_PRESENT" => Ok(CKF_TOKEN_PRESENT),
        "REMOVABLE_DEVICE" => Ok(CKF_REMOVABLE_DEVICE),
        "HW_SLOT" => Ok(CKF_HW_SLOT),
        "RNG" => Ok(CKF_RNG),
        "WRITE_PROTECTED" => Ok(CKF_WRITE_PROTECTED),
        "LOGIN_REQUIRED" => Ok(CKF_LOGIN_REQUIRED),
        "USER_PIN_INITIALIZED" => Ok(CKF_USER_PIN_INITIALIZED),
        "RESTORE_KEY_NOT_NEEDED" => Ok(CKF_RESTORE_KEY_NOT_NEEDED),
        "CLOCK_ON_TOKEN" => Ok(CKF_CLOCK_ON_TOKEN),
        "PROTECTED_AUTHENTICATION_PATH" => Ok(CKF_PROTECTED_AUTHENTICATION_PATH),
        "DUAL_CRYPTO_OPERATIONS" => Ok(CKF_DUAL_CRYPTO_OPERATIONS),
        "TOKEN_INITIALIZED" => Ok(CKF_TOKEN_INITIALIZED),
        "SECONDARY_AUTHENTICATION" => Ok(CKF_SECONDARY_AUTHENTICATION),
        "USER_PIN_COUNT_LOW" => Ok(CKF_USER_PIN_COUNT_LOW),
        "USER_PIN_FINAL_TRY" => Ok(CKF_USER_PIN_FINAL_TRY),
        "USER_PIN_LOCKED" => Ok(CKF_USER_PIN_LOCKED),
        "USER_PIN_TO_BE_CHANGED" => Ok(CKF_USER_PIN_TO_BE_CHANGED),
        "SO_PIN_COUNT_LOW" => Ok(CKF_SO_PIN_COUNT_LOW),
        "SO_PIN_FINAL_TRY" => Ok(CKF_SO_PIN_FINAL_TRY),
        "SO_PIN_LOCKED" => Ok(CKF_SO_PIN_LOCKED),
        "SO_PIN_TO_BE_CHANGED" => Ok(CKF_SO_PIN_TO_BE_CHANGED),
        "ERROR_STATE" => Ok(CKF_ERROR_STATE),
        "SEED_RANDOM_REQUIRED" => Ok(CKF_SEED_RANDOM_REQUIRED),
        "ASYNC_SESSION_SUPPORTED" => Ok(CKF_ASYNC_SESSION_SUPPORTED),
        f => Err(format!("Could not parse CK_FLAGS {:?}", f).into()),
    }
}

fn parse_ck_flags(
    flags: &str,
) -> Result<CK_FLAGS, Box<dyn std::error::Error>> {
    parse_numeric::<CK_FLAGS>(flags).or(
        flags.split(|c| c == '|' || c == ' ')
            .filter(|s| !s.is_empty())
            .try_fold(0, |acc, part| Ok(acc | parse_ck_flag(part)?))
    )
}

pub fn parse_attributes(
    template: &parser::Template,
) -> Result<(Vec<CK_ATTRIBUTE>, Vec<NativeValue>), Box<dyn std::error::Error>> {
    let attr_list = match &template.attribute {
        Some(list) => list,
        None => return Ok((Vec::new(), Vec::new())),
    };

    let mut value_buffer = Vec::with_capacity(attr_list.len());
    let mut attr_types = Vec::with_capacity(attr_list.len());

    // First pass: allocate native data structures
    for attr in attr_list {
        let ck_type = match attr.typ.as_str() {
            // CK_BBOOL
            "TOKEN" => CKA_TOKEN,
            "PRIVATE" => CKA_PRIVATE,
            "COPYABLE" => CKA_COPYABLE,
            "DESTROYABLE" => CKA_DESTROYABLE,
            "RESET_ON_INIT" => CKA_RESET_ON_INIT,
            "HAS_RESET" => CKA_HAS_RESET,
            "COLOR" => CKA_COLOR,
            "TRUSTED" => CKA_TRUSTED,
            "DERIVE" => CKA_DERIVE,
            "LOCAL" => CKA_LOCAL,
            "ENCRYPT" => CKA_ENCRYPT,
            "VERIFY" => CKA_VERIFY,
            "VERIFY_RECOVER" => CKA_VERIFY_RECOVER,
            "WRAP" => CKA_WRAP,
            "SENSITIVE" => CKA_SENSITIVE,
            "DECRYPT" => CKA_DECRYPT,
            "SIGN" => CKA_SIGN,
            "SIGN_RECOVER" => CKA_SIGN_RECOVER,
            "UNWRAP" => CKA_UNWRAP,
            "EXTRACTABLE" => CKA_EXTRACTABLE,
            "ALWAYS_SENSITIVE" => CKA_ALWAYS_SENSITIVE,
            "NEVER_EXTRACTABLE" => CKA_NEVER_EXTRACTABLE,
            "WRAP_WITH_TRUSTED" => CKA_WRAP_WITH_TRUSTED,
            "ALWAYS_AUTHENTICATE" => CKA_ALWAYS_AUTHENTICATE,

            // RFC2279 string
            "LABEL" => CKA_LABEL,
            "UNIQUE_ID" => CKA_UNIQUE_ID,
            "CHAR_SETS" => CKA_CHAR_SETS,
            "ENCODING_METHODS" => CKA_ENCODING_METHODS,
            "MIME_TYPES" => CKA_MIME_TYPES,
            "APPLICATION" => CKA_APPLICATION,
            "URL" => CKA_URL,

            // CK_OBJECT_CLASS
            "CLASS" => CKA_CLASS,

            // CK_OBJECT_CLASS
            "CERTIFICATE_TYPE" => CKA_CERTIFICATE_TYPE,

            // CK_KEY_TYPE
            "KEY_TYPE" => CKA_KEY_TYPE,

            "MODULUS_BITS" => CKA_MODULUS_BITS,

            // Byte Array
            "ATTR_TYPES" => CKA_ATTR_TYPES,
            "AC_ISSUER" => CKA_AC_ISSUER,
            "OWNER" => CKA_OWNER,
            "HASH_OF_SUBJECT_PUBLIC_KEY" => CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
            "HASH_OF_ISSUER_PUBLIC_KEY" => CKA_HASH_OF_ISSUER_PUBLIC_KEY,
            "SERIAL_NUMBER" => CKA_SERIAL_NUMBER,
            "ISSUER" => CKA_ISSUER,
            "ID" => CKA_ID,
            "VALUE" => CKA_VALUE,
            "SUBJECT" => CKA_SUBJECT,
            "PUBLIC_KEY_INFO" => CKA_PUBLIC_KEY_INFO,
            "CHECK_VALUE" => CKA_CHECK_VALUE,
            "OBJECT_ID" => CKA_OBJECT_ID,

            // Big integer
            "MODULUS" => CKA_MODULUS,
            "PUBLIC_EXPONENT" => CKA_PUBLIC_EXPONENT,
            "PRIVATE_EXPONENT" => CKA_PRIVATE_EXPONENT,
            "PRIME_2" => CKA_PRIME_2,
            "PRIME_1" => CKA_PRIME_1,
            "EXPONENT_1" => CKA_EXPONENT_1,
            "EXPONENT_2" => CKA_EXPONENT_2,
            "COEFFICIENT" => CKA_COEFFICIENT,

            unknown => return Err(format!("Unknown Attribute.type {}", unknown).into()),
        };

        let native_val = if let Some(len_str) = &attr.length {
            let buffer_len = parse_numeric::<CK_ULONG>(len_str.as_str())?;
            NativeValue::Bytes(vec![0u8; buffer_len.try_into()?])
        } else {
            let str_value = attr.value.as_deref().unwrap_or("");

            match attr.typ.as_str() {
                // CK_BBOOL
                "TOKEN" | "PRIVATE" | "COPYABLE" | "DESTROYABLE" | "RESET_ON_INIT" | "HAS_RESET" |
                "COLOR" | "TRUSTED" | "DERIVE" | "LOCAL" | "ENCRYPT" | "VERIFY" | "VERIFY_RECOVER" |
                "WRAP" | "SENSITIVE" | "DECRYPT" | "SIGN" | "SIGN_RECOVER" | "UNWRAP" | "EXTRACTABLE" |
                "ALWAYS_SENSITIVE" | "NEVER_EXTRACTABLE" | "WRAP_WITH_TRUSTED" | "ALWAYS_AUTHENTICATE" => {
                    NativeValue::Bool(parse_boolean(str_value)?)
                }

                // Strings
                "LABEL" | "UNIQUE_ID" | "CHAR_SETS" | "ENCODING_METHODS" | "MIME_TYPES" | "APPLICATION" | "URL" => {
                    NativeValue::Bytes(str_value.as_bytes().to_vec())
                }

                // CK_OBJECT_CLASS
                "CLASS" => {
                    let class_val = match str_value {
                        "DATA" => CKO_DATA,
                        "CERTIFICATE" => CKO_CERTIFICATE,
                        "PUBLIC_KEY" => CKO_PUBLIC_KEY,
                        "PRIVATE_KEY" => CKO_PRIVATE_KEY,
                        "SECRET_KEY" => CKO_SECRET_KEY,
                        "HW_FEATURE" => CKO_HW_FEATURE,
                        "DOMAIN_PARAMETERS" => CKO_DOMAIN_PARAMETERS,
                        "MECHANISM" => CKO_MECHANISM,
                        "OTP_KEY" => CKO_OTP_KEY,
                        "PROFILE" => CKO_PROFILE,
                        "VALIDATION" => CKO_VALIDATION,
                        "TRUST" => CKO_TRUST,
                        "VENDOR_DEFINED" => CKO_VENDOR_DEFINED,
                        numeric_str => parse_numeric::<CK_OBJECT_CLASS>(numeric_str).map_err(|e| format!("{}", e))?,
                    };
                    NativeValue::Ulong(class_val)
                }

                // CK_CERTIFICATE_TYPE
                "CERTIFICATE_TYPE" => {
                    let class_val = match str_value {
                        "X_509" => CKC_X_509,
                        "X_509_ATTR_CERT" => CKC_X_509_ATTR_CERT,
                        "WTLS" => CKC_WTLS,
                        "VENDOR_DEFINED" => CKC_VENDOR_DEFINED,
                        numeric_str => parse_numeric::<CK_CERTIFICATE_TYPE>(numeric_str).map_err(|e| format!("{}", e))?,
                    };
                    NativeValue::Ulong(class_val)
                }

                "MODULUS_BITS" => {
                    let class_val = parse_numeric::<CK_ULONG>(str_value).map_err(|e| format!("{}", e))?;
                    NativeValue::Ulong(class_val)
                }

                // CK_KEY_TYPE
                "KEY_TYPE" => {
                    let class_val = match str_value {
                        "RSA" => CKK_RSA,
                        "DSA" => CKK_DSA,
                        "DH" => CKK_DH,
                        "EC" => CKK_EC,
                        "X9_42_DH" => CKK_X9_42_DH,
                        "KEA" => CKK_KEA,
                        "GENERIC_SECRET" => CKK_GENERIC_SECRET,
                        "RC2" => CKK_RC2,
                        "RC4" => CKK_RC4,
                        "DES" => CKK_DES,
                        "DES2" => CKK_DES2,
                        "DES3" => CKK_DES3,
                        "CAST" => CKK_CAST,
                        "CAST3" => CKK_CAST3,
                        "CAST128" => CKK_CAST128,
                        "RC5" => CKK_RC5,
                        "IDEA" => CKK_IDEA,
                        "SKIPJACK" => CKK_SKIPJACK,
                        "BATON" => CKK_BATON,
                        "JUNIPER" => CKK_JUNIPER,
                        "CDMF" => CKK_CDMF,
                        "AES" => CKK_AES,
                        "BLOWFISH" => CKK_BLOWFISH,
                        "TWOFISH" => CKK_TWOFISH,
                        "SECURID" => CKK_SECURID,
                        "HOTP" => CKK_HOTP,
                        "ACTI" => CKK_ACTI,
                        "CAMELLIA" => CKK_CAMELLIA,
                        "ARIA" => CKK_ARIA,
                        "MD5_HMAC" => CKK_MD5_HMAC,
                        "SHA_1_HMAC" => CKK_SHA_1_HMAC,
                        "RIPEMD128_HMAC" => CKK_RIPEMD128_HMAC,
                        "RIPEMD160_HMAC" => CKK_RIPEMD160_HMAC,
                        "SHA256_HMAC" => CKK_SHA256_HMAC,
                        "SHA384_HMAC" => CKK_SHA384_HMAC,
                        "SHA512_HMAC" => CKK_SHA512_HMAC,
                        "SHA224_HMAC" => CKK_SHA224_HMAC,
                        "SEED" => CKK_SEED,
                        "GOSTR3410" => CKK_GOSTR3410,
                        "GOSTR3411" => CKK_GOSTR3411,
                        "GOST28147" => CKK_GOST28147,
                        "CHACHA20" => CKK_CHACHA20,
                        "POLY1305" => CKK_POLY1305,
                        "AES_XTS" => CKK_AES_XTS,
                        "SHA3_224_HMAC" => CKK_SHA3_224_HMAC,
                        "SHA3_256_HMAC" => CKK_SHA3_256_HMAC,
                        "SHA3_384_HMAC" => CKK_SHA3_384_HMAC,
                        "SHA3_512_HMAC" => CKK_SHA3_512_HMAC,
                        "BLAKE2B_160_HMAC" => CKK_BLAKE2B_160_HMAC,
                        "BLAKE2B_256_HMAC" => CKK_BLAKE2B_256_HMAC,
                        "BLAKE2B_384_HMAC" => CKK_BLAKE2B_384_HMAC,
                        "BLAKE2B_512_HMAC" => CKK_BLAKE2B_512_HMAC,
                        "SALSA20" => CKK_SALSA20,
                        "X2RATCHET" => CKK_X2RATCHET,
                        "EC_EDWARDS" => CKK_EC_EDWARDS,
                        "EC_MONTGOMERY" => CKK_EC_MONTGOMERY,
                        "HKDF" => CKK_HKDF,
                        "SHA512_224_HMAC" => CKK_SHA512_224_HMAC,
                        "SHA512_256_HMAC" => CKK_SHA512_256_HMAC,
                        "SHA512_T_HMAC" => CKK_SHA512_T_HMAC,
                        "HSS" => CKK_HSS,
                        "XMSS" => CKK_XMSS,
                        "XMSSMT" => CKK_XMSSMT,
                        "ML_KEM" => CKK_ML_KEM,
                        "ML_DSA" => CKK_ML_DSA,
                        "SLH_DSA" => CKK_SLH_DSA,
                        "VENDOR_DEFINED" => CKK_VENDOR_DEFINED,
                        "ECDSA" => CKK_ECDSA,
                        "CAST5" => CKK_CAST5,
                        numeric_str => parse_numeric::<CK_KEY_TYPE>(numeric_str).map_err(|e| format!("{}", e))?,
                    };
                    NativeValue::Ulong(class_val)
                }

                // binary data & BigInts
                _ => NativeValue::Bytes(parse_binary(str_value).map_err(|e| format!("{}", e))?)
            }
        };

        attr_types.push(ck_type);
        value_buffer.push(native_val);
    }

    // Second pass: Derive C pointers and data
    let mut attributes = Vec::with_capacity(value_buffer.len());

    for (i, val) in value_buffer.iter().enumerate() {
        let (p_value, ul_len) = match val {
            // "ref b" sorgt dafür, dass wir auf die Daten IM Vector zeigen!
            NativeValue::Bool(ref b) => {
                (b as *const CK_BBOOL as *mut std::ffi::c_void, std::mem::size_of::<CK_BBOOL>())
            }
            NativeValue::Ulong(ref u) => {
                (u as *const CK_ULONG as *mut std::ffi::c_void, std::mem::size_of::<CK_ULONG>())
            }
            NativeValue::Bytes(bytes) => {
                if bytes.is_empty() {
                    (ptr::null_mut(), 0)
                } else {
                    (bytes.as_ptr() as *mut std::ffi::c_void, bytes.len())
                }
            }
        };

        attributes.push(CK_ATTRIBUTE {
            type_: attr_types[i],
            pValue: p_value,
            ulValueLen: ul_len.try_into()?,
        });
    }

    Ok((attributes, value_buffer))
}

fn parse_mechanism_type(
    mech_type: &str,
) -> Result<CK_MECHANISM_TYPE, Box<dyn std::error::Error>> {
    let typ = match mech_type {
        "RSA_PKCS_KEY_PAIR_GEN" => CKM_RSA_PKCS_KEY_PAIR_GEN,
        "RSA_PKCS" => CKM_RSA_PKCS,
        "RSA_9796" => CKM_RSA_9796,
        "RSA_X_509" => CKM_RSA_X_509,
        "MD2_RSA_PKCS" => CKM_MD2_RSA_PKCS,
        "MD5_RSA_PKCS" => CKM_MD5_RSA_PKCS,
        "SHA1_RSA_PKCS" => CKM_SHA1_RSA_PKCS,
        "RIPEMD128_RSA_PKCS" => CKM_RIPEMD128_RSA_PKCS,
        "RIPEMD160_RSA_PKCS" => CKM_RIPEMD160_RSA_PKCS,
        "RSA_PKCS_OAEP" => CKM_RSA_PKCS_OAEP,
        "RSA_X9_31_KEY_PAIR_GEN" => CKM_RSA_X9_31_KEY_PAIR_GEN,
        "RSA_X9_31" => CKM_RSA_X9_31,
        "SHA1_RSA_X9_31" => CKM_SHA1_RSA_X9_31,
        "RSA_PKCS_PSS" => CKM_RSA_PKCS_PSS,
        "SHA1_RSA_PKCS_PSS" => CKM_SHA1_RSA_PKCS_PSS,
        "ML_KEM_KEY_PAIR_GEN" => CKM_ML_KEM_KEY_PAIR_GEN,
        "DSA_KEY_PAIR_GEN" => CKM_DSA_KEY_PAIR_GEN,
        "DSA" => CKM_DSA,
        "DSA_SHA1" => CKM_DSA_SHA1,
        "DSA_SHA224" => CKM_DSA_SHA224,
        "DSA_SHA256" => CKM_DSA_SHA256,
        "DSA_SHA384" => CKM_DSA_SHA384,
        "DSA_SHA512" => CKM_DSA_SHA512,
        "ML_KEM" => CKM_ML_KEM,
        "DSA_SHA3_224" => CKM_DSA_SHA3_224,
        "DSA_SHA3_256" => CKM_DSA_SHA3_256,
        "DSA_SHA3_384" => CKM_DSA_SHA3_384,
        "DSA_SHA3_512" => CKM_DSA_SHA3_512,
        "ML_DSA_KEY_PAIR_GEN" => CKM_ML_DSA_KEY_PAIR_GEN,
        "ML_DSA" => CKM_ML_DSA,
        "HASH_ML_DSA" => CKM_HASH_ML_DSA,
        "DH_PKCS_KEY_PAIR_GEN" => CKM_DH_PKCS_KEY_PAIR_GEN,
        "DH_PKCS_DERIVE" => CKM_DH_PKCS_DERIVE,
        "HASH_ML_DSA_SHA224" => CKM_HASH_ML_DSA_SHA224,
        "HASH_ML_DSA_SHA256" => CKM_HASH_ML_DSA_SHA256,
        "HASH_ML_DSA_SHA384" => CKM_HASH_ML_DSA_SHA384,
        "HASH_ML_DSA_SHA512" => CKM_HASH_ML_DSA_SHA512,
        "HASH_ML_DSA_SHA3_224" => CKM_HASH_ML_DSA_SHA3_224,
        "HASH_ML_DSA_SHA3_256" => CKM_HASH_ML_DSA_SHA3_256,
        "HASH_ML_DSA_SHA3_384" => CKM_HASH_ML_DSA_SHA3_384,
        "HASH_ML_DSA_SHA3_512" => CKM_HASH_ML_DSA_SHA3_512,
        "HASH_ML_DSA_SHAKE128" => CKM_HASH_ML_DSA_SHAKE128,
        "HASH_ML_DSA_SHAKE256" => CKM_HASH_ML_DSA_SHAKE256,
        "SLH_DSA_KEY_PAIR_GEN" => CKM_SLH_DSA_KEY_PAIR_GEN,
        "SLH_DSA" => CKM_SLH_DSA,
        "X9_42_DH_KEY_PAIR_GEN" => CKM_X9_42_DH_KEY_PAIR_GEN,
        "X9_42_DH_DERIVE" => CKM_X9_42_DH_DERIVE,
        "X9_42_DH_HYBRID_DERIVE" => CKM_X9_42_DH_HYBRID_DERIVE,
        "X9_42_MQV_DERIVE" => CKM_X9_42_MQV_DERIVE,
        "HASH_SLH_DSA" => CKM_HASH_SLH_DSA,
        "HASH_SLH_DSA_SHA224" => CKM_HASH_SLH_DSA_SHA224,
        "HASH_SLH_DSA_SHA256" => CKM_HASH_SLH_DSA_SHA256,
        "HASH_SLH_DSA_SHA384" => CKM_HASH_SLH_DSA_SHA384,
        "HASH_SLH_DSA_SHA512" => CKM_HASH_SLH_DSA_SHA512,
        "HASH_SLH_DSA_SHA3_224" => CKM_HASH_SLH_DSA_SHA3_224,
        "HASH_SLH_DSA_SHA3_256" => CKM_HASH_SLH_DSA_SHA3_256,
        "HASH_SLH_DSA_SHA3_384" => CKM_HASH_SLH_DSA_SHA3_384,
        "HASH_SLH_DSA_SHA3_512" => CKM_HASH_SLH_DSA_SHA3_512,
        "HASH_SLH_DSA_SHAKE128" => CKM_HASH_SLH_DSA_SHAKE128,
        "HASH_SLH_DSA_SHAKE256" => CKM_HASH_SLH_DSA_SHAKE256,
        "SHA256_RSA_PKCS" => CKM_SHA256_RSA_PKCS,
        "SHA384_RSA_PKCS" => CKM_SHA384_RSA_PKCS,
        "SHA512_RSA_PKCS" => CKM_SHA512_RSA_PKCS,
        "SHA256_RSA_PKCS_PSS" => CKM_SHA256_RSA_PKCS_PSS,
        "SHA384_RSA_PKCS_PSS" => CKM_SHA384_RSA_PKCS_PSS,
        "SHA512_RSA_PKCS_PSS" => CKM_SHA512_RSA_PKCS_PSS,
        "SHA224_RSA_PKCS" => CKM_SHA224_RSA_PKCS,
        "SHA224_RSA_PKCS_PSS" => CKM_SHA224_RSA_PKCS_PSS,
        "SHA512_224" => CKM_SHA512_224,
        "SHA512_224_HMAC" => CKM_SHA512_224_HMAC,
        "SHA512_224_HMAC_GENERAL" => CKM_SHA512_224_HMAC_GENERAL,
        "SHA512_224_KEY_DERIVATION" => CKM_SHA512_224_KEY_DERIVATION,
        "SHA512_256" => CKM_SHA512_256,
        "SHA512_256_HMAC" => CKM_SHA512_256_HMAC,
        "SHA512_256_HMAC_GENERAL" => CKM_SHA512_256_HMAC_GENERAL,
        "SHA512_256_KEY_DERIVATION" => CKM_SHA512_256_KEY_DERIVATION,
        "SHA512_T" => CKM_SHA512_T,
        "SHA512_T_HMAC" => CKM_SHA512_T_HMAC,
        "SHA512_T_HMAC_GENERAL" => CKM_SHA512_T_HMAC_GENERAL,
        "SHA512_T_KEY_DERIVATION" => CKM_SHA512_T_KEY_DERIVATION,
        "TLS12_EXTENDED_MASTER_KEY_DERIVE" => CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
        "TLS12_EXTENDED_MASTER_KEY_DERIVE_DH" => CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
        "SHA3_256_RSA_PKCS" => CKM_SHA3_256_RSA_PKCS,
        "SHA3_384_RSA_PKCS" => CKM_SHA3_384_RSA_PKCS,
        "SHA3_512_RSA_PKCS" => CKM_SHA3_512_RSA_PKCS,
        "SHA3_256_RSA_PKCS_PSS" => CKM_SHA3_256_RSA_PKCS_PSS,
        "SHA3_384_RSA_PKCS_PSS" => CKM_SHA3_384_RSA_PKCS_PSS,
        "SHA3_512_RSA_PKCS_PSS" => CKM_SHA3_512_RSA_PKCS_PSS,
        "SHA3_224_RSA_PKCS" => CKM_SHA3_224_RSA_PKCS,
        "SHA3_224_RSA_PKCS_PSS" => CKM_SHA3_224_RSA_PKCS_PSS,
        "RC2_KEY_GEN" => CKM_RC2_KEY_GEN,
        "RC2_ECB" => CKM_RC2_ECB,
        "RC2_CBC" => CKM_RC2_CBC,
        "RC2_MAC" => CKM_RC2_MAC,
        "RC2_MAC_GENERAL" => CKM_RC2_MAC_GENERAL,
        "RC2_CBC_PAD" => CKM_RC2_CBC_PAD,
        "RC4_KEY_GEN" => CKM_RC4_KEY_GEN,
        "RC4" => CKM_RC4,
        "DES_KEY_GEN" => CKM_DES_KEY_GEN,
        "DES_ECB" => CKM_DES_ECB,
        "DES_CBC" => CKM_DES_CBC,
        "DES_MAC" => CKM_DES_MAC,
        "DES_MAC_GENERAL" => CKM_DES_MAC_GENERAL,
        "DES_CBC_PAD" => CKM_DES_CBC_PAD,
        "DES2_KEY_GEN" => CKM_DES2_KEY_GEN,
        "DES3_KEY_GEN" => CKM_DES3_KEY_GEN,
        "DES3_ECB" => CKM_DES3_ECB,
        "DES3_CBC" => CKM_DES3_CBC,
        "DES3_MAC" => CKM_DES3_MAC,
        "DES3_MAC_GENERAL" => CKM_DES3_MAC_GENERAL,
        "DES3_CBC_PAD" => CKM_DES3_CBC_PAD,
        "DES3_CMAC_GENERAL" => CKM_DES3_CMAC_GENERAL,
        "DES3_CMAC" => CKM_DES3_CMAC,
        "CDMF_KEY_GEN" => CKM_CDMF_KEY_GEN,
        "CDMF_ECB" => CKM_CDMF_ECB,
        "CDMF_CBC" => CKM_CDMF_CBC,
        "CDMF_MAC" => CKM_CDMF_MAC,
        "CDMF_MAC_GENERAL" => CKM_CDMF_MAC_GENERAL,
        "CDMF_CBC_PAD" => CKM_CDMF_CBC_PAD,
        "DES_OFB64" => CKM_DES_OFB64,
        "DES_OFB8" => CKM_DES_OFB8,
        "DES_CFB64" => CKM_DES_CFB64,
        "DES_CFB8" => CKM_DES_CFB8,
        "MD2" => CKM_MD2,
        "MD2_HMAC" => CKM_MD2_HMAC,
        "MD2_HMAC_GENERAL" => CKM_MD2_HMAC_GENERAL,
        "MD5" => CKM_MD5,
        "MD5_HMAC" => CKM_MD5_HMAC,
        "MD5_HMAC_GENERAL" => CKM_MD5_HMAC_GENERAL,
        "SHA_1" => CKM_SHA_1,
        "SHA_1_HMAC" => CKM_SHA_1_HMAC,
        "SHA_1_HMAC_GENERAL" => CKM_SHA_1_HMAC_GENERAL,
        "RIPEMD128" => CKM_RIPEMD128,
        "RIPEMD128_HMAC" => CKM_RIPEMD128_HMAC,
        "RIPEMD128_HMAC_GENERAL" => CKM_RIPEMD128_HMAC_GENERAL,
        "RIPEMD160" => CKM_RIPEMD160,
        "RIPEMD160_HMAC" => CKM_RIPEMD160_HMAC,
        "RIPEMD160_HMAC_GENERAL" => CKM_RIPEMD160_HMAC_GENERAL,
        "SHA256" => CKM_SHA256,
        "SHA256_HMAC" => CKM_SHA256_HMAC,
        "SHA256_HMAC_GENERAL" => CKM_SHA256_HMAC_GENERAL,
        "SHA224" => CKM_SHA224,
        "SHA224_HMAC" => CKM_SHA224_HMAC,
        "SHA224_HMAC_GENERAL" => CKM_SHA224_HMAC_GENERAL,
        "SHA384" => CKM_SHA384,
        "SHA384_HMAC" => CKM_SHA384_HMAC,
        "SHA384_HMAC_GENERAL" => CKM_SHA384_HMAC_GENERAL,
        "SHA512" => CKM_SHA512,
        "SHA512_HMAC" => CKM_SHA512_HMAC,
        "SHA512_HMAC_GENERAL" => CKM_SHA512_HMAC_GENERAL,
        "SECURID_KEY_GEN" => CKM_SECURID_KEY_GEN,
        "SECURID" => CKM_SECURID,
        "HOTP_KEY_GEN" => CKM_HOTP_KEY_GEN,
        "HOTP" => CKM_HOTP,
        "ACTI" => CKM_ACTI,
        "ACTI_KEY_GEN" => CKM_ACTI_KEY_GEN,
        "SHA3_256" => CKM_SHA3_256,
        "SHA3_256_HMAC" => CKM_SHA3_256_HMAC,
        "SHA3_256_HMAC_GENERAL" => CKM_SHA3_256_HMAC_GENERAL,
        "SHA3_256_KEY_GEN" => CKM_SHA3_256_KEY_GEN,
        "SHA3_224" => CKM_SHA3_224,
        "SHA3_224_HMAC" => CKM_SHA3_224_HMAC,
        "SHA3_224_HMAC_GENERAL" => CKM_SHA3_224_HMAC_GENERAL,
        "SHA3_224_KEY_GEN" => CKM_SHA3_224_KEY_GEN,
        "SHA3_384" => CKM_SHA3_384,
        "SHA3_384_HMAC" => CKM_SHA3_384_HMAC,
        "SHA3_384_HMAC_GENERAL" => CKM_SHA3_384_HMAC_GENERAL,
        "SHA3_384_KEY_GEN" => CKM_SHA3_384_KEY_GEN,
        "SHA3_512" => CKM_SHA3_512,
        "SHA3_512_HMAC" => CKM_SHA3_512_HMAC,
        "SHA3_512_HMAC_GENERAL" => CKM_SHA3_512_HMAC_GENERAL,
        "SHA3_512_KEY_GEN" => CKM_SHA3_512_KEY_GEN,
        "CAST_KEY_GEN" => CKM_CAST_KEY_GEN,
        "CAST_ECB" => CKM_CAST_ECB,
        "CAST_CBC" => CKM_CAST_CBC,
        "CAST_MAC" => CKM_CAST_MAC,
        "CAST_MAC_GENERAL" => CKM_CAST_MAC_GENERAL,
        "CAST_CBC_PAD" => CKM_CAST_CBC_PAD,
        "CAST3_KEY_GEN" => CKM_CAST3_KEY_GEN,
        "CAST3_ECB" => CKM_CAST3_ECB,
        "CAST3_CBC" => CKM_CAST3_CBC,
        "CAST3_MAC" => CKM_CAST3_MAC,
        "CAST3_MAC_GENERAL" => CKM_CAST3_MAC_GENERAL,
        "CAST3_CBC_PAD" => CKM_CAST3_CBC_PAD,
        "CAST128_KEY_GEN" => CKM_CAST128_KEY_GEN,
        "CAST128_ECB" => CKM_CAST128_ECB,
        "CAST128_MAC" => CKM_CAST128_MAC,
        "CAST128_CBC" => CKM_CAST128_CBC,
        "CAST128_MAC_GENERAL" => CKM_CAST128_MAC_GENERAL,
        "CAST128_CBC_PAD" => CKM_CAST128_CBC_PAD,
        "RC5_KEY_GEN" => CKM_RC5_KEY_GEN,
        "RC5_ECB" => CKM_RC5_ECB,
        "RC5_CBC" => CKM_RC5_CBC,
        "RC5_MAC" => CKM_RC5_MAC,
        "RC5_MAC_GENERAL" => CKM_RC5_MAC_GENERAL,
        "RC5_CBC_PAD" => CKM_RC5_CBC_PAD,
        "IDEA_KEY_GEN" => CKM_IDEA_KEY_GEN,
        "IDEA_ECB" => CKM_IDEA_ECB,
        "IDEA_CBC" => CKM_IDEA_CBC,
        "IDEA_MAC" => CKM_IDEA_MAC,
        "IDEA_MAC_GENERAL" => CKM_IDEA_MAC_GENERAL,
        "IDEA_CBC_PAD" => CKM_IDEA_CBC_PAD,
        "GENERIC_SECRET_KEY_GEN" => CKM_GENERIC_SECRET_KEY_GEN,
        "CONCATENATE_BASE_AND_KEY" => CKM_CONCATENATE_BASE_AND_KEY,
        "CONCATENATE_BASE_AND_DATA" => CKM_CONCATENATE_BASE_AND_DATA,
        "CONCATENATE_DATA_AND_BASE" => CKM_CONCATENATE_DATA_AND_BASE,
        "XOR_BASE_AND_DATA" => CKM_XOR_BASE_AND_DATA,
        "EXTRACT_KEY_FROM_KEY" => CKM_EXTRACT_KEY_FROM_KEY,
        "SSL3_PRE_MASTER_KEY_GEN" => CKM_SSL3_PRE_MASTER_KEY_GEN,
        "SSL3_MASTER_KEY_DERIVE" => CKM_SSL3_MASTER_KEY_DERIVE,
        "SSL3_KEY_AND_MAC_DERIVE" => CKM_SSL3_KEY_AND_MAC_DERIVE,
        "SSL3_MASTER_KEY_DERIVE_DH" => CKM_SSL3_MASTER_KEY_DERIVE_DH,
        "TLS_PRE_MASTER_KEY_GEN" => CKM_TLS_PRE_MASTER_KEY_GEN,
        "TLS_MASTER_KEY_DERIVE" => CKM_TLS_MASTER_KEY_DERIVE,
        "TLS_KEY_AND_MAC_DERIVE" => CKM_TLS_KEY_AND_MAC_DERIVE,
        "TLS_MASTER_KEY_DERIVE_DH" => CKM_TLS_MASTER_KEY_DERIVE_DH,
        "TLS_PRF" => CKM_TLS_PRF,
        "SSL3_MD5_MAC" => CKM_SSL3_MD5_MAC,
        "SSL3_SHA1_MAC" => CKM_SSL3_SHA1_MAC,
        "MD5_KEY_DERIVATION" => CKM_MD5_KEY_DERIVATION,
        "MD2_KEY_DERIVATION" => CKM_MD2_KEY_DERIVATION,
        "SHA1_KEY_DERIVATION" => CKM_SHA1_KEY_DERIVATION,
        "SHA256_KEY_DERIVATION" => CKM_SHA256_KEY_DERIVATION,
        "SHA384_KEY_DERIVATION" => CKM_SHA384_KEY_DERIVATION,
        "SHA512_KEY_DERIVATION" => CKM_SHA512_KEY_DERIVATION,
        "SHA224_KEY_DERIVATION" => CKM_SHA224_KEY_DERIVATION,
        "SHA3_256_KEY_DERIVATION" => CKM_SHA3_256_KEY_DERIVATION,
        "SHA3_256_KEY_DERIVE" => CKM_SHA3_256_KEY_DERIVE,
        "SHA3_224_KEY_DERIVATION" => CKM_SHA3_224_KEY_DERIVATION,
        "SHA3_224_KEY_DERIVE" => CKM_SHA3_224_KEY_DERIVE,
        "SHA3_384_KEY_DERIVATION" => CKM_SHA3_384_KEY_DERIVATION,
        "SHA3_384_KEY_DERIVE" => CKM_SHA3_384_KEY_DERIVE,
        "SHA3_512_KEY_DERIVATION" => CKM_SHA3_512_KEY_DERIVATION,
        "SHA3_512_KEY_DERIVE" => CKM_SHA3_512_KEY_DERIVE,
        "SHAKE_128_KEY_DERIVATION" => CKM_SHAKE_128_KEY_DERIVATION,
        "SHAKE_128_KEY_DERIVE" => CKM_SHAKE_128_KEY_DERIVE,
        "SHAKE_256_KEY_DERIVATION" => CKM_SHAKE_256_KEY_DERIVATION,
        "SHAKE_256_KEY_DERIVE" => CKM_SHAKE_256_KEY_DERIVE,
        "PBE_MD2_DES_CBC" => CKM_PBE_MD2_DES_CBC,
        "PBE_MD5_DES_CBC" => CKM_PBE_MD5_DES_CBC,
        "PBE_MD5_CAST_CBC" => CKM_PBE_MD5_CAST_CBC,
        "PBE_MD5_CAST3_CBC" => CKM_PBE_MD5_CAST3_CBC,
        "PBE_MD5_CAST128_CBC" => CKM_PBE_MD5_CAST128_CBC,
        "PBE_SHA1_CAST128_CBC" => CKM_PBE_SHA1_CAST128_CBC,
        "PBE_SHA1_RC4_128" => CKM_PBE_SHA1_RC4_128,
        "PBE_SHA1_RC4_40" => CKM_PBE_SHA1_RC4_40,
        "PBE_SHA1_DES3_EDE_CBC" => CKM_PBE_SHA1_DES3_EDE_CBC,
        "PBE_SHA1_DES2_EDE_CBC" => CKM_PBE_SHA1_DES2_EDE_CBC,
        "PBE_SHA1_RC2_128_CBC" => CKM_PBE_SHA1_RC2_128_CBC,
        "PBE_SHA1_RC2_40_CBC" => CKM_PBE_SHA1_RC2_40_CBC,
        "PKCS5_PBKD2" => CKM_PKCS5_PBKD2,
        "PBA_SHA1_WITH_SHA1_HMAC" => CKM_PBA_SHA1_WITH_SHA1_HMAC,
        "WTLS_PRE_MASTER_KEY_GEN" => CKM_WTLS_PRE_MASTER_KEY_GEN,
        "WTLS_MASTER_KEY_DERIVE" => CKM_WTLS_MASTER_KEY_DERIVE,
        "WTLS_MASTER_KEY_DERIVE_DH_ECC" => CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
        "WTLS_PRF" => CKM_WTLS_PRF,
        "WTLS_SERVER_KEY_AND_MAC_DERIVE" => CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
        "WTLS_CLIENT_KEY_AND_MAC_DERIVE" => CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
        "TLS10_MAC_SERVER" => CKM_TLS10_MAC_SERVER,
        "TLS10_MAC_CLIENT" => CKM_TLS10_MAC_CLIENT,
        "TLS12_MAC" => CKM_TLS12_MAC,
        "TLS12_KDF" => CKM_TLS12_KDF,
        "TLS12_MASTER_KEY_DERIVE" => CKM_TLS12_MASTER_KEY_DERIVE,
        "TLS12_KEY_AND_MAC_DERIVE" => CKM_TLS12_KEY_AND_MAC_DERIVE,
        "TLS12_MASTER_KEY_DERIVE_DH" => CKM_TLS12_MASTER_KEY_DERIVE_DH,
        "TLS12_KEY_SAFE_DERIVE" => CKM_TLS12_KEY_SAFE_DERIVE,
        "TLS_MAC" => CKM_TLS_MAC,
        "TLS_KDF" => CKM_TLS_KDF,
        "KEY_WRAP_LYNKS" => CKM_KEY_WRAP_LYNKS,
        "KEY_WRAP_SET_OAEP" => CKM_KEY_WRAP_SET_OAEP,
        "CMS_SIG" => CKM_CMS_SIG,
        "KIP_DERIVE" => CKM_KIP_DERIVE,
        "KIP_WRAP" => CKM_KIP_WRAP,
        "KIP_MAC" => CKM_KIP_MAC,
        "CAMELLIA_KEY_GEN" => CKM_CAMELLIA_KEY_GEN,
        "CAMELLIA_ECB" => CKM_CAMELLIA_ECB,
        "CAMELLIA_CBC" => CKM_CAMELLIA_CBC,
        "CAMELLIA_MAC" => CKM_CAMELLIA_MAC,
        "CAMELLIA_MAC_GENERAL" => CKM_CAMELLIA_MAC_GENERAL,
        "CAMELLIA_CBC_PAD" => CKM_CAMELLIA_CBC_PAD,
        "CAMELLIA_ECB_ENCRYPT_DATA" => CKM_CAMELLIA_ECB_ENCRYPT_DATA,
        "CAMELLIA_CBC_ENCRYPT_DATA" => CKM_CAMELLIA_CBC_ENCRYPT_DATA,
        "CAMELLIA_CTR" => CKM_CAMELLIA_CTR,
        "ARIA_KEY_GEN" => CKM_ARIA_KEY_GEN,
        "ARIA_ECB" => CKM_ARIA_ECB,
        "ARIA_CBC" => CKM_ARIA_CBC,
        "ARIA_MAC" => CKM_ARIA_MAC,
        "ARIA_MAC_GENERAL" => CKM_ARIA_MAC_GENERAL,
        "ARIA_CBC_PAD" => CKM_ARIA_CBC_PAD,
        "ARIA_ECB_ENCRYPT_DATA" => CKM_ARIA_ECB_ENCRYPT_DATA,
        "ARIA_CBC_ENCRYPT_DATA" => CKM_ARIA_CBC_ENCRYPT_DATA,
        "SEED_KEY_GEN" => CKM_SEED_KEY_GEN,
        "SEED_ECB" => CKM_SEED_ECB,
        "SEED_CBC" => CKM_SEED_CBC,
        "SEED_MAC" => CKM_SEED_MAC,
        "SEED_MAC_GENERAL" => CKM_SEED_MAC_GENERAL,
        "SEED_CBC_PAD" => CKM_SEED_CBC_PAD,
        "SEED_ECB_ENCRYPT_DATA" => CKM_SEED_ECB_ENCRYPT_DATA,
        "SEED_CBC_ENCRYPT_DATA" => CKM_SEED_CBC_ENCRYPT_DATA,
        "SKIPJACK_KEY_GEN" => CKM_SKIPJACK_KEY_GEN,
        "SKIPJACK_ECB64" => CKM_SKIPJACK_ECB64,
        "SKIPJACK_CBC64" => CKM_SKIPJACK_CBC64,
        "SKIPJACK_OFB64" => CKM_SKIPJACK_OFB64,
        "SKIPJACK_CFB64" => CKM_SKIPJACK_CFB64,
        "SKIPJACK_CFB32" => CKM_SKIPJACK_CFB32,
        "SKIPJACK_CFB16" => CKM_SKIPJACK_CFB16,
        "SKIPJACK_CFB8" => CKM_SKIPJACK_CFB8,
        "SKIPJACK_WRAP" => CKM_SKIPJACK_WRAP,
        "SKIPJACK_PRIVATE_WRAP" => CKM_SKIPJACK_PRIVATE_WRAP,
        "SKIPJACK_RELAYX" => CKM_SKIPJACK_RELAYX,
        "KEA_KEY_PAIR_GEN" => CKM_KEA_KEY_PAIR_GEN,
        "KEA_KEY_DERIVE" => CKM_KEA_KEY_DERIVE,
        "KEA_DERIVE" => CKM_KEA_DERIVE,
        "FORTEZZA_TIMESTAMP" => CKM_FORTEZZA_TIMESTAMP,
        "BATON_KEY_GEN" => CKM_BATON_KEY_GEN,
        "BATON_ECB128" => CKM_BATON_ECB128,
        "BATON_ECB96" => CKM_BATON_ECB96,
        "BATON_CBC128" => CKM_BATON_CBC128,
        "BATON_COUNTER" => CKM_BATON_COUNTER,
        "BATON_SHUFFLE" => CKM_BATON_SHUFFLE,
        "BATON_WRAP" => CKM_BATON_WRAP,
        "EC_KEY_PAIR_GEN" => CKM_EC_KEY_PAIR_GEN,
        "ECDSA" => CKM_ECDSA,
        "ECDSA_SHA1" => CKM_ECDSA_SHA1,
        "ECDSA_SHA224" => CKM_ECDSA_SHA224,
        "ECDSA_SHA256" => CKM_ECDSA_SHA256,
        "ECDSA_SHA384" => CKM_ECDSA_SHA384,
        "ECDSA_SHA512" => CKM_ECDSA_SHA512,
        "EC_KEY_PAIR_GEN_W_EXTRA_BITS" => CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS,
        "ECDH1_DERIVE" => CKM_ECDH1_DERIVE,
        "ECDH1_COFACTOR_DERIVE" => CKM_ECDH1_COFACTOR_DERIVE,
        "ECMQV_DERIVE" => CKM_ECMQV_DERIVE,
        "ECDH_AES_KEY_WRAP" => CKM_ECDH_AES_KEY_WRAP,
        "RSA_AES_KEY_WRAP" => CKM_RSA_AES_KEY_WRAP,
        "JUNIPER_KEY_GEN" => CKM_JUNIPER_KEY_GEN,
        "JUNIPER_ECB128" => CKM_JUNIPER_ECB128,
        "JUNIPER_CBC128" => CKM_JUNIPER_CBC128,
        "JUNIPER_COUNTER" => CKM_JUNIPER_COUNTER,
        "JUNIPER_SHUFFLE" => CKM_JUNIPER_SHUFFLE,
        "JUNIPER_WRAP" => CKM_JUNIPER_WRAP,
        "FASTHASH" => CKM_FASTHASH,
        "AES_XTS" => CKM_AES_XTS,
        "AES_XTS_KEY_GEN" => CKM_AES_XTS_KEY_GEN,
        "AES_KEY_GEN" => CKM_AES_KEY_GEN,
        "AES_ECB" => CKM_AES_ECB,
        "AES_CBC" => CKM_AES_CBC,
        "AES_MAC" => CKM_AES_MAC,
        "AES_MAC_GENERAL" => CKM_AES_MAC_GENERAL,
        "AES_CBC_PAD" => CKM_AES_CBC_PAD,
        "AES_CTR" => CKM_AES_CTR,
        "AES_GCM" => CKM_AES_GCM,
        "AES_CCM" => CKM_AES_CCM,
        "AES_CTS" => CKM_AES_CTS,
        "AES_CMAC" => CKM_AES_CMAC,
        "AES_CMAC_GENERAL" => CKM_AES_CMAC_GENERAL,
        "AES_XCBC_MAC" => CKM_AES_XCBC_MAC,
        "AES_XCBC_MAC_96" => CKM_AES_XCBC_MAC_96,
        "AES_GMAC" => CKM_AES_GMAC,
        "BLOWFISH_KEY_GEN" => CKM_BLOWFISH_KEY_GEN,
        "BLOWFISH_CBC" => CKM_BLOWFISH_CBC,
        "TWOFISH_KEY_GEN" => CKM_TWOFISH_KEY_GEN,
        "TWOFISH_CBC" => CKM_TWOFISH_CBC,
        "BLOWFISH_CBC_PAD" => CKM_BLOWFISH_CBC_PAD,
        "TWOFISH_CBC_PAD" => CKM_TWOFISH_CBC_PAD,
        "DES_ECB_ENCRYPT_DATA" => CKM_DES_ECB_ENCRYPT_DATA,
        "DES_CBC_ENCRYPT_DATA" => CKM_DES_CBC_ENCRYPT_DATA,
        "DES3_ECB_ENCRYPT_DATA" => CKM_DES3_ECB_ENCRYPT_DATA,
        "DES3_CBC_ENCRYPT_DATA" => CKM_DES3_CBC_ENCRYPT_DATA,
        "AES_ECB_ENCRYPT_DATA" => CKM_AES_ECB_ENCRYPT_DATA,
        "AES_CBC_ENCRYPT_DATA" => CKM_AES_CBC_ENCRYPT_DATA,
        "GOSTR3410_KEY_PAIR_GEN" => CKM_GOSTR3410_KEY_PAIR_GEN,
        "GOSTR3410" => CKM_GOSTR3410,
        "GOSTR3410_WITH_GOSTR3411" => CKM_GOSTR3410_WITH_GOSTR3411,
        "GOSTR3410_KEY_WRAP" => CKM_GOSTR3410_KEY_WRAP,
        "GOSTR3410_DERIVE" => CKM_GOSTR3410_DERIVE,
        "GOSTR3411" => CKM_GOSTR3411,
        "GOSTR3411_HMAC" => CKM_GOSTR3411_HMAC,
        "GOST28147_KEY_GEN" => CKM_GOST28147_KEY_GEN,
        "GOST28147_ECB" => CKM_GOST28147_ECB,
        "GOST28147" => CKM_GOST28147,
        "GOST28147_MAC" => CKM_GOST28147_MAC,
        "GOST28147_KEY_WRAP" => CKM_GOST28147_KEY_WRAP,
        "CHACHA20_KEY_GEN" => CKM_CHACHA20_KEY_GEN,
        "CHACHA20" => CKM_CHACHA20,
        "POLY1305_KEY_GEN" => CKM_POLY1305_KEY_GEN,
        "POLY1305" => CKM_POLY1305,
        "DSA_PARAMETER_GEN" => CKM_DSA_PARAMETER_GEN,
        "DH_PKCS_PARAMETER_GEN" => CKM_DH_PKCS_PARAMETER_GEN,
        "X9_42_DH_PARAMETER_GEN" => CKM_X9_42_DH_PARAMETER_GEN,
        "DSA_PROBABILISTIC_PARAMETER_GEN" => CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
        "DSA_SHAWE_TAYLOR_PARAMETER_GEN" => CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
        "DSA_FIPS_G_GEN" => CKM_DSA_FIPS_G_GEN,
        "AES_OFB" => CKM_AES_OFB,
        "AES_CFB64" => CKM_AES_CFB64,
        "AES_CFB8" => CKM_AES_CFB8,
        "AES_CFB128" => CKM_AES_CFB128,
        "AES_CFB1" => CKM_AES_CFB1,
        "AES_KEY_WRAP" => CKM_AES_KEY_WRAP,
        "AES_KEY_WRAP_PAD" => CKM_AES_KEY_WRAP_PAD,
        "AES_KEY_WRAP_KWP" => CKM_AES_KEY_WRAP_KWP,
        "AES_KEY_WRAP_PKCS7" => CKM_AES_KEY_WRAP_PKCS7,
        "RSA_PKCS_TPM_1_1" => CKM_RSA_PKCS_TPM_1_1,
        "RSA_PKCS_OAEP_TPM_1_1" => CKM_RSA_PKCS_OAEP_TPM_1_1,
        "SHA_1_KEY_GEN" => CKM_SHA_1_KEY_GEN,
        "SHA224_KEY_GEN" => CKM_SHA224_KEY_GEN,
        "SHA256_KEY_GEN" => CKM_SHA256_KEY_GEN,
        "SHA384_KEY_GEN" => CKM_SHA384_KEY_GEN,
        "SHA512_KEY_GEN" => CKM_SHA512_KEY_GEN,
        "SHA512_224_KEY_GEN" => CKM_SHA512_224_KEY_GEN,
        "SHA512_256_KEY_GEN" => CKM_SHA512_256_KEY_GEN,
        "SHA512_T_KEY_GEN" => CKM_SHA512_T_KEY_GEN,
        "NULL" => CKM_NULL,
        "BLAKE2B_160" => CKM_BLAKE2B_160,
        "BLAKE2B_160_HMAC" => CKM_BLAKE2B_160_HMAC,
        "BLAKE2B_160_HMAC_GENERAL" => CKM_BLAKE2B_160_HMAC_GENERAL,
        "BLAKE2B_160_KEY_DERIVE" => CKM_BLAKE2B_160_KEY_DERIVE,
        "BLAKE2B_160_KEY_GEN" => CKM_BLAKE2B_160_KEY_GEN,
        "BLAKE2B_256" => CKM_BLAKE2B_256,
        "BLAKE2B_256_HMAC" => CKM_BLAKE2B_256_HMAC,
        "BLAKE2B_256_HMAC_GENERAL" => CKM_BLAKE2B_256_HMAC_GENERAL,
        "BLAKE2B_256_KEY_DERIVE" => CKM_BLAKE2B_256_KEY_DERIVE,
        "BLAKE2B_256_KEY_GEN" => CKM_BLAKE2B_256_KEY_GEN,
        "BLAKE2B_384" => CKM_BLAKE2B_384,
        "BLAKE2B_384_HMAC" => CKM_BLAKE2B_384_HMAC,
        "BLAKE2B_384_HMAC_GENERAL" => CKM_BLAKE2B_384_HMAC_GENERAL,
        "BLAKE2B_384_KEY_DERIVE" => CKM_BLAKE2B_384_KEY_DERIVE,
        "BLAKE2B_384_KEY_GEN" => CKM_BLAKE2B_384_KEY_GEN,
        "BLAKE2B_512" => CKM_BLAKE2B_512,
        "BLAKE2B_512_HMAC" => CKM_BLAKE2B_512_HMAC,
        "BLAKE2B_512_HMAC_GENERAL" => CKM_BLAKE2B_512_HMAC_GENERAL,
        "BLAKE2B_512_KEY_DERIVE" => CKM_BLAKE2B_512_KEY_DERIVE,
        "BLAKE2B_512_KEY_GEN" => CKM_BLAKE2B_512_KEY_GEN,
        "SALSA20" => CKM_SALSA20,
        "CHACHA20_POLY1305" => CKM_CHACHA20_POLY1305,
        "SALSA20_POLY1305" => CKM_SALSA20_POLY1305,
        "X3DH_INITIALIZE" => CKM_X3DH_INITIALIZE,
        "X3DH_RESPOND" => CKM_X3DH_RESPOND,
        "X2RATCHET_INITIALIZE" => CKM_X2RATCHET_INITIALIZE,
        "X2RATCHET_RESPOND" => CKM_X2RATCHET_RESPOND,
        "X2RATCHET_ENCRYPT" => CKM_X2RATCHET_ENCRYPT,
        "X2RATCHET_DECRYPT" => CKM_X2RATCHET_DECRYPT,
        "XEDDSA" => CKM_XEDDSA,
        "HKDF_DERIVE" => CKM_HKDF_DERIVE,
        "HKDF_DATA" => CKM_HKDF_DATA,
        "HKDF_KEY_GEN" => CKM_HKDF_KEY_GEN,
        "SALSA20_KEY_GEN" => CKM_SALSA20_KEY_GEN,
        "ECDSA_SHA3_224" => CKM_ECDSA_SHA3_224,
        "ECDSA_SHA3_256" => CKM_ECDSA_SHA3_256,
        "ECDSA_SHA3_384" => CKM_ECDSA_SHA3_384,
        "ECDSA_SHA3_512" => CKM_ECDSA_SHA3_512,
        "EC_EDWARDS_KEY_PAIR_GEN" => CKM_EC_EDWARDS_KEY_PAIR_GEN,
        "EC_MONTGOMERY_KEY_PAIR_GEN" => CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        "EDDSA" => CKM_EDDSA,
        "SP800_108_COUNTER_KDF" => CKM_SP800_108_COUNTER_KDF,
        "SP800_108_FEEDBACK_KDF" => CKM_SP800_108_FEEDBACK_KDF,
        "SP800_108_DOUBLE_PIPELINE_KDF" => CKM_SP800_108_DOUBLE_PIPELINE_KDF,
        "IKE2_PRF_PLUS_DERIVE" => CKM_IKE2_PRF_PLUS_DERIVE,
        "IKE_PRF_DERIVE" => CKM_IKE_PRF_DERIVE,
        "IKE1_PRF_DERIVE" => CKM_IKE1_PRF_DERIVE,
        "IKE1_EXTENDED_DERIVE" => CKM_IKE1_EXTENDED_DERIVE,
        "HSS_KEY_PAIR_GEN" => CKM_HSS_KEY_PAIR_GEN,
        "HSS" => CKM_HSS,
        "XMSS_KEY_PAIR_GEN" => CKM_XMSS_KEY_PAIR_GEN,
        "XMSSMT_KEY_PAIR_GEN" => CKM_XMSSMT_KEY_PAIR_GEN,
        "XMSS" => CKM_XMSS,
        "XMSSMT" => CKM_XMSSMT,
        "ECDH_X_AES_KEY_WRAP" => CKM_ECDH_X_AES_KEY_WRAP,
        "ECDH_COF_AES_KEY_WRAP" => CKM_ECDH_COF_AES_KEY_WRAP,
        "PUB_KEY_FROM_PRIV_KEY" => CKM_PUB_KEY_FROM_PRIV_KEY,
        "VENDOR_DEFINED" => CKM_VENDOR_DEFINED,
        "CAST5_KEY_GEN" => CKM_CAST5_KEY_GEN,
        "CAST5_ECB" => CKM_CAST5_ECB,
        "CAST5_CBC" => CKM_CAST5_CBC,
        "CAST5_MAC" => CKM_CAST5_MAC,
        "CAST5_MAC_GENERAL" => CKM_CAST5_MAC_GENERAL,
        "CAST5_CBC_PAD" => CKM_CAST5_CBC_PAD,
        "PBE_MD5_CAST5_CBC" => CKM_PBE_MD5_CAST5_CBC,
        "PBE_SHA1_CAST5_CBC" => CKM_PBE_SHA1_CAST5_CBC,
        "ECDSA_KEY_PAIR_GEN" => CKM_ECDSA_KEY_PAIR_GEN,
        "DSA_PROBABLISTIC_PARAMETER_GEN" => CKM_DSA_PROBABLISTIC_PARAMETER_GEN,
        unknown => return Err(format!("Unknown Mechanism.Type {}", unknown).into()),
    };

    Ok(typ)
}

pub fn parse_mechanism(
    mechanism: &parser::Mechanism,
) -> Result<(CK_MECHANISM, NativeValue), Box<dyn std::error::Error>> {
    let mech_type = parse_mechanism_type(&mechanism.typ.value)?;
    if let Some(parameter) = &mechanism.parameter {
        let param_len = parse_numeric::<CK_ULONG>(&parameter.length)?;

        if param_len > 0 {
            return Err("Parameter.length > 0 not supported".into());
        }
    }

    let ck_mechanism = CK_MECHANISM {
        mechanism: mech_type,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    Ok((ck_mechanism, NativeValue::Bytes(Vec::new())))
}

fn insert_variable<'a, T>(
    key: &'a str,
    value: T,
    variables: &'a mut HashMap<String, Box<dyn Any>>
) -> Result<(), (&'a str, T)>
where 
    T: Any + 'static
{
    if key.starts_with('$') {
        // this is a variable
        variables.insert(key.into(), Box::new(value));
        Ok(())
    } else {
        Err((key, value))
    }
}

/*
fn remove_variable<T: 'static>(
    key: &str,
    variables: &mut HashMap<String, Box<dyn Any>>
) -> Result<T, ()> {
    if key.starts_with('$') {
        variables.remove(key)
            .and_then(|b| b.downcast::<T>().ok())
            .map(|b| *b)
            .ok_or(())
    } else {
        Err(())
    }
}
*/

fn extract_env_var(key: &str) -> Option<String> {
    key.strip_prefix("${")
       .and_then(|k| k.strip_suffix('}'))
       .and_then(|var_name| std::env::var(var_name).ok())
}

fn get_variable<'a, T: Any>(
    key: &str,
    variables: &'a HashMap<String, Box<dyn Any>>
) -> Result<&'a T, ()> {
    if key.starts_with('$') {
        variables.get(key)
            .and_then(|v| v.downcast_ref::<T>())
            .ok_or(())
    } else {
        Err(())
    }
}

fn get_numeric<T: Num>(
    key: &str,
    variables: &HashMap<String, Box<dyn Any>>
) -> Result<T, ()>
where
    T: Clone + 'static
{
    if let Ok(v) = get_variable::<T>(key, variables) {
        return Ok(v.clone());
    }

    // Sicherer Auszug aus der Umgebungsvariable
    if let Some(val) = extract_env_var(key) {
        if let Ok(parsed) = parse_numeric::<T>(&val) {
            return Ok(parsed);
        }
    }
    Err(())
}

/*
fn get_binary(
    key: &str,
    variables: &HashMap<String, Box<dyn Any>>
) -> Result<Vec<u8>, ()> {
    if let Ok(v) = get_variable::<Vec<u8>>(key, variables) {
        return Ok(v.clone());
    } else {
        if key.starts_with('$') {
            // check environment
            let var_name = &key[2..key.len() - 1];
            if let Ok(val) = std::env::var(var_name) {
                if let Ok(parsed) = parse_binary(&val) {
                    return Ok(parsed);
                }
            }
        }
    }
    Err(())
}
*/

fn get_text(
    key: &str,
    variables: &HashMap<String, Box<dyn Any>>
) -> Result<String, ()> {
    if let Ok(v) = get_variable::<String>(key, variables) {
        return Ok(v.clone());
    }

    if let Some(val) = extract_env_var(key) {
        return Ok(val);
    }
    Err(())
}

fn fetch_text(
    text: &str,
    variables: &mut HashMap<String, Box<dyn Any>>
) -> Result<String, ()> {
    get_text(text, variables)
        .or_else(|_| Ok(text.to_string()))
}

fn fetch_numeric<T>(
    numeric: &str,
    variables: &mut HashMap<String, Box<dyn Any>>
) -> Result<T, Box<dyn std::error::Error>>
where
    T: Num + Any + Clone + 'static,
    T::FromStrRadixErr: std::fmt::Display + 'static,
{
    if numeric.starts_with("$") {
        get_numeric::<T>(numeric, variables)
            .map_err(|_| format!("Variable '{:#?} not found", numeric).into())
    } else {
        parse_numeric::<T>(numeric)
            .map_err(|e| format!("{e}").into())
    }
}

/*
fn fetch_binary(
    binary: &str,
    variables: &mut HashMap<String, Box<dyn Any>>
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if binary.starts_with("$") {
        get_binary(binary, variables)
            .map_err(|_| format!("Variable '{:#?}' not found", binary).into())
    } else {
        parse_binary(binary)
            .map_err(|e| format!("{e}").into())
    }
}
*/

fn match_boolean(
    expected: &str,
    result: CK_BBOOL,
    variables: &mut HashMap<String, Box<dyn Any>>
) -> Result<(), Box<dyn std::error::Error>>
{
    let (expected, result) = match insert_variable(expected, result, variables) {
        Ok(_) => return Ok(()),
        Err((n, e)) => (n, e),
    };

    let e = parse_boolean(expected)?;

    if e == result {
        Ok(())
    } else {
        Err(format!("Expected {}, got {}", e, result).into())
    }
}

fn match_limit(
    expected: &str,
    result: CK_ULONG,
    variables: &mut HashMap<String, Box<dyn Any>>
) -> Result<(), Box<dyn std::error::Error>>
{
    let (expected, result) = match insert_variable(expected, result, variables) {
        Ok(_) => return Ok(()),
        Err((n, e)) => (n, e),
    };

    let e = parse_limit(expected)?;

    if e == result {
        Ok(())
    } else {
        Err(format!("Expected {}, got {}", e, result).into())
    }
}

fn match_numeric<T>(
    expected: &str,
    result: T,
    variables: &mut HashMap<String, Box<dyn Any>>
) -> Result<(), Box<dyn std::error::Error>>
where
    T: Num + PartialEq + Copy + std::fmt::Display + 'static,
    T::FromStrRadixErr: std::error::Error + Send + Sync,
{
    let (expected, result) = match insert_variable(expected, result, variables) {
        Ok(_) => return Ok(()),
        Err((n, e)) => (n, e),
    };

    let e = parse_numeric::<T>(expected)?;

    if e == result {
        Ok(())
    } else {
        Err(format!("Expected {}, got {}", e, result).into())
    }
}

fn match_binary(
    expected: &str,
    result: Vec<u8>,
    variables: &mut HashMap<String, Box<dyn Any>>
) -> Result<(), Box<dyn std::error::Error>> {
    let (expected, result) = match insert_variable(expected, result, variables) {
        Ok(_) => return Ok(()),
        Err((n, e)) => (n, e),
    };

    let e_bytes = parse_binary(expected)?;

    if e_bytes == result {
        Ok(())
    } else {
        Err(format!("Expected {} bytes, got {} bytes (binary mismatch)", e_bytes.len(), result.len()).into())
    }
}

fn match_text(
    expected: &str,
    result: &[u8],
    variables: &mut HashMap<String, Box<dyn Any>>
) -> Result<(), Box<dyn std::error::Error>> {
    let r = String::from_utf8_lossy(result).into_owned();

    let (expected_str, actual_str) = match insert_variable(expected, r, variables) {
        Ok(_) => return Ok(()),
        Err((exp, act)) => (exp, act),
    };

    if expected_str == actual_str {
        return Ok(());
    }

    if expected_str.trim() == actual_str.trim() {
        return Err(format!("White space error: Expected {:#?}, got {:#?}", expected_str, actual_str.to_string()).into());
    }

    Err(format!("Expected {:?}, got {:?}", expected_str.trim(), actual_str.trim()).into())
}

fn match_rv(
    expected: &str,
    result: &CK_RV,
) -> Result<(), Box<dyn std::error::Error>> {
    let r = parse_ck_rv(expected)?;

    if r == *result {
        return Ok(());
    } else {
        return Err(format!("Expected 0x{:08X} ({:?}), got 0x{:08X}", r, expected, result).into());
    }
}

fn match_flags(
    expected: &str,
    result: &CK_FLAGS,
) -> Result<(), Box<dyn std::error::Error>> {
    let r = parse_ck_flags(expected)?;

    if r == *result {
        return Ok(());
    } else {
        return Err(format!("Expected 0x{:08X} ({:?}), got 0x{:08X}", r, expected, result).into());
    }
}

fn match_mechanism_type(
    expected: &str,
    result: &CK_MECHANISM_TYPE,
) -> Result<(), Box<dyn std::error::Error>> {
    let r = parse_mechanism_type(expected)?;

    if r == *result {
        return Ok(());
    } else {
        return Err(format!("Expected 0x{:08X} ({:?}), got 0x{:08X}", r, expected, result).into());
    }
}

fn match_attributes(
    output_attrs: &[parser::Attribute],
    result: &(Vec<CK_ATTRIBUTE>, Vec<NativeValue>),
    variables: &mut HashMap<String, Box<dyn Any>>
) -> Result<(), Box<dyn std::error::Error>> {
    let (ck_attributes, input_val_buf) = result;
    let compare_limit = output_attrs.len().min(ck_attributes.len());

    for i in 0..compare_limit {
        if let Some(expected_str) = &output_attrs[i].value {
            match &input_val_buf[i] {
                NativeValue::Bool(b) => {
                    let _ = match_boolean(expected_str, *b, variables)
                        .inspect_err(|e| log_mismatches!(format!("Attribute {}", i), format!("{e}")));
                }
                NativeValue::Ulong(u) => {
                    let _ = match_numeric::<u64>(expected_str, (*u).into(), variables)
                        .inspect_err(|e| log_mismatches!(format!("Attribute {}", i), format!("{e}")));
                }
                NativeValue::Bytes(b) => {
                    let actual_len = ck_attributes[i].ulValueLen.try_into()?;
                    if actual_len > b.len() {
                        log_mismatches!(format!("Attribute {}", i), format!("Expected {}, got {} (invalid size)", b.len(), actual_len));
                    } else {
                        let actual_bytes = &b[..actual_len];
                        match ck_attributes[i].type_ {
                            CKA_LABEL | CKA_UNIQUE_ID | CKA_CHAR_SETS | CKA_ENCODING_METHODS | CKA_MIME_TYPES | CKA_APPLICATION | CKA_URL => {
                                if !expected_str.bytes().eq(actual_bytes.to_vec()) {
                                    log_mismatches!(format!("Attribute {}", i), format!("Expected {:?}, got {:?}", expected_str, actual_bytes));
                                }
                            },
                            _ => {
                                let _ = match_binary(expected_str, actual_bytes.to_vec(), variables)
                                    .inspect_err(|e| log_mismatches!(format!("Attribute {}", i), format!("{e}")));
                            },
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

unsafe fn copy_to_3_2<T: Copy>(
    from: &T
) -> cryptoki_sys::CK_FUNCTION_LIST_3_2 {
    let mut functions: cryptoki_sys::CK_FUNCTION_LIST_3_2 = std::mem::zeroed();
    let src = from as *const T as *const u8;
    let dest = &mut functions as *mut cryptoki_sys::CK_FUNCTION_LIST_3_2 as *mut u8;

    let copy_size = std::mem::size_of::<T>().min(std::mem::size_of::<cryptoki_sys::CK_FUNCTION_LIST_3_2>());

    ptr::copy_nonoverlapping(src, dest, copy_size);
    functions
}

pub struct P11TestRunner {
    _lib: libloading::Library,
    _functions: CK_FUNCTION_LIST_3_2,
}

impl P11TestRunner {
    pub unsafe fn new(
        library_path: &str
    ) -> Result<Self, String> {
        let lib = libloading::Library::new(library_path).map_err(|e| e.to_string())?;

        let c_get_function_list: libloading::Symbol<
            unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> cryptoki_sys::CK_RV,
        > = lib.get(b"C_GetFunctionList").map_err(|e| e.to_string())?;

        let mut functions_2_40 = ptr::null_mut();
        let res = c_get_function_list(&mut functions_2_40);

        if res != cryptoki_sys::CKR_OK || functions_2_40.is_null() {
            return Err(format!("C_GetFunctionList fehlgeschlagen: 0x{:X}", res));
        }

        Ok(Self {
            _lib: lib,
            _functions: copy_to_3_2(&*functions_2_40),
        })
    }

    pub fn run(
        &mut self,
        test: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_steps: PKCS11 = quick_xml::de::from_str(test)
            .inspect_err(|e| {
                report::set_context("File parsing");
                report::record_result(report::StepResult::Failed(format!("{}", e)));
            })?;
        let mut variables: HashMap<String, Box<dyn Any>> = HashMap::new();
        for io_pair in test_steps.steps.as_deref().unwrap_or_default().chunks(2) {
            report::set_context(format!("{}", io_pair[0]).as_str());
            let [input, output] = io_pair else {
                let e = "Missing output";
                report::record_result(report::StepResult::Failed(e.to_string()));
                return Err(e.into());
            };
            if std::mem::discriminant(input) != std::mem::discriminant(output) {
                let e = format!("Wrong output type: {}", output);
                report::record_result(report::StepResult::Failed(format!("{}", e)));
                return Err(e.into());
            }
            let r = match input {
                parser::TestStep::C_GetFunctionList   { .. } => self._c_get_function_list(input, output, &variables),
                parser::TestStep::C_GetInterface      { .. } => self._c_get_interface(input, output, &mut variables),
                parser::TestStep::C_Initialize        { .. } => self._c_initialize(input, output, &variables),
                parser::TestStep::C_Finalize          { .. } => self._c_finalize(input, output, &variables),
                parser::TestStep::C_GetInfo           { .. } => self._c_get_info(input, output, &mut variables),
                parser::TestStep::C_GetSlotList       { .. } => self._c_get_slot_list(input, output, &mut variables),
                parser::TestStep::C_GetSlotInfo       { .. } => self._c_get_slot_info(input, output, &mut variables),
                parser::TestStep::C_GetTokenInfo      { .. } => self._c_get_token_info(input, output, &mut variables),
                parser::TestStep::C_OpenSession       { .. } => self._c_open_session(input, output, &mut variables),
                parser::TestStep::C_CloseSession      { .. } => self._c_close_session(input, output, &mut variables),
                parser::TestStep::C_CloseAllSessions  { .. } => self._c_close_all_sessions(input, output, &mut variables),
                parser::TestStep::C_SessionCancel     { .. } => self._c_session_cancel(input, output, &mut variables),
                parser::TestStep::C_FindObjectsInit   { .. } => self._c_find_objects_init(input, output, &mut variables),
                parser::TestStep::C_FindObjects       { .. } => self._c_find_objects(input, output, &mut variables),
                parser::TestStep::C_FindObjectsFinal  { .. } => self._c_find_objects_final(input, output, &mut variables),
                parser::TestStep::C_CreateObject      { .. } => self._c_create_object(input, output, &mut variables),
                parser::TestStep::C_CopyObject        { .. } => self._c_copy_object(input, output, &mut variables),
                parser::TestStep::C_DestroyObject     { .. } => self._c_destroy_object(input, output, &mut variables),
                parser::TestStep::C_LoginUser         { .. } => self._c_login_user(input, output, &mut variables),
                parser::TestStep::C_Login             { .. } => self._c_login(input, output, &mut variables),
                parser::TestStep::C_Logout            { .. } => self._c_logout(input, output, &mut variables),
                parser::TestStep::C_SignRecoverInit   { .. } => self._c_sign_recover_init(input, output, &mut variables),
                parser::TestStep::C_SignRecover       { .. } => self._c_sign_recover(input, output, &mut variables),
                parser::TestStep::C_SignInit          { .. } => self._c_sign_init(input, output, &mut variables),
                parser::TestStep::C_Sign              { .. } => self._c_sign(input, output, &mut variables),
                parser::TestStep::C_SignUpdate        { .. } => self._c_sign_update(input, output, &mut variables),
                parser::TestStep::C_SignFinal         { .. } => self._c_sign_final(input, output, &mut variables),
                parser::TestStep::C_MessageSignInit   { .. } => self._c_message_sign_init(input, output, &mut variables),
                parser::TestStep::C_SignMessage       { .. } => self._c_sign_message(input, output, &mut variables),
                parser::TestStep::C_EncryptInit       { .. } => self._c_encrypt_init(input, output, &mut variables),
                parser::TestStep::C_Encrypt           { .. } => self._c_encrypt(input, output, &mut variables),
                parser::TestStep::C_EncryptUpdate     { .. } => self._c_encrypt_update(input, output, &mut variables),
                parser::TestStep::C_EncryptFinal      { .. } => self._c_encrypt_final(input, output, &mut variables),
                parser::TestStep::C_DecryptInit       { .. } => self._c_decrypt_init(input, output, &mut variables),
                parser::TestStep::C_Decrypt           { .. } => self._c_decrypt(input, output, &mut variables),
                parser::TestStep::C_DecryptUpdate     { .. } => self._c_decrypt_update(input, output, &mut variables),
                parser::TestStep::C_DecryptFinal      { .. } => self._c_decrypt_final(input, output, &mut variables),
                parser::TestStep::C_DigestInit        { .. } => self._c_digest_init(input, output, &mut variables),
                parser::TestStep::C_Digest            { .. } => self._c_digest(input, output, &mut variables),
                parser::TestStep::C_DigestUpdate      { .. } => self._c_digest_update(input, output, &mut variables),
                parser::TestStep::C_DigestKey         { .. } => self._c_digest_key(input, output, &mut variables),
                parser::TestStep::C_DigestFinal       { .. } => self._c_digest_final(input, output, &mut variables),
                parser::TestStep::C_GetAttributeValue { .. } => self._c_get_attribute_value(input, output, &mut variables),
                parser::TestStep::C_SetAttributeValue { .. } => self._c_set_attribute_value(input, output, &mut variables),
                parser::TestStep::C_GetMechanismList  { .. } => self._c_get_mechanism_list(input, output, &mut variables),
                parser::TestStep::C_GetMechanismInfo  { .. } => self._c_get_mechanism_info(input, output, &mut variables),
                parser::TestStep::C_InitToken         { .. } => self._c_init_token(input, output, &mut variables),
                parser::TestStep::C_InitPIN           { .. } => self._c_init_pin(input, output, &mut variables),
                parser::TestStep::C_SetPIN            { .. } => self._c_set_pin(input, output, &mut variables),
                parser::TestStep::C_GenerateKeyPair   { .. } => self._c_generate_key_pair(input, output, &mut variables),
                _ => Err("Unhandled operation".into()),
            };
            if r.is_ok() {
                report::record_result(report::StepResult::Pass);
            } else {
                report::record_result(report::StepResult::Failed(format!("{}", r.unwrap_err())));
            }
            
        }
        Ok(())
    }

    fn _c_get_function_list(
        &mut self,
        _input: &parser::TestStep,
        output: &parser::TestStep,
        _variables: &HashMap<String, Box<dyn Any>>,
    ) -> Result<(), Box<dyn std::error::Error>> {

        let get_function_list = self._functions.C_GetFunctionList
            .ok_or("Module doesn't implement call back")?;
        let mut functions = ptr::null_mut();

        let res = unsafe { get_function_list(&mut functions) };
        if res == CKR_OK && !functions.is_null() {
            // switch to received interface if operation was successful
            self._functions = unsafe { copy_to_3_2(&*functions) };
        }

        if let parser::TestStep::C_GetFunctionList { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_get_interface(
        &mut self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_GetInterface { interface_name: Some(interface_name), version: Some(version), flags: Some(flags), .. } = input else {
            return Err("Missing required field Flags".into());
        };
        let f = parse_ck_flags(flags.value.as_str())?;
        let name_str = fetch_text(interface_name.value.as_str(), variables)
            .map_err(|_| format!("InterfaceName '{}' not handled", interface_name.value))?;
        let p_name = name_str.as_ptr() as CK_UTF8CHAR_PTR;
        let mut target_version = CK_VERSION { major: parse_numeric(&version.major)?, minor: parse_numeric(&version.minor)? };
        let p_version = &mut target_version as *mut CK_VERSION;
        let mut functions = ptr::null_mut();

        let get_interface = self._functions.C_GetInterface
            .ok_or("Module doesn't implement call back")?;
        let res;
        unsafe {
            res = get_interface(p_name, p_version, &mut functions, f);
            let interface_struct = &*functions;
            if res == CKR_OK && !interface_struct.pFunctionList.is_null() {
                // switch to received interface if operation was successful
                let interface_version = interface_struct.pFunctionList as *const cryptoki_sys::CK_VERSION;
                if (*interface_version).major < 3 {
                    let functions_2_40 = interface_struct.pFunctionList as *const cryptoki_sys::CK_FUNCTION_LIST;
                    self._functions = copy_to_3_2(&*functions_2_40);
                } else {
                    if (*interface_version).major == 3 && (*interface_version).minor < 2 {
                        let functions_3_0 = interface_struct.pFunctionList as *const cryptoki_sys::CK_FUNCTION_LIST_3_0;
                        self._functions = copy_to_3_2(&*functions_3_0);
                    } else {
                        self._functions = *(interface_struct.pFunctionList as *const cryptoki_sys::CK_FUNCTION_LIST_3_2);
                    }
                }

            }
        }

        if let parser::TestStep::C_GetFunctionList { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_initialize(
        &self,
        _input: &parser::TestStep,
        output: &parser::TestStep,
        _variables: &HashMap<String, Box<dyn Any>>,
    ) -> Result<(), Box<dyn std::error::Error>> {

        let initialize = self._functions.C_Initialize
            .ok_or("Module doesn't implement call back")?;

        let res = unsafe { initialize(ptr::null_mut()) };

        if let parser::TestStep::C_Initialize { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_finalize(
        &self,
        _input: &parser::TestStep,
        output: &parser::TestStep,
        _variables: &HashMap<String, Box<dyn Any>>,
    ) -> Result<(), Box<dyn std::error::Error>> {

        let finalize = self._functions.C_Finalize
            .ok_or("Module doesn't implement call back")?;

        let res = unsafe { finalize(ptr::null_mut()) };


        if let parser::TestStep::C_Finalize { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_get_info(
        &self,
        _input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let get_info = self._functions.C_GetInfo
            .ok_or("Module doesn't implement call back")?;
        let mut ck_info: CK_INFO = unsafe { std::mem::zeroed() };
        let res = unsafe { get_info(&mut ck_info) };

        if let parser::TestStep::C_GetInfo { rv, info, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
            if let Some(value) = info {
                match_text(&value.manufacturer_id.value, &ck_info.manufacturerID, variables)
                    .inspect_err(|e| log_mismatches!("Info.manufacturerID", format!("{e}"))).ok();
                match_text(&value.library_description.value, &ck_info.libraryDescription, variables)
                    .inspect_err(|e| log_mismatches!("Info.libraryDescription", format!("{e}"))).ok();
                match_numeric(&value.cryptoki_version.major, ck_info.cryptokiVersion.major, variables)
                    .inspect_err(|e| log_mismatches!("Info.cryptokiVersion.major", format!("{e}"))).ok();
                match_numeric(&value.cryptoki_version.minor, ck_info.cryptokiVersion.minor, variables)
                    .inspect_err(|e| log_mismatches!("Info.cryptokiVersion.minor", format!("{e}"))).ok();
                match_numeric(&value.library_version.major, ck_info.libraryVersion.major, variables)
                    .inspect_err(|e| log_mismatches!("Info.libraryVersion.major", format!("{e}"))).ok();
                match_numeric(&value.library_version.minor, ck_info.libraryVersion.minor, variables)
                    .inspect_err(|e| log_mismatches!("Info.libraryVersion.minor", format!("{e}"))).ok();
                match_flags(&value.flags.value, &ck_info.flags.into())
                    .inspect_err(|e| log_mismatches!("Info.Flags", format!("{e}"))).ok();
            }
        }

        return Ok(());
    }

    fn _c_get_slot_list(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_GetSlotList { token_present: Some(token_present), slot_list, .. } = input else {
            return Err("Missing required fields TokenPresent".into());
        };
        let present = parse_boolean(token_present.value.as_str())?;
        let mut buffer: Vec<CK_SLOT_ID> = Vec::new();
        let (mut length, list) = if let Some(l) = &slot_list.length {
            let len = fetch_numeric::<CK_ULONG>(&l, variables)?;
            buffer = vec![0; len.try_into()?];
            (len.try_into()?, buffer.as_mut_ptr())
        } else {
            (0, ptr::null_mut())
        };
        let get_slot_list = self._functions.C_GetSlotList
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { get_slot_list(present, list, &mut length) };

        if let parser::TestStep::C_GetSlotList { rv, slot_list, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
            if let Some(value) = &slot_list.length {
                match_numeric(&value, length, variables)
                    .inspect_err(|e| log_mismatches!("SlotList.length", format!("{e}"))).ok();
            }
            if let Some(value) = &slot_list.slot_ids {
                if value.len() != length.try_into()? {
                    let r = format!("Expected {}, got {}", length, value.len());
                    log_mismatches!("SlotList.length", r);
                }
                for (slot_id, slot_id_value) in buffer.iter().zip(value.iter()) {
                    match_numeric(&slot_id_value.value, *slot_id, variables)
                        .inspect_err(|e| log_mismatches!("SlotList.SlotID", format!("{e}"))).ok();
                }
            }
        }

        return Ok(());
    }

    fn _c_get_slot_info(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_GetSlotInfo { slot_id: Some(slot_id), .. } = input else {
            return Err("Missing required field SlotID".into());
        };
        let id = fetch_numeric::<CK_SLOT_ID>(slot_id.value.as_str(), variables)?;

        let mut ck_slot_info: CK_SLOT_INFO = unsafe { std::mem::zeroed() };
        let get_slot_info = self._functions.C_GetSlotInfo
            .ok_or("Module doesn't implement call back")?;

        let res = unsafe { get_slot_info(id, &mut ck_slot_info) };

        if let parser::TestStep::C_GetSlotInfo { rv, info, slot_info, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
            if let Some(value) = &slot_info {
                match_text(&value.slot_description.value, &ck_slot_info.slotDescription, variables)
                    .inspect_err(|e| log_mismatches!("Info.slotDescription", format!("{e}"))).ok();
                match_text(&value.manufacturer_id.value, &ck_slot_info.manufacturerID, variables)
                    .inspect_err(|e| log_mismatches!("Info.manufacturerID", format!("{e}"))).ok();
                match_numeric(&value.hardware_version.major, ck_slot_info.hardwareVersion.major, variables)
                    .inspect_err(|e| log_mismatches!("Info.hardwareVersion.major", format!("{e}"))).ok();
                match_numeric(&value.hardware_version.minor, ck_slot_info.hardwareVersion.minor, variables)
                    .inspect_err(|e| log_mismatches!("Info.hardwareVersion.minor", format!("{e}"))).ok();
                match_numeric(&value.firmware_version.major, ck_slot_info.firmwareVersion.major, variables)
                    .inspect_err(|e| log_mismatches!("Info.firmwareVersion.major", format!("{e}"))).ok();
                match_numeric(&value.firmware_version.minor, ck_slot_info.firmwareVersion.minor, variables)
                    .inspect_err(|e| log_mismatches!("Info.firmwareVersion.minor", format!("{e}"))).ok();
                match_flags(&value.flags.value, &ck_slot_info.flags.into())
                    .inspect_err(|e| log_mismatches!("Info.Flags", format!("{e}"))).ok();
            }
            if let Some(value) = &info {
                match_text(&value.slot_description.value, &ck_slot_info.slotDescription, variables)
                    .inspect_err(|e| log_mismatches!("Info.slotDescription", format!("{e}"))).ok();
                match_text(&value.manufacturer_id.value, &ck_slot_info.manufacturerID, variables)
                    .inspect_err(|e| log_mismatches!("Info.manufacturerID", format!("{e}"))).ok();
                match_numeric(&value.hardware_version.major, ck_slot_info.hardwareVersion.major, variables)
                    .inspect_err(|e| log_mismatches!("Info.hardwareVersion.major", format!("{e}"))).ok();
                match_numeric(&value.hardware_version.minor, ck_slot_info.hardwareVersion.minor, variables)
                    .inspect_err(|e| log_mismatches!("Info.hardwareVersion.minor", format!("{e}"))).ok();
                match_numeric(&value.firmware_version.major, ck_slot_info.firmwareVersion.major, variables)
                    .inspect_err(|e| log_mismatches!("Info.firmwareVersion.major", format!("{e}"))).ok();
                match_numeric(&value.firmware_version.minor, ck_slot_info.firmwareVersion.minor, variables)
                    .inspect_err(|e| log_mismatches!("Info.firmwareVersion.minor", format!("{e}"))).ok();
                match_flags(&value.flags.value, &ck_slot_info.flags.into())
                    .inspect_err(|e| log_mismatches!("Info.Flags", format!("{e}"))).ok();
            }
        }

        return Ok(());
    }

    fn _c_get_token_info(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_GetTokenInfo { slot_id: Some(slot_id), .. } = input else {
            return Err("Missing required field SlotID".into());
        };
        let id = fetch_numeric::<CK_SLOT_ID>(slot_id.value.as_str(), variables)?;

        let mut ck_token_info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
        let get_token_info = self._functions.C_GetTokenInfo
            .ok_or("Module doesn't implement call back")?;

        let res = unsafe { get_token_info(id, &mut ck_token_info) };

        if let parser::TestStep::C_GetTokenInfo { rv, info, token_info, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
            if let Some(value) = &info {
                match_text(&value.label.value, &ck_token_info.label, variables)
                    .inspect_err(|e| log_mismatches!("Info.label", format!("{e}"))).ok();
                match_text(&value.manufacturer_id.value, &ck_token_info.manufacturerID, variables)
                    .inspect_err(|e| log_mismatches!("Info.manufacturerID", format!("{e}"))).ok();
                match_text(&value.model.value, &ck_token_info.model, variables)
                    .inspect_err(|e| log_mismatches!("Info.model", format!("{e}"))).ok();
                match_text(&value.serial_number.value, &ck_token_info.serialNumber, variables)
                    .inspect_err(|e| log_mismatches!("Info.serialNumber", format!("{e}"))).ok();
                match_numeric(&value.hardware_version.major, ck_token_info.hardwareVersion.major, variables)
                    .inspect_err(|e| log_mismatches!("Info.hardwareVersion.major", format!("{e}"))).ok();
                match_numeric(&value.hardware_version.minor, ck_token_info.hardwareVersion.minor, variables)
                    .inspect_err(|e| log_mismatches!("Info.hardwareVersion.minor", format!("{e}"))).ok();
                match_numeric(&value.firmware_version.major, ck_token_info.firmwareVersion.major, variables)
                    .inspect_err(|e| log_mismatches!("Info.firmwareVersion.major", format!("{e}"))).ok();
                match_numeric(&value.firmware_version.minor, ck_token_info.firmwareVersion.minor, variables)
                    .inspect_err(|e| log_mismatches!("Info.firmwareVersion.minor", format!("{e}"))).ok();
                match_text(&value.utc_time.value, &ck_token_info.utcTime, variables)
                    .inspect_err(|e| log_mismatches!("Info.utcTime", format!("{e}"))).ok();
                match_limit(&value.max_session_count, ck_token_info.ulMaxSessionCount, variables)
                    .inspect_err(|e| log_mismatches!("Info.MaxSessionCount", format!("{e}"))).ok();
                match_limit(&value.session_count, ck_token_info.ulSessionCount, variables)
                    .inspect_err(|e| log_mismatches!("Info.SessionCount", format!("{e}"))).ok();
                match_limit(&value.max_rw_session_count, ck_token_info.ulMaxRwSessionCount, variables)
                    .inspect_err(|e| log_mismatches!("Info.MaxRwSessionCount", format!("{e}"))).ok();
                match_limit(&value.rw_session_count, ck_token_info.ulRwSessionCount, variables)
                    .inspect_err(|e| log_mismatches!("Info.RwSessionCount", format!("{e}"))).ok();
                match_numeric(&value.max_pin_len, ck_token_info.ulMaxPinLen, variables)
                    .inspect_err(|e| log_mismatches!("Info.MaxPinLen", format!("{e}"))).ok();
                match_numeric(&value.min_pin_len, ck_token_info.ulMinPinLen, variables)
                    .inspect_err(|e| log_mismatches!("Info.MinPinLen", format!("{e}"))).ok();
                match_limit(&value.total_public_memory, ck_token_info.ulTotalPublicMemory, variables)
                    .inspect_err(|e| log_mismatches!("Info.TotalPublicMemory", format!("{e}"))).ok();
                match_limit(&value.free_public_memory, ck_token_info.ulFreePublicMemory, variables)
                    .inspect_err(|e| log_mismatches!("Info.FreePublicMemory", format!("{e}"))).ok();
                match_limit(&value.total_private_memory, ck_token_info.ulTotalPrivateMemory, variables)
                    .inspect_err(|e| log_mismatches!("Info.TotalPrivateMemory", format!("{e}"))).ok();
                match_limit(&value.free_private_memory, ck_token_info.ulFreePrivateMemory, variables)
                    .inspect_err(|e| log_mismatches!("Info.FreePrivateMemory", format!("{e}"))).ok();
                match_flags(&value.flags.value, &ck_token_info.flags.into())
                    .inspect_err(|e| log_mismatches!("Info.Flags", format!("{e}"))).ok();
            }
            if let Some(value) = &token_info {
                match_text(&value.label.value, &ck_token_info.label, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.label", format!("{e}"))).ok();
                match_text(&value.manufacturer_id.value, &ck_token_info.manufacturerID, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.manufacturerID", format!("{e}"))).ok();
                match_text(&value.model.value, &ck_token_info.model, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.model", format!("{e}"))).ok();
                match_text(&value.serial_number.value, &ck_token_info.serialNumber, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.serialNumber", format!("{e}"))).ok();
                match_numeric(&value.hardware_version.major, ck_token_info.hardwareVersion.major, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.hardwareVersion.major", format!("{e}"))).ok();
                match_numeric(&value.hardware_version.minor, ck_token_info.hardwareVersion.minor, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.hardwareVersion.minor", format!("{e}"))).ok();
                match_numeric(&value.firmware_version.major, ck_token_info.firmwareVersion.major, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.firmwareVersion.major", format!("{e}"))).ok();
                match_numeric(&value.firmware_version.minor, ck_token_info.firmwareVersion.minor, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.firmwareVersion.minor", format!("{e}"))).ok();
                match_text(&value.utc_time.value, &ck_token_info.utcTime, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.utcTime", format!("{e}"))).ok();
                match_limit(&value.max_session_count.value, ck_token_info.ulMaxSessionCount, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.MaxSessionCount", format!("{e}"))).ok();
                match_limit(&value.session_count.value, ck_token_info.ulSessionCount, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.SessionCount", format!("{e}"))).ok();
                match_limit(&value.max_rw_session_count.value, ck_token_info.ulMaxRwSessionCount, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.MaxRwSessionCount", format!("{e}"))).ok();
                match_limit(&value.rw_session_count.value, ck_token_info.ulRwSessionCount, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.RwSessionCount", format!("{e}"))).ok();
                match_numeric(&value.max_pin_len.value, ck_token_info.ulMaxPinLen, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.MaxPinLen", format!("{e}"))).ok();
                match_numeric(&value.min_pin_len.value, ck_token_info.ulMinPinLen, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.MinPinLen", format!("{e}"))).ok();
                match_limit(&value.total_public_memory.value, ck_token_info.ulTotalPublicMemory, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.TotalPublicMemory", format!("{e}"))).ok();
                match_limit(&value.free_public_memory.value, ck_token_info.ulFreePublicMemory, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.FreePublicMemory", format!("{e}"))).ok();
                match_limit(&value.total_private_memory.value, ck_token_info.ulTotalPrivateMemory, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.TotalPrivateMemory", format!("{e}"))).ok();
                match_limit(&value.free_private_memory.value, ck_token_info.ulFreePrivateMemory, variables)
                    .inspect_err(|e| log_mismatches!("TokenInfo.FreePrivateMemory", format!("{e}"))).ok();
                match_flags(&value.flags.value, &ck_token_info.flags.into())
                    .inspect_err(|e| log_mismatches!("TokenInfo.Flags", format!("{e}"))).ok();
            }
        }

        return Ok(());
    }

    fn _c_open_session(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_OpenSession { slot_id: Some(slot_id), flags: Some(flags), .. } = input else {
            return Err("Missing required fields (SlotID, Flags)".into());
        };
        let id = fetch_numeric::<CK_SLOT_ID>(slot_id.value.as_str(), variables)?;
        let f = parse_ck_flags(flags.value.as_str())?;
        let mut session_handle: CK_SESSION_HANDLE = 0;

        let open_session = self._functions.C_OpenSession
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { open_session(id, f, ptr::null_mut(), None, &mut session_handle) };

        if let parser::TestStep::C_OpenSession { rv, session, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
            if let Some(value) = &session {
                match_numeric(&value.value, session_handle, variables)
                    .inspect_err(|e| log_mismatches!("Session", format!("{e}"))).ok();
            }
        }

        return Ok(());
    }

    fn _c_session_cancel(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_SessionCancel { session: Some(session), flags: Some(flags), .. } = input else {
            return Err("Missing required field Session".into());
        };
        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let f = parse_ck_flags(flags.value.as_str())?;

        let session_cancel = self._functions.C_SessionCancel
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { session_cancel(session_handle, f) };

        if let parser::TestStep::C_SessionCancel { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        return Ok(());
    }

    fn _c_close_session(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_CloseSession { session: Some(session), .. } = input else {
            return Err("Missing required field Session".into());
        };
        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let close_session = self._functions.C_CloseSession
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { close_session(session_handle) };

        if let parser::TestStep::C_CloseSession { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        return Ok(());
    }

    fn _c_close_all_sessions(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_CloseAllSessions { slot_id: Some(slot_id), .. } = input else {
            return Err("Missing required field SlotID".into());
        };
        let id = fetch_numeric::<CK_SLOT_ID>(slot_id.value.as_str(), variables)?;
        let close_all_sessions = self._functions.C_CloseAllSessions
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { close_all_sessions(id) };

        if let parser::TestStep::C_CloseAllSessions { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        return Ok(());
    }

    fn _c_find_objects_init(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_FindObjectsInit { session: Some(session), template: Some(template), .. } = input else {
            return Err("Missing required fields (Session, Template)".into());
        };
        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let (mut attributes, _memory_guard) = parse_attributes(&template)?;
        let p_template = attributes.as_mut_ptr();
        let ul_count = attributes.len().try_into()?;
        let find_objects_init = self._functions.C_FindObjectsInit
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { find_objects_init(session_handle, p_template, ul_count) };

        if let parser::TestStep::C_FindObjectsInit { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        return Ok(());
    }

    fn _c_find_objects(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_FindObjects { session: Some(session), objects: Some(objects), .. } = input else {
            return Err("Missing required fields (Session, Object)".into());
        };
        let Some(ref max_count_str) = objects.length else {
            return Err("Missing required field Object.length".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let max_object_count = fetch_numeric::<CK_ULONG>(max_count_str, variables)?;
        let find_objects = self._functions.C_FindObjects
            .ok_or("Module doesn't implement C_FindObjects callback")?;

        let mut object_handles = vec![0 as CK_OBJECT_HANDLE; max_object_count.try_into()?];
        let mut found_object_count: CK_ULONG = 0;

        let res = unsafe {
            find_objects(session_handle, object_handles.as_mut_ptr(), max_object_count, &mut found_object_count)
        };

        if let parser::TestStep::C_FindObjects { rv, objects: expected_objects,  .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(obj_list) = expected_objects {
                if let Some(ref expected_vec) = obj_list.object {
                    if expected_vec.len() != found_object_count.try_into()? {
                        log_mismatches!("Object.length", format!("Expected {}, got {}", expected_vec.len(), found_object_count));
                    }
                    object_handles.truncate(found_object_count.try_into()?);

                    let compare_limit = expected_vec.len().min(object_handles.len());

                    for i in 0..compare_limit {
                        let expected_str = &expected_vec[i].value;
                        match_numeric::<CK_OBJECT_HANDLE>(expected_str.as_str(), object_handles[i], variables)
                            .inspect_err(|e| log_mismatches!(format!("Object.Object[{i}]"), format!("{e}"))).ok();
                    }
                }
            }
        }

        return Ok(());
    }

    fn _c_find_objects_final(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_FindObjectsFinal { session: Some(session), ..  } = input else {
            return Err("Missing required field Session".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let find_objects_final = self._functions.C_FindObjectsFinal
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { find_objects_final(session_handle) };

        if let parser::TestStep::C_FindObjectsFinal { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        return Ok(());
    }

    fn _c_create_object(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_CreateObject { session: Some(session), template: Some(template), .. } = input else {
            return Err("Missing required fields (Session, Template)".into());
        };
        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let (mut attributes, _memory_guard) = parse_attributes(&template)?;
        let p_template = attributes.as_mut_ptr();
        let ul_count = attributes.len().try_into()?;
        let mut object_handle: CK_OBJECT_HANDLE = 0;

        let create_object = self._functions.C_CreateObject
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { create_object(session_handle, p_template, ul_count, &mut object_handle) };

        if let parser::TestStep::C_CreateObject { rv, object, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(expected_str) = object {
                match_numeric::<CK_OBJECT_HANDLE>(&expected_str.value, object_handle, variables)
                    .inspect_err(|e| log_mismatches!(format!("Object"), format!("{e}"))).ok();
            }
        }

        return Ok(());
    }

    fn _c_copy_object(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_CopyObject { session: Some(session), object: Some(object), template: Some(template), .. } = input else {
            return Err("Missing required fields (Session, Object, Template)".into());
        };
        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let object_handle = fetch_numeric::<CK_OBJECT_HANDLE>(object.value.as_str(), variables)?;
        let (mut attributes, _memory_guard) = parse_attributes(&template)?;
        let p_template = attributes.as_mut_ptr();
        let ul_count = attributes.len().try_into()?;
        let mut new_object_handle: CK_OBJECT_HANDLE = 0;

        let copy_object = self._functions.C_CopyObject
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { copy_object(session_handle, object_handle, p_template, ul_count, &mut new_object_handle) };

        if let parser::TestStep::C_CopyObject { rv, new_object, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(expected_str) = new_object {
                match_numeric::<CK_OBJECT_HANDLE>(&expected_str.value, new_object_handle, variables)
                    .inspect_err(|e| log_mismatches!(format!("NewObject"), format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_destroy_object(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        // KORRIGIERT: Matcht jetzt auf C_DestroyObject
        let parser::TestStep::C_DestroyObject { session: Some(session), object: Some(object), .. } = input else {
            return Err("Missing required fields (Session, Object) in C_DestroyObject".into());
        };
        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let object_handle = fetch_numeric::<CK_OBJECT_HANDLE>(object.value.as_str(), variables)?;

        let destroy_object = self._functions.C_DestroyObject
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { destroy_object(session_handle, object_handle) };

        if let parser::TestStep::C_DestroyObject { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_get_object_size(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_GetObjectSize { session: Some(session), object: Some(object), .. } = input else {
            return Err("Missing required fields (Session, Object)".into());
        };
        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let object_handle = fetch_numeric::<CK_OBJECT_HANDLE>(object.value.as_str(), variables)?;
        let mut length = 0.try_into()?;

        let get_object_size = self._functions.C_GetObjectSize
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { get_object_size(session_handle, object_handle, &mut length) };

        if let parser::TestStep::C_GetObjectSize { rv, size, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(value) = size {
                match_numeric(&value.value, length, variables)
                    .inspect_err(|e| log_mismatches!("size", format!("{e}"))).ok();
            }
        }

        return Ok(());
    }

    fn _c_login_user(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_LoginUser { session: Some(session), user_type: Some(user_type), pin: Some(pin), username: Some(username), .. } = input else {
            return Err("Missing required fields (Session, UserType, Pin)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let user_type_val = parse_ck_user_type(&user_type.value)?;
        let pin_str = fetch_text(pin.value.as_str(), variables)
            .map_err(|_| format!("PIN or Variable '{}' not handled", pin.value))?;
        let p_pin = pin_str.as_ptr() as CK_UTF8CHAR_PTR;
        let ul_pin_len = pin_str.len().try_into()?;
        let username_str = fetch_text(username.value.as_str(), variables)
            .map_err(|_| format!("Username or Variable '{}' not handled", username.value))?;
        let p_username = username_str.as_ptr() as CK_UTF8CHAR_PTR;
        let ul_username_len = username_str.len().try_into()?;

        let login_user = self._functions.C_LoginUser
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { login_user(session_handle, user_type_val, p_pin, ul_pin_len, p_username, ul_username_len) };

        if let parser::TestStep::C_LoginUser { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_login(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_Login { session: Some(session), user_type: Some(user_type), pin: Some(pin), .. } = input else {
            return Err("Missing required fields (Session, UserType, Pin)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let user_type_val = parse_ck_user_type(&user_type.value)?;
        let pin_str = fetch_text(pin.value.as_str(), variables)
            .map_err(|_| format!("PIN or Variable '{}' not handled", pin.value))?;
        let p_pin = pin_str.as_ptr() as CK_UTF8CHAR_PTR;
        let ul_pin_len = pin_str.len().try_into()?;

        let login = self._functions.C_Login
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { login(session_handle, user_type_val, p_pin, ul_pin_len) };

        if let parser::TestStep::C_Login { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_logout(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_Logout { session: Some(session), .. } = input else {
            return Err("Missing required field Session".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let logout = self._functions.C_Logout
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { logout(session_handle) };

        if let parser::TestStep::C_Logout { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_message_sign_init(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_MessageSignInit { session: Some(session), mechanism: Some(mechanism), key: Some(key), .. } = input else {
            return Err("Missing required fields (Session, Mechanism, Key)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let key_handle = fetch_numeric::<CK_OBJECT_HANDLE>(key.value.as_str(), variables)?;

        let (mut ck_mechanism, _memory_guard) = parse_mechanism(mechanism)?;

        let message_sign_init = self._functions.C_MessageSignInit
            .ok_or("Module doesn't implement call back")?;

        let res = unsafe { message_sign_init(session_handle, &mut ck_mechanism, key_handle) };

        if let parser::TestStep::C_MessageSignInit { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_sign_message(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_SignMessage { session: Some(session), data: Some(data), signature: Some(signature_in), .. } = input else {
            return Err("Missing required fields (Session, Data, Signature)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        /* TODO parse parameter */
        let p_parameter = ptr::null_mut();
        let ul_parameter_len = 0.try_into()?;
        let mut data_bytes = parse_binary(data.value.as_str())?;
        let p_data = data_bytes.as_mut_ptr() as CK_BYTE_PTR;
        let ul_data_len = data_bytes.len().try_into()?;
        let sig_len_str = signature_in.length.as_ref().ok_or("Missing Signature.length")?;
        let mut ul_signature_len = parse_numeric::<CK_ULONG>(sig_len_str)?;
        let mut signature_buffer = vec![0u8; ul_signature_len.try_into()?];
        let p_signature = signature_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let sign_message = self._functions.C_SignMessage
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { sign_message(session_handle, p_parameter, ul_parameter_len, p_data, ul_data_len, p_signature, &mut ul_signature_len) };

        if let parser::TestStep::C_SignMessage { rv, signature: signature_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(sig_out) = signature_out {
                if let Some(expected_val) = &sig_out.value {
                    let actual_bytes = signature_buffer[..ul_signature_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("Signature", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    fn _c_sign_recover_init(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_SignRecoverInit { session: Some(session), mechanism: Some(mechanism), key: Some(key), .. } = input else {
            return Err("Missing required fields (Session, Mechanism, Key)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let key_handle = fetch_numeric::<CK_OBJECT_HANDLE>(key.value.as_str(), variables)?;

        let (mut ck_mechanism, _memory_guard) = parse_mechanism(mechanism)?;

        let sign_recover_init = self._functions.C_SignRecoverInit
            .ok_or("Module doesn't implement call back")?;

        let res = unsafe { sign_recover_init(session_handle, &mut ck_mechanism, key_handle) };

        if let parser::TestStep::C_SignRecoverInit { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_sign_recover(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_SignRecover { session: Some(session), data: Some(data), signature: Some(signature_in), .. } = input else {
            return Err("Missing required fields (Session, Data, Signature)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let mut data_bytes = parse_binary(data.value.as_str())?;
        let p_data = data_bytes.as_mut_ptr() as CK_BYTE_PTR;
        let ul_data_len = data_bytes.len().try_into()?;
        let sig_len_str = signature_in.length.as_ref().ok_or("Missing Signature.length")?;
        let mut ul_signature_len = parse_numeric::<CK_ULONG>(sig_len_str)?;
        let mut signature_buffer = vec![0u8; ul_signature_len.try_into()?];
        let p_signature = signature_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let sign_recover = self._functions.C_SignRecover
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { sign_recover(session_handle, p_data, ul_data_len, p_signature, &mut ul_signature_len) };

        if let parser::TestStep::C_SignRecover { rv, signature: signature_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(sig_out) = signature_out {
                if let Some(expected_val) = &sig_out.value {
                    let actual_bytes = signature_buffer[..ul_signature_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("Signature", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    fn _c_sign_init(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_SignInit { session: Some(session), mechanism: Some(mechanism), key: Some(key), .. } = input else {
            return Err("Missing required fields (Session, Mechanism, Key)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let key_handle = fetch_numeric::<CK_OBJECT_HANDLE>(key.value.as_str(), variables)?;

        let (mut ck_mechanism, _memory_guard) = parse_mechanism(mechanism)?;

        let sign_init = self._functions.C_SignInit
            .ok_or("Module doesn't implement call back")?;

        let res = unsafe { sign_init(session_handle, &mut ck_mechanism, key_handle) };

        if let parser::TestStep::C_SignInit { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_sign(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_Sign { session: Some(session), data: Some(data), signature: Some(signature_in), .. } = input else {
            return Err("Missing required fields (Session, Data, Signature)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let mut data_bytes = parse_binary(data.value.as_str())?;
        let p_data = data_bytes.as_mut_ptr() as CK_BYTE_PTR;
        let ul_data_len = data_bytes.len().try_into()?;
        let sig_len_str = signature_in.length.as_ref().ok_or("Missing Signature.length")?;
        let mut ul_signature_len = parse_numeric::<CK_ULONG>(sig_len_str)?;
        let mut signature_buffer = vec![0u8; ul_signature_len.try_into()?];
        let p_signature = signature_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let sign = self._functions.C_Sign
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { sign(session_handle, p_data, ul_data_len, p_signature, &mut ul_signature_len) };

        if let parser::TestStep::C_Sign { rv, signature: signature_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(sig_out) = signature_out {
                if let Some(expected_val) = &sig_out.value {
                    let actual_bytes = signature_buffer[..ul_signature_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("Signature", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    fn _c_sign_update(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_SignUpdate { session: Some(session), part: Some(part), .. } = input else {
            return Err("Missing required fields (Session, Part)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let mut part_bytes = parse_binary(part.value.as_str())?;
        let p_part = part_bytes.as_mut_ptr() as CK_BYTE_PTR;
        let ul_part_len = part_bytes.len().try_into()?;

        let sign_update = self._functions.C_SignUpdate
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { sign_update(session_handle, p_part, ul_part_len) };

        if let parser::TestStep::C_SignUpdate { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_sign_final(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_SignFinal { session: Some(session), signature: Some(signature), .. } = input else {
            return Err("Missing required fields (Session, Signature)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let last_dig_len_str = signature.length.as_ref().ok_or("Missing Signature.length")?;
        let mut ul_signature_len = parse_numeric::<CK_ULONG>(last_dig_len_str)?;
        let mut signature_buffer = vec![0u8; ul_signature_len.try_into()?];
        let p_signature = signature_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let signature_final = self._functions.C_SignFinal
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { signature_final(session_handle, p_signature, &mut ul_signature_len) };

        if let parser::TestStep::C_SignFinal { rv, signature: signature_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(dig_out) = signature_out {
                if let Some(expected_val) = &dig_out.value {
                    let actual_bytes = signature_buffer[..ul_signature_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("Signature", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }


    fn _c_encrypt_init(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_EncryptInit { session: Some(session), mechanism: Some(mechanism), key: Some(key), .. } = input else {
            return Err("Missing required fields (Session, Mechanism, Key)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let key_handle = fetch_numeric::<CK_OBJECT_HANDLE>(key.value.as_str(), variables)?;

        let (mut ck_mechanism, _memory_guard) = parse_mechanism(mechanism)?;

        let encrypt_init = self._functions.C_EncryptInit
            .ok_or("Module doesn't implement call back")?;

        let res = unsafe { encrypt_init(session_handle, &mut ck_mechanism, key_handle) };

        if let parser::TestStep::C_EncryptInit { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_encrypt(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_Encrypt { session: Some(session), data: Some(data), encrypted_data: Some(encrypted_data), .. } = input else {
            return Err("Missing required fields (Session, Data, EncryptedData)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let mut data_bytes = parse_binary(data.value.as_str())?;
        let p_data = data_bytes.as_mut_ptr() as CK_BYTE_PTR;
        let ul_data_len = data_bytes.len().try_into()?;
        let enc_len_str = encrypted_data.length.as_ref().ok_or("Missing EncryptedData.length")?;
        let mut ul_encrypted_data_len = parse_numeric::<CK_ULONG>(enc_len_str)?;
        let mut encrypted_data_buffer = vec![0u8; ul_encrypted_data_len.try_into()?];
        let p_encrypted_data = encrypted_data_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let encrypt = self._functions.C_Encrypt
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { encrypt(session_handle, p_data, ul_data_len, p_encrypted_data, &mut ul_encrypted_data_len) };

        if let parser::TestStep::C_Encrypt { rv, encrypted_data: encrypted_data_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(enc_out) = encrypted_data_out {
                if let Some(expected_val) = &enc_out.value {
                    let actual_bytes = encrypted_data_buffer[..ul_encrypted_data_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("EncryptedData", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    fn _c_encrypt_update(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_EncryptUpdate { session: Some(session), part: Some(part), encrypted_part: Some(encrypted_part), .. } = input else {
            return Err("Missing required fields (Session, Part, EncryptedPart)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let mut part_bytes = parse_binary(part.value.as_str())?;
        let p_part = part_bytes.as_mut_ptr() as CK_BYTE_PTR;
        let ul_part_len = part_bytes.len().try_into()?;

        let enc_len_str = encrypted_part.length.as_ref().ok_or("Missing EncryptedPart.length")?;
        let mut ul_encrypted_part_len = parse_numeric::<CK_ULONG>(enc_len_str)?;
        let mut encrypted_part_buffer = vec![0u8; ul_encrypted_part_len.try_into()?];
        let p_encrypted_part = encrypted_part_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let encrypt_update = self._functions.C_EncryptUpdate
            .ok_or("Module doesn't implement C_EncryptUpdate callback")?;
        let res = unsafe { encrypt_update(session_handle, p_part, ul_part_len, p_encrypted_part, &mut ul_encrypted_part_len) };

        if let parser::TestStep::C_EncryptUpdate { rv, encrypted_part: encrypted_part_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(enc_out) = encrypted_part_out {
                if let Some(expected_val) = &enc_out.value {
                    let actual_bytes = encrypted_part_buffer[..ul_encrypted_part_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("EncryptedPart", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    // TODO
    fn _c_encrypt_final(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_EncryptFinal { session: Some(session), last_encrypted_part: Some(last_encrypted_part), .. } = input else {
            return Err("Missing required fields (Session, LastEncryptedPart)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let last_enc_len_str = last_encrypted_part.length.as_ref().ok_or("Missing LastEncryptedPart.length")?;
        let mut ul_last_encrypted_part_len = parse_numeric::<CK_ULONG>(last_enc_len_str)?;
        let mut last_encrypted_part_buffer = vec![0u8; ul_last_encrypted_part_len.try_into()?];
        let p_last_encrypted_part = last_encrypted_part_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let encrypt_final = self._functions.C_EncryptFinal
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { encrypt_final(session_handle, p_last_encrypted_part, &mut ul_last_encrypted_part_len) };

        if let parser::TestStep::C_EncryptFinal { rv, last_encrypted_part: last_encrypted_part_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(enc_out) = last_encrypted_part_out {
                if let Some(expected_val) = &enc_out.value {
                    let actual_bytes = last_encrypted_part_buffer[..ul_last_encrypted_part_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("LastEncryptedPart", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    fn _c_decrypt_init(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_DecryptInit { session: Some(session), mechanism: Some(mechanism), key: Some(key), .. } = input else {
            return Err("Missing required fields (Session, Mechanism, Key)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let key_handle = fetch_numeric::<CK_OBJECT_HANDLE>(key.value.as_str(), variables)?;

        let (mut ck_mechanism, _memory_guard) = parse_mechanism(mechanism)?;

        let decrypt_init = self._functions.C_DecryptInit
            .ok_or("Module doesn't implement call back")?;

        let res = unsafe { decrypt_init(session_handle, &mut ck_mechanism, key_handle) };

        if let parser::TestStep::C_DecryptInit { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_decrypt(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_Decrypt { session: Some(session), data: Some(data), decrypted_data: Some(decrypted_data), .. } = input else {
            return Err("Missing required fields (Session, Data, DecryptedData)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let mut data_bytes = parse_binary(data.value.as_str())?;
        let p_data = data_bytes.as_mut_ptr() as CK_BYTE_PTR;
        let ul_data_len = data_bytes.len().try_into()?;
        let dec_len_str = decrypted_data.length.as_ref().ok_or("Missing DecryptedData.length")?;
        let mut ul_decrypted_data_len = parse_numeric::<CK_ULONG>(dec_len_str)?;
        let mut decrypted_data_buffer = vec![0u8; ul_decrypted_data_len.try_into()?];
        let p_decrypted_data = decrypted_data_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let decrypt = self._functions.C_Decrypt
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { decrypt(session_handle, p_data, ul_data_len, p_decrypted_data, &mut ul_decrypted_data_len) };

        if let parser::TestStep::C_Decrypt { rv, decrypted_data: decrypted_data_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(dec_out) = decrypted_data_out {
                if let Some(expected_val) = &dec_out.value {
                    let actual_bytes = decrypted_data_buffer[..ul_decrypted_data_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("DecryptedData", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    fn _c_decrypt_update(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_DecryptUpdate { session: Some(session), part: Some(part), decrypted_part: Some(decrypted_part), .. } = input else {
            return Err("Missing required fields (Session, Part, DecryptedPart)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let mut part_bytes = parse_binary(part.value.as_str())?;
        let p_part = part_bytes.as_mut_ptr() as CK_BYTE_PTR;
        let ul_part_len = part_bytes.len().try_into()?;
        let dec_len_str = decrypted_part.length.as_ref().ok_or("Missing DecryptedPart.length")?;
        let mut ul_decrypted_part_len = parse_numeric::<CK_ULONG>(dec_len_str)?;
        let mut decrypted_part_buffer = vec![0u8; ul_decrypted_part_len.try_into()?];
        let p_decrypted_part = decrypted_part_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let decrypt = self._functions.C_Decrypt
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { decrypt(session_handle, p_part, ul_part_len, p_decrypted_part, &mut ul_decrypted_part_len) };

        if let parser::TestStep::C_DecryptUpdate { rv, decrypted_part: decrypted_part_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(dec_out) = decrypted_part_out {
                if let Some(expected_val) = &dec_out.value {
                    let actual_bytes = decrypted_part_buffer[..ul_decrypted_part_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("DecryptedPart", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    fn _c_decrypt_final(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_DecryptFinal { session: Some(session), last_decrypted_part: Some(last_decrypted_part), .. } = input else {
            return Err("Missing required fields (Session, LastDecryptedPart)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let last_dec_len_str = last_decrypted_part.length.as_ref().ok_or("Missing LastDecryptedPart.length")?;
        let mut ul_last_decrypted_part_len = parse_numeric::<CK_ULONG>(last_dec_len_str)?;
        let mut last_decrypted_part_buffer = vec![0u8; ul_last_decrypted_part_len.try_into()?];
        let p_last_decrypted_part = last_decrypted_part_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let decrypt_final = self._functions.C_DecryptFinal
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { decrypt_final(session_handle, p_last_decrypted_part, &mut ul_last_decrypted_part_len) };

        if let parser::TestStep::C_DecryptFinal { rv, last_decrypted_part: last_decrypted_part_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(dec_out) = last_decrypted_part_out {
                if let Some(expected_val) = &dec_out.value {
                    let actual_bytes = last_decrypted_part_buffer[..ul_last_decrypted_part_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("LastDecryptedPart", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    fn _c_digest_init(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_DigestInit { session: Some(session), mechanism: Some(mechanism), .. } = input else {
            return Err("Missing required fields (Session, Mechanism)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;

        let (mut ck_mechanism, _memory_guard) = parse_mechanism(mechanism)?;

        let digest_init = self._functions.C_DigestInit
            .ok_or("Module doesn't implement call back")?;

        let res = unsafe { digest_init(session_handle, &mut ck_mechanism) };

        if let parser::TestStep::C_DigestInit { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_digest(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_Digest { session: Some(session), data: Some(data), digest: Some(digest), .. } = input else {
            return Err("Missing required fields (Session, Data, Digest)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let mut data_bytes = parse_binary(data.value.as_str())?;
        let p_data = data_bytes.as_mut_ptr() as CK_BYTE_PTR;
        let ul_data_len = data_bytes.len().try_into()?;
        let dig_len_str = digest.length.as_ref().ok_or("Missing DigestedData.length")?;
        let mut ul_digest_data_len = parse_numeric::<CK_ULONG>(dig_len_str)?;
        let mut digest_data_buffer = vec![0u8; ul_digest_data_len.try_into()?];
        let p_digest_data = digest_data_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let decrypt = self._functions.C_Digest
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { decrypt(session_handle, p_data, ul_data_len, p_digest_data, &mut ul_digest_data_len) };

        if let parser::TestStep::C_Digest { rv, digest: digest_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(dig_out) = digest_out {
                if let Some(expected_val) = &dig_out.value {
                    let actual_bytes = digest_data_buffer[..ul_digest_data_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("DigestedData", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    fn _c_digest_update(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_DigestUpdate { session: Some(session), part: Some(part), .. } = input else {
            return Err("Missing required fields (Session, Part, DigestedPart)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let mut part_bytes = parse_binary(part.value.as_str())?;
        let p_part = part_bytes.as_mut_ptr() as CK_BYTE_PTR;
        let ul_part_len = part_bytes.len().try_into()?;

        let digest_update = self._functions.C_DigestUpdate
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { digest_update(session_handle, p_part, ul_part_len) };

        if let parser::TestStep::C_DigestUpdate { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_digest_key(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_DigestKey { session: Some(session), key: Some(key), .. } = input else {
            return Err("Missing required fields (Session, Key)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let key_handle = fetch_numeric::<CK_OBJECT_HANDLE>(key.value.as_str(), variables)?;

        let digest_key = self._functions.C_DigestKey
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { digest_key(session_handle, key_handle) };

        if let parser::TestStep::C_DigestKey { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_digest_final(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_DigestFinal { session: Some(session), digest: Some(digest), .. } = input else {
            return Err("Missing required fields (Session, LastDigestedPart)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let last_dig_len_str = digest.length.as_ref().ok_or("Missing LastDigestedPart.length")?;
        let mut ul_digest_len = parse_numeric::<CK_ULONG>(last_dig_len_str)?;
        let mut digest_buffer = vec![0u8; ul_digest_len.try_into()?];
        let p_digest = digest_buffer.as_mut_ptr() as CK_BYTE_PTR;

        let digest_final = self._functions.C_DigestFinal
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { digest_final(session_handle, p_digest, &mut ul_digest_len) };

        if let parser::TestStep::C_DigestFinal { rv, digest: digest_out, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(dig_out) = digest_out {
                if let Some(expected_val) = &dig_out.value {
                    let actual_bytes = digest_buffer[..ul_digest_len.try_into()?].to_vec();
                    match_binary(expected_val.as_str(), actual_bytes, variables)
                        .inspect_err(|e| log_mismatches!("LastDigestedPart", format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    fn _c_get_attribute_value(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_GetAttributeValue {
            session: Some(session),
            object: Some(object),
            template: Some(input_template),
            ..
        } = input else {
            return Err("Missing required fields (Session, Object, Template)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let object_handle = fetch_numeric::<CK_OBJECT_HANDLE>(object.value.as_str(), variables)?;
        let (mut ck_attributes, input_val_buf) = parse_attributes(input_template)?;
        let p_template = ck_attributes.as_mut_ptr();
        let ul_count = ck_attributes.len().try_into()?;

        let get_attribute_value = self._functions.C_GetAttributeValue
            .ok_or("Module doesn't implement C_GetAttributeValue")?;
        let res = unsafe { get_attribute_value(session_handle, object_handle, p_template, ul_count) };

        if let parser::TestStep::C_GetAttributeValue { rv, template: Some(output_template), .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }

            if let Some(output_attrs) = &output_template.attribute {
                if output_attrs.len() != ul_count.try_into()? {
                    log_mismatches!("Template.length", format!("Expected {}, got {}", output_attrs.len(), ul_count))
                }
                match_attributes(output_attrs, &(ck_attributes, input_val_buf), variables)
                    .inspect_err(|e| log_mismatches!("Template", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_set_attribute_value(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_SetAttributeValue {
            session: Some(session),
            object: Some(object),
            template: Some(input_template),
            ..
        } = input else {
            return Err("Missing required fields (Session, Object, Template)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let object_handle = fetch_numeric::<CK_OBJECT_HANDLE>(object.value.as_str(), variables)?;
        let (mut ck_attributes, _input_val_buf) = parse_attributes(input_template)?;
        let p_template = ck_attributes.as_mut_ptr();
        let ul_count = ck_attributes.len().try_into()?;

        let set_attribute_value = self._functions.C_SetAttributeValue
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { set_attribute_value(session_handle, object_handle, p_template, ul_count) };

        if let parser::TestStep::C_SetAttributeValue { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_get_mechanism_list(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_GetMechanismList { slot_id: Some(slot), mechanism_list, ..  } = input else {
            return Err("Missing SlotID in input C_GetMechanismList".into());
        };

        let slot_id = fetch_numeric::<CK_SLOT_ID>(slot.value.as_str(), variables)?;
        let mut buffer: Vec<CK_MECHANISM_TYPE> = Vec::new();
        let (mut length, list) = if let Some(l) = &mechanism_list.length {
            let len = fetch_numeric::<CK_ULONG>(&l, variables)?;
            buffer = vec![0; len.try_into()?];
            (len.try_into()?, buffer.as_mut_ptr())
        } else {
            (0, ptr::null_mut())
        };

        let get_mechanism_list = self._functions.C_GetMechanismList
            .ok_or("Module doesn't implement C_GetMechanismList")?;
        let res = unsafe { get_mechanism_list(slot_id, list, &mut length) };

        if let parser::TestStep::C_GetMechanismList { rv, mechanism_list, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
            if let Some(value) = &mechanism_list.length {
                match_numeric(&value, length, variables)
                    .inspect_err(|e| log_mismatches!("MechanismList.length", format!("{e}"))).ok();
            }
            if let Some(ref typ) = mechanism_list.typ {
                if typ.len() != length.try_into()? {
                    log_mismatches!("MechanismList.length", format!("Expected {}, got {}", typ.len(), length));
                }
                buffer.truncate(length.try_into()?);

                let compare_limit = typ.len().min(buffer.len());

                for i in 0..compare_limit {
                    let expected_str = &typ[i].value;
                    match_mechanism_type(expected_str.as_str(), &buffer[i])
                        .inspect_err(|e| log_mismatches!(format!("Object.Object[{i}]"), format!("{e}"))).ok();
                }
            }
        }

        Ok(())
    }

    fn _c_get_mechanism_info(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_GetMechanismInfo { slot_id: Some(slot_id), mechanism: Some(mechanism), ..  } = input else {
            return Err("Missing required fields (SlotID, Mechanism)".into());
        };

        let id = fetch_numeric::<CK_SLOT_ID>(slot_id.value.as_str(), variables)?;
        let mech_type = parse_mechanism_type(mechanism.value.as_str())?;
        let mut info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };

        let get_mechanism_info = self._functions.C_GetMechanismInfo
            .ok_or("Module doesn't implement C_GetMechanismInfo")?;
        let res = unsafe { get_mechanism_info(id, mech_type, &mut info) };

        if let parser::TestStep::C_GetMechanismInfo { rv, info: mechanisminfo, mechanism_info, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
            if let Some(value) = &mechanisminfo {
                match_numeric(&value.min_key_size, info.ulMinKeySize, variables)
                    .inspect_err(|e| log_mismatches!("Info.MinKeySize", format!("{e}"))).ok();
                match_numeric(&value.max_key_size, info.ulMaxKeySize, variables)
                    .inspect_err(|e| log_mismatches!("Info.MaxKeySize", format!("{e}"))).ok();
                match_flags(&value.flags.value, &info.flags.into())
                    .inspect_err(|e| log_mismatches!("Info.Flags", format!("{e}"))).ok();
            }
            if let Some(value) = &mechanism_info {
                match_numeric(&value.min_key_size.value, info.ulMinKeySize, variables)
                    .inspect_err(|e| log_mismatches!("Info.MinKeySize", format!("{e}"))).ok();
                match_numeric(&value.max_key_size.value, info.ulMaxKeySize, variables)
                    .inspect_err(|e| log_mismatches!("Info.MaxKeySize", format!("{e}"))).ok();
                match_flags(&value.flags.value, &info.flags.into())
                    .inspect_err(|e| log_mismatches!("Info.Flags", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_init_token(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_InitToken { slot_id: Some(slot_id), pin: Some(pin), label: Some(label), .. } = input else {
            return Err("Missing required fields (SlotID, PIN, Label)".into());
        };

        let id = fetch_numeric::<CK_SLOT_ID>(slot_id.value.as_str(), variables)?;
        let pin_str = fetch_text(pin.value.as_str(), variables)
            .map_err(|_| format!("PIN or Variable '{}' not handled", pin.value))?;
        let p_pin = pin_str.as_ptr() as CK_UTF8CHAR_PTR;

        let ul_pin_len = pin_str.len().try_into().map_err(|_| "PIN length overflow")?;
        let mut padded_label = vec![b' '; 32];
        let label_bytes = label.value.as_bytes();
        let copy_len = label_bytes.len().min(32);
        padded_label[..copy_len].copy_from_slice(&label_bytes[..copy_len]);
        let p_label = padded_label.as_mut_ptr() as CK_UTF8CHAR_PTR;

        let init_token = self._functions.C_InitToken
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { init_token(id, p_pin, ul_pin_len, p_label) };

        if let parser::TestStep::C_InitToken { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_init_pin(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_InitPIN { session: Some(session), pin: Some(pin), .. } = input else {
            return Err("Missing required field Session".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let pin_str = fetch_text(pin.value.as_str(), variables)
            .map_err(|_| format!("PIN or Variable '{}' not handled", pin.value))?;
        let p_pin = pin_str.as_ptr() as CK_UTF8CHAR_PTR;
        let ul_pin_len = pin_str.len().try_into()?;

        let init_pin = self._functions.C_InitPIN
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { init_pin(session_handle, p_pin, ul_pin_len) };

        if let parser::TestStep::C_InitPIN { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_set_pin(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parser::TestStep::C_SetPIN { session: Some(session), old_pin: Some(old_pin), new_pin: Some(new_pin), .. } = input else {
            return Err("Missing required field Session".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let old_pin_str = fetch_text(old_pin.value.as_str(), variables)
            .map_err(|_| format!("PIN or Variable '{}' not handled", old_pin.value))?;
        let p_old_pin = old_pin_str.as_ptr() as CK_UTF8CHAR_PTR;
        let ul_old_pin_len = old_pin_str.len().try_into()?;
        let new_pin_str = fetch_text(new_pin.value.as_str(), variables)
            .map_err(|_| format!("PIN or Variable '{}' not handled", new_pin.value))?;
        let p_new_pin = new_pin_str.as_ptr() as CK_UTF8CHAR_PTR;
        let ul_new_pin_len = new_pin_str.len().try_into()?;

        let set_pin = self._functions.C_SetPIN
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe { set_pin(session_handle, p_old_pin, ul_old_pin_len, p_new_pin, ul_new_pin_len) };

        if let parser::TestStep::C_SetPIN { rv, .. } = output {
            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

    fn _c_generate_key_pair(
        &self,
        input: &parser::TestStep,
        output: &parser::TestStep,
        variables: &mut HashMap<String, Box<dyn Any>>
    ) -> Result<(), Box<dyn std::error::Error>> {

        // 1. Input-Parameter destrukturieren
        // Hinweis: In deiner Parser-Definition heißt das Feld für den Mechanismus `key`.
        let parser::TestStep::C_GenerateKeyPair {
            session: Some(session),
            key: Some(mechanism_in),
            public_template: Some(public_template),
            private_template: Some(private_template),
            ..
        } = input else {
            return Err("Missing required fields (Session, Mechanism, PublicKeyTemplate, PrivateKeyTemplate)".into());
        };

        let session_handle = fetch_numeric::<CK_SESSION_HANDLE>(session.value.as_str(), variables)?;
        let (mut mechanism, _mech_native) = parse_mechanism(mechanism_in)?;
        let p_mechanism = &mut mechanism as CK_MECHANISM_PTR;
        let (mut pub_attr, _pub_native) = parse_attributes(public_template)?;
        let p_public_key_template = pub_attr.as_mut_ptr();
        let ul_public_key_attribute_count = pub_attr.len().try_into()?;
        let (mut priv_attr, _priv_native) = parse_attributes(private_template)?;
        let p_private_key_template = priv_attr.as_mut_ptr();
        let ul_private_key_attribute_count = priv_attr.len().try_into()?;
        let mut h_public_key: CK_OBJECT_HANDLE = 0;
        let mut h_private_key: CK_OBJECT_HANDLE = 0;

        let generate_key_pair = self._functions.C_GenerateKeyPair
            .ok_or("Module doesn't implement call back")?;
        let res = unsafe {
            generate_key_pair(
                session_handle,
                p_mechanism,
                p_public_key_template,
                ul_public_key_attribute_count,
                p_private_key_template,
                ul_private_key_attribute_count,
                &mut h_public_key,
                &mut h_private_key
            )
        };

        if let parser::TestStep::C_GenerateKeyPair { rv, public_key: pub_key_out, private_key: priv_key_out, .. } = output {

            if let Some(value) = rv {
                match_rv(value, &res)
                    .inspect_err(|e| log_mismatches!("rv", format!("{e}"))).ok();
            }
            if let Some(pub_key) = pub_key_out {
                match_numeric(&pub_key.value, h_public_key, variables)
                    .inspect_err(|e| log_mismatches!("PublicKey", format!("{e}"))).ok();
            }
            if let Some(priv_key) = priv_key_out {
                match_numeric(&priv_key.value, h_private_key, variables)
                    .inspect_err(|e| log_mismatches!("PrivateKey", format!("{e}"))).ok();
            }
        }

        Ok(())
    }

}
