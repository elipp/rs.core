use client::{ProtocolError, Verifier};
use num_bigint::BigUint;

#[allow(dead_code)]
#[repr(u8)]
pub enum AuthResult {
    Success = 0x00,
    FailBanned = 0x03,
    FailUnknownAccount = 0x04,
    FailIncorrectPassword = 0x05,
    FailAlreadyOnline = 0x06,
    FailNoTime = 0x07,
    FailDbBusy = 0x08,
    FailVersionInvalid = 0x09,
    FailVersionUpdate = 0x0A,
    FailInvalidServer = 0x0B,
    FailSuspended = 0x0C,
    FailNoAccess = 0x0D,
    SuccessSurvey = 0x0E,
    FailParentControl = 0x0F,
    FailLockedEnforced = 0x10,
    FailTrialEnded = 0x11,
    FailUseBattlenet = 0x12,
    FailAntiIndulgence = 0x13,
    FailExpired = 0x14,
    FailNoGameAccount = 0x15,
    FailChargeback = 0x16,
    FailInternetGameRoomWithoutBnet = 0x17,
    FailGameAccountLocked = 0x18,
    FailUnlockableLock = 0x19,
    FailConversionRequired = 0x20,
    FailDisconnected = 0xFF,
}

#[allow(dead_code)]
#[repr(u8)]
pub enum LoginResult {
    Ok = 0x00,
    Failed = 0x01,
    Failed2 = 0x02,
    Banned = 0x03,
    UnknownAccount = 0x04,
    UnknownAccount3 = 0x05,
    AlreadyOnline = 0x06,
    NoTime = 0x07,
    DbBusy = 0x08,
    BadVersion = 0x09,
    DownloadFile = 0x0A,
    Failed3 = 0x0B,
    Suspended = 0x0C,
    Failed4 = 0x0D,
    Connected = 0x0E,
    ParentalControl = 0x0F,
    LockedEnforced = 0x10,
}

#[allow(dead_code)]
#[repr(u8)]
pub enum ExpansionFlags {
    PostBcExpFlag = 0x2,
    PreBcExpFlag = 0x1,
    NoValidExpFlag = 0x0,
}
