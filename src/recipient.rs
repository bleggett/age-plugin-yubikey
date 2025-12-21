use std::fmt;

use age_core::format::{FileKey, Stanza};
use sha2::{Digest, Sha256};

use crate::{piv_p256, PLUGIN_NAME};

pub(crate) const TAG_BYTES: usize = 4;

#[derive(Clone, Debug)]
pub(crate) enum Recipient {
    PivP256(piv_p256::Recipient),
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Recipient::PivP256(recipient) => recipient.fmt(f),
        }
    }
}

impl Recipient {
    /// Attempts to parse a supported YubiKey recipient.
    pub(crate) fn from_bytes(plugin_name: &str, bytes: &[u8]) -> Option<Self> {
        match plugin_name {
            PLUGIN_NAME => piv_p256::Recipient::from_bytes(bytes).map(Self::PivP256),
            _ => None,
        }
    }

    /// Returns the static tag for this recipient.
    pub(crate) fn static_tag(&self) -> [u8; TAG_BYTES] {
        match self {
            Recipient::PivP256(recipient) => recipient.tag(),
        }
    }

    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> Stanza {
        match self {
            Recipient::PivP256(recipient) => recipient.wrap_file_key(file_key).into(),
        }
    }
}

pub(crate) fn static_tag(pk: &[u8]) -> [u8; TAG_BYTES] {
    Sha256::digest(pk)[0..TAG_BYTES]
        .try_into()
        .expect("length is correct")
}
