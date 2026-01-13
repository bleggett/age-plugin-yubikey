use dialoguer::Password;
use yubikey::{
    certificate::Certificate,
    piv::{generate as yubikey_generate, AlgorithmId, RetiredSlotId, SlotId},
    Key, PinPolicy, TouchPolicy, YubiKey,
};
use der::asn1::Utf8StringRef;
use der::Encode;
use x509_cert::name::{Name, RdnSequence};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::{
    error::Error,
    fl,
    key::{self, Stub},
    piv_p256,
    util::Metadata,
    Recipient, BINARY_NAME, USABLE_SLOTS,
};

pub(crate) const DEFAULT_PIN_POLICY: PinPolicy = PinPolicy::Once;
pub(crate) const DEFAULT_TOUCH_POLICY: TouchPolicy = TouchPolicy::Always;

pub(crate) struct IdentityBuilder {
    slot: Option<RetiredSlotId>,
    force: bool,
    name: Option<String>,
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
}

impl IdentityBuilder {
    pub(crate) fn new(slot: Option<RetiredSlotId>) -> Self {
        IdentityBuilder {
            slot,
            name: None,
            pin_policy: None,
            touch_policy: None,
            force: false,
        }
    }

    pub(crate) fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    pub(crate) fn with_pin_policy(mut self, pin_policy: Option<PinPolicy>) -> Self {
        self.pin_policy = pin_policy;
        self
    }

    pub(crate) fn with_touch_policy(mut self, touch_policy: Option<TouchPolicy>) -> Self {
        self.touch_policy = touch_policy;
        self
    }

    pub(crate) fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub(crate) fn build(self, yubikey: &mut YubiKey) -> Result<(Stub, Recipient, Metadata), Error> {
        let slot = match self.slot {
            Some(slot) => {
                if !self.force {
                    // Check that the slot is empty.
                    if Key::list(yubikey)?
                        .into_iter()
                        .any(|key| key.slot() == SlotId::Retired(slot))
                    {
                        return Err(Error::SlotIsNotEmpty(slot));
                    }
                }

                // Now either the slot is empty, or --force is specified.
                slot
            }
            None => {
                // Use the first empty slot.
                let keys = Key::list(yubikey)?;
                USABLE_SLOTS
                    .iter()
                    .find(|&&slot| !keys.iter().any(|key| key.slot() == SlotId::Retired(slot)))
                    .cloned()
                    .ok_or_else(|| Error::NoEmptySlots(yubikey.serial()))?
            }
        };

        let pin_policy = self.pin_policy.unwrap_or(DEFAULT_PIN_POLICY);
        let touch_policy = self.touch_policy.unwrap_or(DEFAULT_TOUCH_POLICY);
        let force = self.force;

        eprintln!("{}", fl!("builder-gen-key"));

        // No need to ask for users to enter their PIN if the PIN policy requires it,
        // because here we _always_ require them to enter their PIN in order to access the
        // protected management key (which is necessary in order to generate identities).
        key::manage(yubikey)?;

        // If forcing overwrite, delete the old certificate first to avoid conflicts
        if force {
            let _ = Certificate::delete(yubikey, SlotId::Retired(slot));
        }

        // Generate a new key in the selected slot.
        let generated = yubikey_generate(
            yubikey,
            SlotId::Retired(slot),
            AlgorithmId::EccP256,
            pin_policy,
            touch_policy,
        )?;

        // Convert SubjectPublicKeyInfoOwned to Ref by re-parsing from DER
        let generated_der = generated.to_der().map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?;
        let generated_ref = spki::SubjectPublicKeyInfoRef::try_from(&generated_der[..])
            .map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?;
        let recipient = Recipient::PivP256(
            piv_p256::Recipient::from_spki(generated_ref).expect("YubiKey generates a valid pubkey"),
        );
        let stub = Stub::new(yubikey.serial(), slot, &recipient);

        eprintln!();
        eprintln!("{}", fl!("builder-gen-cert"));

        // Pick a random serial for the new self-signed certificate.
        let mut serial_bytes = [0u8; 20];
        // Use getrandom directly to avoid rand_core version conflicts
        getrandom::getrandom(&mut serial_bytes).map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?;
        // Ensure the serial number is positive by clearing the high bit of the first byte
        // X.509 serial numbers must be positive integers in DER encoding
        serial_bytes[0] &= 0x7F;
        let serial = SerialNumber::new(&serial_bytes).map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?;

        let name = self
            .name
            .unwrap_or(format!("age identity {}", hex::encode(stub.tag)));

        if let PinPolicy::Always = pin_policy {
            // We need to enter the PIN again.
            let pin = Password::new()
                .with_prompt(fl!(
                    "plugin-enter-pin",
                    yubikey_serial = yubikey.serial().to_string(),
                ))
                .report(true)
                .interact()?;
            yubikey.verify_pin(pin.as_bytes())?;
        }
        if let TouchPolicy::Never = touch_policy {
            // No need to touch YubiKey
        } else {
            eprintln!("{}", fl!("builder-touch-yk"));
        }

        // Build the subject name
        use x509_cert::attr::AttributeTypeAndValue;
        use x509_cert::name::RelativeDistinguishedName;
        use der::asn1::SetOfVec;
        let rdns = vec![
            RelativeDistinguishedName::from(SetOfVec::try_from(vec![AttributeTypeAndValue {
                oid: const_oid::db::rfc4519::O,
                value: der::Any::from(Utf8StringRef::new(BINARY_NAME).map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?),
            }]).map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?),
            RelativeDistinguishedName::from(SetOfVec::try_from(vec![AttributeTypeAndValue {
                oid: const_oid::db::rfc4519::OU,
                value: der::Any::from(Utf8StringRef::new(env!("CARGO_PKG_VERSION")).map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?),
            }]).map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?),
            RelativeDistinguishedName::from(SetOfVec::try_from(vec![AttributeTypeAndValue {
                oid: const_oid::db::rfc4519::CN,
                value: der::Any::from(Utf8StringRef::new(&name).map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?),
            }]).map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?),
        ];
        let subject = Name::hazmat_from_rdn_sequence(RdnSequence::from(rdns));

        // Set validity period (10 years)
        let not_before = x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_unix_duration(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap())
                .map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?
        );
        let not_after = x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_unix_duration(
                (std::time::SystemTime::now() + std::time::Duration::from_secs(10 * 365 * 24 * 60 * 60))
                    .duration_since(std::time::UNIX_EPOCH).unwrap()
            ).map_err(|_| Error::YubiKey(yubikey::Error::KeyError))?
        );
        let validity = Validity::new(not_before, not_after);

        // Encode PIN and touch policies as certificate extension
        // Per PIV attestation spec: https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
        struct PolicyExtension {
            pin_policy: PinPolicy,
            touch_policy: TouchPolicy,
        }

        impl const_oid::AssociatedOid for PolicyExtension {
            const OID: const_oid::ObjectIdentifier = crate::util::POLICY_EXTENSION_OID;
        }

        impl der::Encode for PolicyExtension {
            fn encoded_len(&self) -> der::Result<der::Length> {
                // Just 2 raw bytes - the Extension struct will wrap them in an OCTET STRING
                Ok(der::Length::new(2))
            }

            fn encode(&self, writer: &mut impl der::Writer) -> der::Result<()> {
                let pin_byte = match self.pin_policy {
                    PinPolicy::Never => 0x01u8,
                    PinPolicy::Once => 0x02u8,
                    PinPolicy::Always => 0x03u8,
                    PinPolicy::Default => 0x02u8,
                };
                let touch_byte = match self.touch_policy {
                    TouchPolicy::Never => 0x01u8,
                    TouchPolicy::Always => 0x02u8,
                    TouchPolicy::Cached => 0x03u8,
                    TouchPolicy::Default => 0x02u8,
                };
                // Write just the 2 raw bytes - Extension struct handles OCTET STRING wrapping
                writer.write(&[pin_byte, touch_byte])
            }
        }

        impl x509_cert::ext::AsExtension for PolicyExtension {
            fn critical(&self, _subject: &x509_cert::name::Name, _extensions: &[x509_cert::ext::Extension]) -> bool {
                false
            }
        }

        let policy_ext = PolicyExtension {
            pin_policy,
            touch_policy,
        };

        let cert = Certificate::generate_self_signed::<_, p256::NistP256>(
            yubikey,
            SlotId::Retired(slot),
            serial,
            validity,
            subject,
            generated,
            |builder| {
                builder.add_extension(&policy_ext)
                    .map_err(|_| der::Error::from(der::ErrorKind::Failed))
            },
        )?;

        let metadata = Metadata::extract(yubikey, slot, &cert, false).unwrap();

        Ok((
            Stub::new(yubikey.serial(), slot, &recipient),
            recipient,
            metadata,
        ))
    }
}
