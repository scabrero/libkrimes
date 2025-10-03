mod cc_dir;
mod cc_file;

#[cfg(feature = "keyring")]
mod cc_keyring;

use crate::asn1::constants::encryption_types::EncryptionType as Asn1EncryptionType;
use crate::asn1::constants::PrincipalNameType;
use crate::asn1::encrypted_data::EncryptedData as Asn1EncryptedData;
use crate::asn1::tagged_ticket::TaggedTicket as Asn1TaggedTicket;
use crate::asn1::tagged_ticket::Ticket as Asn1Ticket;
use crate::error::KrbError;
use crate::proto::{EncTicket, EncryptedData, KdcReplyPart, Name, SessionKey};
use binrw::{binread, binwrite};
use der::asn1::OctetString;
use der::Decode;
use der::Encode;
use std::env;
use std::fmt;
use std::time::Duration;
use std::time::SystemTime;
use tracing::{debug, error, trace};
use uzers::get_current_uid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/* TODO:
 *   - Handle cache conf entries. CredentialCache::new() could take a KV pair collection
 *   - Handle multiple credentials. The time offset is global, as the primary name. The
 *     there is a list of credentials, the primary name usually matches the first's
 *     credential 'client' field.
 */

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct DataComponent {
    #[bw(try_calc(u32::try_from(value.len())))]
    value_len: u32,
    #[br(count = value_len)]
    value: Vec<u8>,
}

impl fmt::Display for DataComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.value {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl TryInto<Asn1TaggedTicket> for &DataComponent {
    type Error = KrbError;
    fn try_into(self) -> Result<Asn1TaggedTicket, Self::Error> {
        let ticket = Asn1TaggedTicket::from_der(&self.value).map_err(|e| {
            error!(?e, "Failed to decode");
            KrbError::DerDecodeTaggedTicket
        })?;
        Ok(ticket)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct PrincipalV4 {
    name_type: u32,
    #[bw(try_calc(u32::try_from(components.len())))]
    components_count: u32,
    realm: DataComponent,
    #[br(count = components_count)]
    components: Vec<DataComponent>,
}

impl fmt::Display for PrincipalV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name: Name = self.try_into().map_err(|e| {
            error!(
                ?e,
                "Failed to convert: name_type={:?}, components={:?}, realm={:?}",
                self.name_type,
                self.components,
                self.realm
            );
            fmt::Error
        })?;
        write!(f, "{}", name)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
enum Principal {
    V4(PrincipalV4),
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Principal::V4(v4) => {
                let name: Name = v4.try_into().map_err(|_| fmt::Error)?;
                write!(f, "{name}")
            }
        }
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct KeyBlockV4 {
    enc_type: u16,
    data: DataComponent,
}

impl fmt::Display for KeyBlockV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.enc_type, self.data)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
enum KeyBlock {
    V4(KeyBlockV4),
}

impl fmt::Display for KeyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyBlock::V4(v4) => write!(f, "{}", v4),
        }
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct Address {
    addr_type: u16,
    data: DataComponent,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] ", self.addr_type)?;
        for v in &self.data.value {
            write!(f, "{:02X}", v)?;
        }
        writeln!(f)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct Addresses {
    #[bw(try_calc(u32::try_from(addresses.len())))]
    count: u32,
    #[br(count = count)]
    addresses: Vec<Address>,
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct AuthDataComponent {
    ad_type: u16,
    data: DataComponent,
}

impl fmt::Display for AuthDataComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.ad_type)?;
        for v in &self.data.value {
            write!(f, "{:02X}", v)?;
        }
        writeln!(f)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct AuthData {
    #[bw(try_calc(u32::try_from(auth_data.len())))]
    count: u32,
    #[br(count = count)]
    auth_data: Vec<AuthDataComponent>,
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
enum Credential {
    V4(CredentialV4),
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct CredentialV4 {
    client: PrincipalV4,
    server: PrincipalV4,
    keyblock: KeyBlock,
    authtime: u32,
    starttime: u32,
    endtime: u32,
    renew_till: u32,
    is_skey: u8,
    ticket_flags: u32,
    addresses: Addresses,
    authdata: AuthData,
    ticket: DataComponent,
    second_ticket: DataComponent,
}

impl CredentialV4 {
    pub fn new(
        client: &Name,
        ticket: &EncTicket,
        enc_part: &KdcReplyPart,
    ) -> Result<Self, KrbError> {
        let cred: Self = CredentialV4 {
            client: client.try_into()?,
            server: (&enc_part.server).try_into()?,
            keyblock: KeyBlock::V4((&enc_part.key).try_into()?),
            authtime: enc_part
                .auth_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| KrbError::InsufficientData)?
                .as_secs() as u32,
            starttime: if let Some(start_time) = enc_part.start_time {
                start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|_| KrbError::InsufficientData)?
                    .as_secs() as u32
            } else {
                0u32
            },
            endtime: enc_part
                .end_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| KrbError::InsufficientData)?
                .as_secs() as u32,
            renew_till: if let Some(till) = enc_part.renew_until {
                till.duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|_| KrbError::InsufficientData)?
                    .as_secs() as u32
            } else {
                0u32
            },
            is_skey: 0u8,
            ticket_flags: enc_part.flags.bits().reverse_bits(),
            addresses: Addresses { addresses: vec![] },
            authdata: AuthData { auth_data: vec![] },
            ticket: DataComponent {
                value: match &ticket.enc_part {
                    EncryptedData::Aes256CtsHmacSha196 { kvno: _, data } => {
                        let t = Asn1Ticket {
                            tkt_vno: 5,
                            realm: (&enc_part.server).try_into()?,
                            sname: (&enc_part.server).try_into()?,
                            enc_part: Asn1EncryptedData {
                                etype: Asn1EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                                kvno: Some(1), // TODO Why?
                                cipher: OctetString::new(data.clone())
                                    .map_err(|_| KrbError::DerEncodeOctetString)?,
                            },
                        };
                        let tt = Asn1TaggedTicket::new(t);
                        tt.to_der().map_err(|e| {
                            println!("{e:#?}");
                            KrbError::DerEncodeEncTicketPart
                        })?
                    }
                },
            },
            second_ticket: DataComponent { value: vec![] },
        };
        Ok(cred)
    }
}

impl TryFrom<&Name> for PrincipalV4 {
    type Error = KrbError;

    fn try_from(name: &Name) -> Result<Self, Self::Error> {
        match name {
            Name::Principal { name, realm } => {
                let p: PrincipalV4 = PrincipalV4 {
                    name_type: PrincipalNameType::NtPrincipal as u32,
                    realm: DataComponent {
                        value: realm.as_bytes().into(),
                    },
                    components: vec![DataComponent {
                        value: name.as_bytes().into(),
                    }],
                };
                Ok(p)
            }
            Name::SrvInst {
                service,
                instance,
                realm,
            } => {
                let mut components: Vec<DataComponent> = vec![];
                components.push(DataComponent {
                    value: service.as_bytes().into(),
                });
                let iv: Vec<DataComponent> = instance
                    .iter()
                    .map(|x| DataComponent {
                        value: x.as_bytes().into(),
                    })
                    .collect();
                components.extend(iv);

                let p: PrincipalV4 = PrincipalV4 {
                    name_type: PrincipalNameType::NtSrvInst as u32,
                    realm: DataComponent {
                        value: realm.as_bytes().into(),
                    },
                    components,
                };
                Ok(p)
            }
            _ => Err(KrbError::PrincipalNameInvalidType),
        }
    }
}

impl TryInto<Name> for &PrincipalV4 {
    type Error = KrbError;

    fn try_into(self) -> Result<Name, Self::Error> {
        let name_type: i32 = self.name_type as i32;
        let name_type: PrincipalNameType = name_type.try_into().map_err(|err| {
            error!(?err, ?name_type, "invalid principal name type");
            KrbError::PrincipalNameInvalidType
        })?;

        match name_type {
            PrincipalNameType::NtPrincipal => {
                let n: Name = Name::Principal {
                    name: self
                        .components
                        .iter()
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())
                        .collect::<Vec<String>>()
                        .join(""),
                    realm: String::from_utf8_lossy(self.realm.value.as_slice()).to_string(),
                };
                Ok(n)
            }
            PrincipalNameType::NtSrvInst => {
                let n: Name = Name::SrvInst {
                    service: self
                        .components
                        .first()
                        .ok_or(KrbError::NameNotPrincipal)
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())?,
                    instance: self
                        .components
                        .get(1..)
                        .ok_or(KrbError::NameNotPrincipal)?
                        .iter()
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())
                        .collect::<Vec<String>>(),
                    realm: String::from_utf8_lossy(self.realm.value.as_slice()).to_string(),
                };
                Ok(n)
            }
            PrincipalNameType::NtSrvHst => {
                let n: Name = Name::SrvHst {
                    service: self
                        .components
                        .first()
                        .ok_or(KrbError::NameNotPrincipal)
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())?,
                    host: self
                        .components
                        .get(1..)
                        .ok_or(KrbError::NameNotPrincipal)?
                        .iter()
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())
                        .collect::<Vec<String>>()
                        .join(""),
                    realm: String::from_utf8_lossy(self.realm.value.as_slice()).to_string(),
                };
                Ok(n)
            }
            _ => Err(KrbError::PrincipalNameInvalidType),
        }
    }
}

impl TryFrom<&SessionKey> for KeyBlockV4 {
    type Error = KrbError;

    fn try_from(value: &SessionKey) -> Result<Self, Self::Error> {
        match value {
            SessionKey::Aes256CtsHmacSha196 { k } => Ok(KeyBlockV4 {
                enc_type: 0x12,
                data: DataComponent { value: k.to_vec() },
            }),
        }
    }
}

/// Order of preference:
/// 1. Given argument
/// 2. Environment variable
/// 3. TODO default_ccache_name from /etc/krb5.conf
/// 4. hardcoded library default: FILE:/tmp/krb5cc_%{uid}
fn parse_ccache_name(ccache: Option<&str>) -> String {
    let uid = get_current_uid().to_string();

    match ccache {
        Some(c) => c.to_string(),
        None => match env::var("KRB5CCNAME") {
            Ok(val) => val,
            _ => "FILE:/tmp/krb5cc_%{uid}".to_string(),
        },
    }
    .replace("%{uid}", uid.as_str())
}

pub trait CredentialCache {
    //const char * (KRB5_CALLCONV *get_name)(krb5_context, krb5_ccache);
    //krb5_error_code (KRB5_CALLCONV *gen_new)(krb5_context, krb5_ccache *);
    fn init(&mut self, name: &Name, clock_skew: Option<Duration>) -> Result<(), KrbError>;
    fn destroy(&mut self) -> Result<(), KrbError>;
    //krb5_error_code (KRB5_CALLCONV *close)(krb5_context, krb5_ccache);

    fn store(
        &mut self,
        name: &Name,
        ticket: &EncTicket,
        kdc_reply: &KdcReplyPart,
    ) -> Result<(), KrbError>;

    #[cfg(debug_assertions)]
    fn dump(&self) -> Result<(), KrbError>;

    //krb5_error_code (KRB5_CALLCONV *retrieve)(krb5_context, krb5_ccache,
    //                                          krb5_flags, krb5_creds *,
    //                                          krb5_creds *);
    //krb5_error_code (KRB5_CALLCONV *get_princ)(krb5_context, krb5_ccache,
    //                                           krb5_principal *);
    //krb5_error_code (KRB5_CALLCONV *get_first)(krb5_context, krb5_ccache,
    //                                           krb5_cc_cursor *);
    //krb5_error_code (KRB5_CALLCONV *get_next)(krb5_context, krb5_ccache,
    //                                          krb5_cc_cursor *, krb5_creds *);
    //krb5_error_code (KRB5_CALLCONV *end_get)(krb5_context, krb5_ccache,
    //                                         krb5_cc_cursor *);
    //krb5_error_code (KRB5_CALLCONV *remove_cred)(krb5_context, krb5_ccache,
    //                                             krb5_flags, krb5_creds *);
    //krb5_error_code (KRB5_CALLCONV *set_flags)(krb5_context, krb5_ccache,
    //                                           krb5_flags);
    //krb5_error_code (KRB5_CALLCONV *get_flags)(krb5_context, krb5_ccache,
    //                                           krb5_flags *);
    //krb5_error_code (KRB5_CALLCONV *ptcursor_new)(krb5_context,
    //                                              krb5_cc_ptcursor *);
    //krb5_error_code (KRB5_CALLCONV *ptcursor_next)(krb5_context,
    //                                               krb5_cc_ptcursor,
    //                                               krb5_ccache *);
    //krb5_error_code (KRB5_CALLCONV *ptcursor_free)(krb5_context,
    //                                               krb5_cc_ptcursor *);
    //krb5_error_code (KRB5_CALLCONV *replace)(krb5_context, krb5_ccache,
    //                                         krb5_principal, krb5_creds **);
    //krb5_error_code (KRB5_CALLCONV *wasdefault)(krb5_context, krb5_ccache,
    //                                            krb5_timestamp *);
    //krb5_error_code (KRB5_CALLCONV *lock)(krb5_context, krb5_ccache);
    //krb5_error_code (KRB5_CALLCONV *unlock)(krb5_context, krb5_ccache);
    //krb5_error_code (KRB5_CALLCONV *switch_to)(krb5_context, krb5_ccache);
}

///
/// ccache_name is in the form type:residual.
/// type is FILE|DIR|KEYRING
/// residual is interpreted by type implementation
pub fn resolve(ccache_name: Option<&str>) -> Result<Box<dyn CredentialCache>, KrbError> {
    let ccache_name = parse_ccache_name(ccache_name);
    trace!(?ccache_name, "Credential cache name");

    if ccache_name.starts_with("FILE:") {
        return cc_file::resolve(ccache_name.as_str());
    }

    if ccache_name.starts_with("DIR:") {
        return cc_dir::resolve(ccache_name.as_str());
    }

    if ccache_name.starts_with("KEYRING:") {
        return cc_keyring::resolve(ccache_name.as_str());
    }

    debug!(?ccache_name, "Unsupported credential cache type");
    Err(KrbError::BadCredentialCacheName)
}

#[cfg(test)]
mod tests {
    use tracing::warn;

    use super::*;
    use std::process::Command;
    #[cfg(feature = "keyring")]
    use std::process::Stdio;

    #[tokio::test]
    async fn test_ccache_file_store() -> Result<(), KrbError> {
        let _ = tracing_subscriber::fmt::try_init();
        if std::env::var("CI").is_ok() {
            // Skip this test in CI, as it requires a KDC running on localhost
            warn!("Skipping test_ccache_file_store in CI");
            return Ok(());
        }

        let (name, ticket, kdc_reply_part) =
            crate::client::get_tgt("testuser", "EXAMPLE.COM", "password").await?;

        let path = "/tmp/krb5cc_krime";
        let ccname = format!("FILE:{path}");
        let mut ccache = super::resolve(Some(ccname.as_str()))?;
        ccache.init(&name, None)?;
        ccache.store(&name, &ticket, &kdc_reply_part)?;
        assert!(std::fs::exists(path).expect("Unable to check if file exists"));

        // TODO load and compare

        // Test MIT can parse the created ccache
        let output = Command::new("klist")
            .arg("-c")
            .arg(ccname.as_str())
            .output()
            .expect("Unable to execute command klist");
        assert!(output.status.success());

        let output = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
        assert!(output.contains("testuser@EXAMPLE.COM"));

        ccache.destroy()?;
        assert!(!std::fs::exists(path).expect("Unable to check if file exists"));

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "keyring")]
    async fn test_ccache_keyring_store() -> Result<(), KrbError> {
        if std::env::var("CI").is_ok() {
            // Skip this test in CI, as it requires a KDC running on localhost
            warn!("Skipping get_tgt in CI");
            return Ok(());
        }

        let ccache_name = "KEYRING:session:abc";
        let ccname = Some(ccache_name);
        let mut ccache = super::resolve(ccname.as_deref())?;

        let (name, ticket, kdc_reply_part) =
            crate::client::get_tgt("testuser", "EXAMPLE.COM", "password").await?;
        ccache.init(&name, None)?;
        ccache.store(&name, &ticket, &kdc_reply_part)?;

        let (name, ticket, kdc_reply_part) =
            crate::client::get_tgt("testuser2", "EXAMPLE.COM", "password").await?;
        ccache.store(&name, &ticket, &kdc_reply_part)?;

        let output = Command::new("klist")
            .stderr(Stdio::null())
            .arg("-c")
            .arg(ccache_name)
            .arg("-A")
            .output()
            .expect("Unable to execute command klist");
        assert!(output.status.success());

        let output = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
        assert!(output.contains("testuser@EXAMPLE.COM"));
        assert!(output.contains("testuser2@EXAMPLE.COM"));

        ccache.destroy()?;

        let output = Command::new("klist")
            .stderr(Stdio::null())
            .arg("-c")
            .arg(ccache_name)
            .arg("-A")
            .output()
            .expect("Unable to execute command klist");
        assert!(output.status.success());

        let output = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
        assert!(!output.contains("testuser@EXAMPLE.COM"));
        assert!(output.contains("testuser2@EXAMPLE.COM"));

        Ok(())
    }

    #[tokio::test]
    async fn test_ccache_api() -> Result<(), KrbError> {
        Ok(())
    }
}
