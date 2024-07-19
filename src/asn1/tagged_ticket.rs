use super::principal_name::PrincipalName;
use super::realm::Realm;
use super::{enc_ticket_part::EncTicketPart, encrypted_data::EncryptedData};
use der::{Decode, DecodeValue, Encode, EncodeValue, FixedTag, Sequence, Tag, TagNumber};

/// ```text
/// Ticket          ::= [APPLICATION 1] SEQUENCE {
///         tkt-vno         [0] INTEGER (5),
///         realm           [1] Realm,
///         sname           [2] PrincipalName,
///         enc-part        [3] EncryptedData -- EncTicketPart
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct TicketInner {
    #[asn1(context_specific = "0")]
    pub(crate) tkt_vno: i8,
    #[asn1(context_specific = "1")]
    pub(crate) realm: Realm,
    #[asn1(context_specific = "2")]
    pub(crate) sname: PrincipalName,
    #[asn1(context_specific = "3")]
    pub(crate) enc_part: EncryptedData,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Ticket {
    pub(crate) inner: TicketInner,
}

impl Ticket {
    pub fn new(tkt_vno: i8, realm: Realm, sname: PrincipalName, enc_part: EncryptedData) -> Self {
        let inner = TicketInner {
            tkt_vno,
            realm,
            sname,
            enc_part,
        };
        Self { inner }
    }

    pub fn tkt_vno(&self) -> i8 {
        self.inner.tkt_vno
    }

    pub fn realm(&self) -> &Realm {
        &self.inner.realm
    }

    pub fn sname(&self) -> &PrincipalName {
        &self.inner.sname
    }

    pub fn enc_part(&self) -> &EncryptedData {
        &self.inner.enc_part
    }
}

impl FixedTag for Ticket {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::N1,
    };
}

impl<'a> DecodeValue<'a> for Ticket {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let inner: TicketInner = TicketInner::decode(reader)?;
        Ok(Self { inner })
    }
}

impl<'a> EncodeValue for Ticket {
    fn value_len(&self) -> der::Result<der::Length> {
        self.inner.encoded_len()
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.inner.encode(encoder)?;
        Ok(())
    }
}
