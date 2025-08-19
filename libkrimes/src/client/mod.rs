mod discovery;

use crate::error::KrbError;
use crate::proto::{
    DerivedKey, EncTicket, KdcReplyPart, KerberosReply, KerberosRequest, Name, PreauthErrorReply,
};
use crate::KerberosTcpCodec;
use futures::SinkExt;
use futures::StreamExt;
use std::time::{Duration, SystemTime};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::error;

async fn do_as_req(
    username: &str,
    realm: &str,
    passphrase: &str,
    pa_error: Option<PreauthErrorReply>,
    stream: &mut Framed<TcpStream, KerberosTcpCodec>,
) -> Result<KerberosReply, KrbError> {
    let now = SystemTime::now();
    let name = Name::principal(username, realm);
    let mut builder = KerberosRequest::as_builder(
        &name,
        Name::service_krbtgt(realm),
        now + Duration::from_secs(3600),
    )
    .renew_until(Some(now + Duration::from_secs(86400 * 7)));

    if let Some(pa_error) = pa_error {
        let PreauthErrorReply {
            service,
            pa_data,
            stime: _,
        } = pa_error;

        if service != Name::service_krbtgt(realm) {
            return Err(KrbError::PreauthNotFromTgt);
        }

        let einfo2 = pa_data
            .etype_info2
            .last()
            .ok_or(KrbError::PreauthMissingEtypeInfo2)?;

        let seconds_since_epoch = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to convert value");

        let base_key = DerivedKey::from_etype_info2(einfo2, realm, username, passphrase, 1)?;

        builder = builder.preauth_enc_ts(&pa_data, seconds_since_epoch, &base_key)?;
    }

    let as_req = builder.build();

    // Write a request
    stream.send(as_req).await.map_err(|e| {
        error!(?e, "Failed to transmit request");
        KrbError::IoError
    })?;

    stream
        .next()
        .await
        .ok_or_else(|| {
            error!("Failed to read from stream");
            KrbError::IoError
        })?
        .map_err(|e| {
            error!(?e, "No messages available in the stream");
            KrbError::IoError
        })
}

pub async fn get_tgt(
    username: &str,
    realm: &str,
    passphrase: &str,
) -> Result<(Name, EncTicket, KdcReplyPart), KrbError> {
    match self::discovery::get_kdc_addr(realm).await? {
        discovery::Transport::Tcp(addrs) => {
            for addr in &addrs {
                match TcpStream::connect(addr).await {
                    Ok(stream) => return get_tgt_tcp(username, realm, passphrase, stream).await,
                    Err(e) => error!(?e, "Failed to connect"),
                }
            }
        }
    }

    Err(KrbError::KdcNotFound)
}

pub async fn get_tgt_tcp(
    username: &str,
    realm: &str,
    passphrase: &str,
    stream: TcpStream,
) -> Result<(Name, EncTicket, KdcReplyPart), KrbError> {
    let mut stream = Framed::new(stream, KerberosTcpCodec::default());

    let response = do_as_req(username, realm, passphrase, None, &mut stream).await?;
    match response {
        KerberosReply::AS(reply) => {
            let name = reply.name().to_owned();
            let ticket = reply.ticket().to_owned();
            let kdc_reply = reply.kdc_reply_part(username, realm, passphrase)?;
            Ok((name, ticket, kdc_reply))
        }
        KerberosReply::ERR(err) => {
            error!(?err, "Failed to get initial credentials");
            Err(KrbError::AsError)
        }
        KerberosReply::PA(err) => {
            let response = do_as_req(username, realm, passphrase, Some(err), &mut stream).await?;
            match response {
                KerberosReply::AS(reply) => {
                    let name = reply.name().to_owned();
                    let ticket = reply.ticket().to_owned();
                    let kdc_reply = reply.kdc_reply_part(username, realm, passphrase)?;
                    Ok((name, ticket, kdc_reply))
                }
                KerberosReply::ERR(err) => {
                    error!(?err, "Failed to get initial credentials");
                    Err(KrbError::AsError)
                }
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
}
