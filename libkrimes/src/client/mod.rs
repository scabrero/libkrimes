use crate::error::KrbError;
use crate::proto::{EncTicket, KdcReplyPart, KerberosReply, KerberosRequest, Name};
use std::time::{Duration, SystemTime};
use tracing::error;

fn get_kdc_addr() -> Result<String, KrbError> {
    // TODO
    let kdc_addr = option_env!("LIBKRIMES_TEST_KDC_ADDRESS")
        .unwrap_or("127.0.0.1:55000")
        .to_string();
    Ok(kdc_addr)
}

pub async fn get_tgt(
    username: &str,
    realm: &str,
    passphrase: &str,
) -> Result<(Name, EncTicket, KdcReplyPart), KrbError> {
    use crate::KerberosTcpCodec;
    use futures::SinkExt;
    use futures::StreamExt;
    use tokio::net::TcpStream;
    use tokio_util::codec::Framed;

    let kdc_addr = get_kdc_addr()?;

    let stream = TcpStream::connect(&kdc_addr).await.map_err(|e| {
        error!(?e, ?kdc_addr, "Failed to connect");
        KrbError::IoError
    })?;

    let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

    let now = SystemTime::now();
    let client_name = Name::principal(username, realm);
    let as_req = KerberosRequest::as_builder(
        &client_name,
        Name::service_krbtgt(realm),
        now + Duration::from_secs(3600),
    )
    .renew_until(Some(now + Duration::from_secs(86400 * 7)))
    .build();

    // Write a request
    krb_stream.send(as_req).await.map_err(|e| {
        error!(?e, "Failed to transmit request");
        KrbError::IoError
    })?;

    let response = krb_stream
        .next()
        .await
        .ok_or_else(|| {
            error!("Failed to read from stream");
            KrbError::IoError
        })?
        .map_err(|e| {
            error!(?e, "No messages available in the stream");
            KrbError::IoError
        })?;

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
