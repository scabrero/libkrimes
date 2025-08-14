use std::net::SocketAddr;

use crate::error::KrbError;
use hickory_resolver::{proto::rr::rdata::SRV, Resolver};
use tracing::error;

pub enum Transport {
    Tcp(Vec<SocketAddr>),
    //TODO Https(Vec<SocketAddr>),
}

pub async fn get_kdc_addr(realm: &str) -> Result<Transport, KrbError> {
    if let Some(addr) = option_env!("LIBKRIMES_TEST_KDC_ADDRESS") {
        let addr: SocketAddr = addr.parse().expect("Failed to parse");
        return Ok(Transport::Tcp(vec![addr]));
    }

    // TODO krb5.conf static mappings
    // TODO krb5.conf HTTPS proxy for [MS-KKDCP]

    // TODO Only if dns_lookup_kdc = true
    let addrs = get_kdc_addr_from_dns(realm).await?;
    Ok(Transport::Tcp(addrs))
}

pub async fn get_kdc_addr_from_dns(realm: &str) -> Result<Vec<SocketAddr>, KrbError> {
    let query = format!("_kerberos._tcp.{realm}");
    let resolver = Resolver::builder_tokio()
        .map_err(|e| {
            error!(?e, "Failed to get resolver");
            KrbError::DnsError
        })?
        .build();
    let response = resolver.srv_lookup(&query).await.map_err(|e| {
        error!(?e, ?query, "Failed to resolve");
        KrbError::DnsError
    })?;

    // Order by priority, then weight
    let mut targets: Vec<SRV> = response.iter().cloned().collect();
    targets.sort_by(|a, b| {
        let prio = a.priority().cmp(&b.priority());
        if prio.is_eq() {
            a.weight().cmp(&b.weight())
        } else {
            prio
        }
    });

    // targets to SocketAddr
    let mut ret: Vec<SocketAddr> = vec![];
    for r in &targets {
        let lookup = resolver
            .lookup_ip(r.target().to_string())
            .await
            .map_err(|e| error!(?e, "Failed to resolve"))
            .ok();

        if let Some(lookup) = lookup {
            let a: Vec<SocketAddr> = lookup
                .iter()
                .map(|v| SocketAddr::new(v, r.port()))
                .collect();
            ret.extend(a);
        }
    }
    Ok(ret)
}
