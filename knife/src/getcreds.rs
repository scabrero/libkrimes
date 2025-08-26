use crate::opt::GetCredsOpt;
use tracing::error;

pub(crate) async fn acquire(opt: GetCredsOpt) {
    let srvname = &opt.service_name;
    let hostname = &opt.service_name;
    let realm = "";

    match libkrimes::client::get_st(srvname, hostname, realm, principal, ticket, session_key).await
    {
        Err(e) => error!(?e, "Failed to acquire initial credentials"),
        Ok((name, ticket, kdc_reply_part)) => {
            if let Err(e) =
                libkrimes::ccache::store(&name, &ticket, &kdc_reply_part, clock_skew, ccache_name)
            {
                error!(?e, "Failed to store credentials in cache");
            }
        }
    }
}
