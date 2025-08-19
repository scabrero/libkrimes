use crate::opt::InitCredsOpt;
use tracing::error;

pub(crate) async fn acquire(opt: InitCredsOpt) {
    // TODO realm from krb5.conf if not given in the principal name
    let (username, realm) = match opt.principal.rsplit_once('@') {
        Some(v) => v,
        None => {
            error!(
                "Principal name '{}' does not contain realm part",
                opt.principal
            );
            return;
        }
    };

    // Ask password if not given
    let passphrase = match opt.password {
        Some(p) => p,
        None => rpassword::prompt_password(format!("Enter password for {}: ", opt.principal))
            .expect("Failed to read password"),
    };

    let clock_skew = None;
    let ccache_name = opt.ccache_name.as_deref();

    match libkrimes::client::get_tgt(username, realm, &passphrase).await {
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
