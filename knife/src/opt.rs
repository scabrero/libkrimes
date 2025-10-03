use clap::Args;

#[derive(Debug, Clone, Args)]
pub(crate) struct CcacheCommonOpt {
    #[clap(short, long)]
    pub(crate) name: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct CcacheDumpOpt {
    #[clap(flatten)]
    pub(crate) common: CcacheCommonOpt,
    #[clap(short = 'x', long, action = clap::ArgAction::Set)]
    pub(crate) hexdump: Option<bool>,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct InitCredsOpt {
    #[clap(short = 'c', long)]
    pub(crate) ccache_name: Option<String>,
    #[clap(short = 'f', long, action = clap::ArgAction::Set)]
    pub(crate) forwardable: Option<bool>,
    #[clap(short = 'p', long, action = clap::ArgAction::Set)]
    pub(crate) password: Option<String>,
    pub(crate) principal: String,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct AcquireCredsOpt {
    #[clap(short = 'c', long)]
    pub(crate) ccache_name: Option<String>,
    #[clap(short = 'f', long, action = clap::ArgAction::Set)]
    pub(crate) forwardable: Option<bool>,
    #[clap(short = 'S', long, default_value = "HOST")]
    pub(crate) service: String,
    pub(crate) hostname: String,
}
