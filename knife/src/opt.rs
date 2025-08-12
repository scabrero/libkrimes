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
