use crate::opt::CcacheDumpOpt;

pub(crate) fn dump(opt: CcacheDumpOpt) {
    if let Err(e) = libkrimes::ccache::dump(opt.common.name.as_deref()) {
        println!("Error: {e:?}");
    }
}
