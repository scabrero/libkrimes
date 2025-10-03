use crate::opt::CcacheDumpOpt;

pub(crate) fn dump(opt: CcacheDumpOpt) {
    let ccname = opt.common.name.as_deref();
    match libkrimes::ccache::resolve(ccname) {
        Ok(ccname) => {
            if let Err(e) = ccname.dump() {
                println!("Dump error: {e:?}");
            }
        }
        Err(e) => println!("Resolve error: {e:?}"),
    }
}
