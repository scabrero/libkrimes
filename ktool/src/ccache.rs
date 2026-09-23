use crate::opt::CcacheDumpOpt;
use libkrimes::ccache::ResolvedCredentialCache;

pub(crate) fn dump(opt: CcacheDumpOpt) {
    let ccache = libkrimes::ccache::resolve(opt.common.name.as_deref()).unwrap();
    match ccache {
        ResolvedCredentialCache::Collection(cccol) => {
            print!(
                "Collection contains {} credential caches\n\n",
                cccol.iter().count()
            );

            if let Ok(primary) = cccol.primary() {
                match primary.name() {
                    Ok(name) => print!("Primary credential cache is {name}\n\n"),
                    Err(e) => print!("Failed to read primary subsidiary name: {:?}", e),
                }
            }

            for cc in cccol.iter() {
                print!("{:?}", cc.dump());
            }
        }
        ResolvedCredentialCache::Subsidiary(cc) => {
            println!("Dumping credential cache {:?}", cc.name());
            if let Err(e) = cc.dump() {
                println!("Error: {e:?}");
            }
        }
    }
}
