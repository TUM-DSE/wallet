use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::process_runtime::{ReturnTarget, RETURN_TO_GUEST};
use super::super::PALContext;

pub trait ProcessRuntimeFin {
    fn pal_svsm_finalize(&mut self) -> ReturnTarget;
}

impl ProcessRuntimeFin for PALContext {
    #[cfg(feature = "no_cow")]
    fn pal_svsm_finalize(&mut self) -> ReturnTarget {
        log::info!("Finalize called in No CoW mode");
        RETURN_TO_GUEST
    }
    #[cfg(not(feature = "no_cow"))]
    fn pal_svsm_finalize(&mut self) -> ReturnTarget {
        //Finalize should mark every current page as finalizsed, e.g. read only
        let page_table = self.vmsa.cr3;
        let mut page_table_ref = ProcessPageTableRef::default();
        page_table_ref.set_external_table(page_table);
        /* F4 tripwire: model-store (8) and GPU (9) mappings are SHARED
           subtrees - finalize walking them would rewrite their flags
           (CoW/read-only) for every user. They should never exist at
           finalize time (both attach to running trustlets, and only
           trustlets get them). */
        if page_table_ref.pgd_present(8) || page_table_ref.pgd_present(9) {
            log::warn!("finalize: PML4 slot 8/9 populated at finalize - \
                        shared model/GPU subtree flags are being rewritten");
        }
        page_table_ref.finalize_pages();
        let rip = self.vmsa.rip;
        log::info!("RIP: {:#x?}",rip);
        log::info!("Fin done");
        RETURN_TO_GUEST
    }
}
