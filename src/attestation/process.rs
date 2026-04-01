use crate::process_manager::process::TrustedProcess;

#[allow(dead_code)]
pub fn attest_process() -> bool {
    log::info!("attest(): Attesting Monitor");
    true
}

#[allow(dead_code)]
pub fn hash_process(_process: &mut TrustedProcess) {
    log::info!("Hash of Process is: 0");
    //process.hash = [0u8;32];

}
