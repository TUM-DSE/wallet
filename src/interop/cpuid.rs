
extern "Rust" {
    pub fn wallet_cpuid_table(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> Option<CpuidResult>;
}

#[derive(Clone, Copy, Debug)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub fn cpuid_table(eax: u32) -> Option<CpuidResult> {
    unsafe { wallet_cpuid_table(eax,0,0,0) }
}
pub fn cpuid_table_raw(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> Option<CpuidResult> {
    unsafe { wallet_cpuid_table(eax, ecx, xcr0, xss) }
}
