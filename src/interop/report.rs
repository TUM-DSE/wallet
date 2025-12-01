
use crate::SvsmReqError;
extern "Rust" {
    fn wallet_get_regular_report(buffer: &mut [u8]) -> Result<usize, SvsmReqError>;
}

pub fn get_regular_report(buffer: &mut [u8]) -> Result<usize, SvsmReqError> {
    unsafe { wallet_get_regular_report(buffer) }
}




pub const USER_DATA_SIZE: usize = 64;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct Signature {
    r: [u8; 72],
    s: [u8; 72],
    reserved: [u8; 368],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct TcbVersion {
    raw: u64,
}


#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SnpReportRequest {
    user_data: [u8; USER_DATA_SIZE],
    vmpl: u32,
    flags: u32,
    rsvd: [u8; 24],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SnpReportResponse {
    status: u32,
    report_size: u32,
    _reserved: [u8; 24],
    report: AttestationReport,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum SnpReportResponseStatus {
    Success = 0,
    InvalidParameters = 0x16,
    InvalidKeySelection = 0x27,
}

impl SnpReportResponse {
    pub fn try_from_as_ref(buffer: &[u8]) -> Result<&Self, SvsmReqError> {
        let buffer = buffer
            .get(..size_of::<Self>())
            .ok_or_else(SvsmReqError::invalid_parameter)?;

        // SAFETY: SnpReportResponse has no invalid representations, as it is
        // comprised entirely of integer types. It is repr(packed), so its
        // required alignment is simply 1. We have checked the size, so this
        // is entirely safe.
        let response = unsafe { &*buffer.as_ptr().cast::<Self>() };
        Ok(response)
    }

    /// Validate the [SnpReportResponse] fields
    pub fn validate(&self) -> Result<(), SvsmReqError> {
        if self.status != SnpReportResponseStatus::Success as u32 {
            return Err(SvsmReqError::invalid_request());
        }

        if self.report_size != size_of::<AttestationReport>() as u32 {
            return Err(SvsmReqError::invalid_format());
        }

        Ok(())
    }

    pub fn get_report(&self) -> &AttestationReport {
          &self.report
    }

    pub fn get_report_size(&self) -> u32 {
          self.report_size
    }
}






#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct AttestationReport {
    version: u32,
    guest_svn: u32,
    policy: u64,
    family_id: [u8; 16],
    image_id: [u8; 16],
    vmpl: u32,
    signature_algo: u32,
    platform_version: TcbVersion,
    platform_info: u64,
    flags: u32,
    reserved0: u32,
    report_data: [u8; 64],
    measurement: [u8; 48],
    host_data: [u8; 32],
    id_key_digest: [u8; 48],
    author_key_digest: [u8; 48],
    report_id: [u8; 32],
    report_id_ma: [u8; 32],
    reported_tcb: TcbVersion,
    reserved1: [u8; 24],
    chip_id: [u8; 64],
    reserved2: [u8; 192],
    signature: Signature,
}
