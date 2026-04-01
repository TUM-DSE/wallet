// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

use crate::MonitorError;
extern "Rust" {
    fn wallet_get_regular_report(buffer: &mut [u8]) -> usize;
}

pub fn get_regular_report(buffer: &mut [u8]) -> Result<usize, MonitorError> {
    let size = unsafe { wallet_get_regular_report(buffer) };
    match size {
        0 => Err(MonitorError::report_failed()),
        _ => Ok(size)
    }
}

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
pub struct SnpReportResponse {
    status: u32,
    report_size: u32,
    _reserved: [u8; 24],
    report: AttestationReport,
}


#[allow(dead_code)]
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum SnpReportResponseStatus {
    Success = 0,
    InvalidParameters = 0x16,
    InvalidKeySelection = 0x27,
}

impl SnpReportResponse {
    /// Validate the [SnpReportResponse] fields
    pub fn validate(&self) -> Result<(), MonitorError> {
        if self.status != SnpReportResponseStatus::Success as u32 {
            return Err(MonitorError::report_invalid());
        }

        if self.report_size != size_of::<AttestationReport>() as u32 {
            return Err(MonitorError::report_format_invalid());
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
