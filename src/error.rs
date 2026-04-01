use core::fmt;

#[derive(Debug, Clone, Copy)]
pub enum MonitorErrorType {
    Unsupported,
    Unknown,
    InvalidParameters,
    PvalidateFailed,
    ReportFailed,
    ReportInvalid,
    ReportFormatInvalid,

}

#[derive(Debug, Clone)]
pub struct MonitorError(pub MonitorErrorType);

macro_rules! impl_monitor_err {
    ($name:ident, $v:ident) => {
        pub fn $name() -> Self {
            Self(MonitorErrorType::$v)
        }
    };
}

#[allow(dead_code)]
impl MonitorError {
    impl_monitor_err!(unsupported, Unsupported);
    impl_monitor_err!(unknown, Unknown);
    impl_monitor_err!(invalid_params, InvalidParameters);
    impl_monitor_err!(validate_failed, PvalidateFailed);
    impl_monitor_err!(report_failed, ReportFailed);
    impl_monitor_err!(report_invalid, ReportInvalid);
    impl_monitor_err!(report_format_invalid, ReportFormatInvalid);
}

impl fmt::Display for MonitorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Monitor error encounterd: {:?}", self.0)
    }
}
