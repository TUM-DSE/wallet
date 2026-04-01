use super::PALContext;

pub trait ProcessRuntimePrint {
    fn pal_svsm_debug_print(&mut self) -> bool;
}


impl ProcessRuntimePrint for PALContext {
    /// Print debug message from the trustlet
    ///
    /// This function expects that the trustlet calls this function with each character,
    /// and the final character is 0
    ///
    /// Register arguments:
    /// * rax: monitor call code (0x4FFFFFFD)
    /// * rbx: character to print
    ///
    /// Return:
    /// * no return value
    fn pal_svsm_debug_print(&mut self) -> bool {
        let c = self.vmsa.rbx;
        if self.string_pos < 255{
            self.string_buf[self.string_pos] = c as u8;
            self.string_pos += 1;
        } else {
            log::info!("Trustlet Debug Message to long");
            let debug_string = str::from_utf8(&self.string_buf).unwrap();
            log::info!(" [Trustlet](partial) {}", debug_string);
            self.string_pos = 0;
            self.string_buf = [0;256];
        }
        if c == 0 {
            let debug_string = str::from_utf8(&self.string_buf).unwrap();
            log::info!(" [Trustlet] {}", debug_string);
            self.string_pos = 0;
            self.string_buf = [0;256];
        }
        true
    }

}
