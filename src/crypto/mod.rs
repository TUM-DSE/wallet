#[repr(C)]
#[derive(Debug, Default)]
#[derive(Copy, Clone)]
pub struct KeyPair
{
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

#[cfg(feature = "rustcrypto")]
pub fn sha512_single(buf: &[u8], h: &mut [u8]) {
    let hash = Sha512::digest(buf);
    h.copy_from_slice(&hash);
}

#[allow(dead_code)]
extern "C" {
    pub fn gen_keys() -> *mut KeyPair;
    pub fn get_key_size() -> u32;
    pub fn get_keys() -> *mut KeyPair;
    pub fn encrypt
        (
            dst: *mut u8,
            src: *mut u8,
            len: u32,
            nonce: *mut u8,
            pub_key_recipient: *mut u8,
            priv_key_sender: *mut u8
        ) -> u32;

    pub fn decrypt(
        dst: *mut u8,
        src: *mut u8,
        len: u32,
        nonce: *mut u8,
        pub_key_sender: *mut u8,
        priv_key_recipient: *mut u8
        ) -> u32;

    pub fn my_SHA512(buff: *mut u8, buff_len: u32, hash: *mut u8) -> i32;
    pub fn my_Hacl_Ed25519_sign(msg: *const u8, msg_len: u32, private_key: *const u8, signature: *mut u8) -> i32;
    pub fn sha512_create() -> u64;
    pub fn sha512_update(buff: *mut u8, msg_len: u32, state: u64);
    pub fn sha512_digest(hash: *mut u8, state: u64);
    pub fn get_cycles() -> u64;

}
