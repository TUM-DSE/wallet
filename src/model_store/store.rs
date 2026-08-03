extern crate alloc;
use core::cell::UnsafeCell;
use alloc::vec::Vec;
use crate::model_store::AllocationRange;

pub trait StoreTrait {
    fn empty() -> Self;
    fn is_empty(&self) -> bool;
    fn set_empty(&mut self);
    fn cmp(&self, index: [u8; 64]) -> bool;
}

#[derive(Debug)]
pub struct Store<T: StoreTrait> {
    data: UnsafeCell<Vec<T>>
}

unsafe impl<T: StoreTrait> Sync for Store<T> {}

impl<T: StoreTrait> Store<T> {
    pub const fn new() -> Self {
        Self {
            data: UnsafeCell::new(Vec::new()),
        }
    }
    pub fn init(&self, size: u32) {
        for _ in 0..size {
            let e = T::empty();
            self.push(e);
        }
    }
    pub fn insert(&self, p: T) -> i64 {
        let ptr: &mut Vec<T> = unsafe { self.data.get().as_mut().unwrap() };
        for i in 0..(ptr.len()) {
            if ptr[i].is_empty() {
                ptr[i] = p;
                return i.try_into().unwrap();
            }
        }
        return -1;
    }
    pub fn get(&self, id: usize) -> &mut T {
        let ptr = unsafe { self.data.get().as_mut().unwrap() };
        &mut ptr[id]
    }
    /// Number of slots; get() panics beyond this, so callers taking
    /// ids from an untrusted source must bounds-check first.
    pub fn len(&self) -> usize {
        let ptr = unsafe { self.data.get().as_mut().unwrap() };
        ptr.len()
    }
    #[allow(dead_code)]
    pub fn delete(&self, id: usize) {
        let ptr: &mut Vec<T> = unsafe { self.data.get().as_mut().unwrap() };
        ptr[id].set_empty();
    }
    pub fn push(&self, data: T) {
        let ptr: &mut Vec<T> = unsafe { self.data.get().as_mut().unwrap() };
        ptr.push(data);
    }

    pub fn find(&self, index: [u8; 64]) -> i64 {
        let ptr: &mut Vec<T> = unsafe { self.data.get().as_mut().unwrap() };
        for i in 0..(ptr.len()) {
            if !ptr[i].is_empty() {
                if ptr[i].cmp(index) {
                    return i.try_into().unwrap();
                }
            }
        }
        return -1;
    }
}

#[derive(Debug)]
pub struct StoreEntry {
    pub measurement: [u8; 64],
    pub data: AllocationRange,
    pub real_size: u64,
    pub state: bool,
}

impl StoreTrait for StoreEntry {
    fn empty() -> Self {
        Self {
            state: true,
            data: AllocationRange(0,0),
            real_size: 0,
            measurement: [0; 64],
        }
    }
    fn is_empty(&self) -> bool {
        return self.state;
    }
    fn set_empty(&mut self) {
        self.state = true;
    }

    fn cmp(&self, index: [u8; 64]) -> bool {
        self.measurement == index
    }
}
