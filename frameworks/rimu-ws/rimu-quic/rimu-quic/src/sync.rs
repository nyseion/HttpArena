//! The shared and atomic types that the crate uses.

pub(crate) use alloc::sync::Arc;
pub(crate) use core::sync::atomic::AtomicU32;
#[cfg(test)]
pub(crate) use core::sync::atomic::AtomicU64;
