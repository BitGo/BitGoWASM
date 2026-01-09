mod bip32;
mod ecpair;
mod error;
mod message;

pub use bip32::WasmBIP32;
pub use ecpair::WasmECPair;
pub use error::WasmBip32Error;

// Provide a no-op critical section implementation for single-threaded WASM
use critical_section::RawRestoreState;

struct SingleThreadedCs;
critical_section::set_impl!(SingleThreadedCs);

unsafe impl critical_section::Impl for SingleThreadedCs {
    unsafe fn acquire() -> RawRestoreState {
        // WASM is single-threaded, no actual locking needed
    }

    unsafe fn release(_restore_state: RawRestoreState) {
        // WASM is single-threaded, no actual unlocking needed
    }
}
