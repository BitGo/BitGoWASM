mod zcash;

use prost::Message;
use std::cell::RefCell;

// Include protobuf generated code from build.rs / prost-build.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/bitgo.privacy_coin.rs"));
}

use proto::{
    response, AppendCommitmentsRequest, FromFrontierRequest, Response, TreeInfo, TruncateRequest,
    WasmError,
};

// ---------------------------------------------------------------------------
// Per-instance state
//
// `wasm32-unknown-unknown` is single-threaded; `thread_local!` is safe here.
// Each Java `ShieldedMerkleTree` owns its own Chicory `Instance` (separate
// WASM linear memory), so these statics are effectively per-Java-object.
// ---------------------------------------------------------------------------

thread_local! {
    static TREE: RefCell<Option<zcash::tree::OwnedTree>> = const { RefCell::new(None) };
    static LAST_RESULT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

// ---------------------------------------------------------------------------
// Result buffer helpers
// ---------------------------------------------------------------------------

fn set_last_result(r: Response) {
    LAST_RESULT.with(|lr| *lr.borrow_mut() = r.encode_to_vec());
}

fn write_ok() {
    set_last_result(Response {
        result: Some(response::Result::Ok(true)),
    });
}

fn write_ok_bytes(bytes: Vec<u8>) {
    set_last_result(Response {
        result: Some(response::Result::BytesValue(bytes)),
    });
}

fn write_error(code: &str, msg: &str) {
    set_last_result(Response {
        result: Some(response::Result::Error(WasmError {
            code: code.into(),
            message: msg.into(),
        })),
    });
}

/// Split "CODE: message" into ("CODE", "message").
/// Falls back to ("WASM_ERROR", whole string) if no valid code prefix is found.
fn split_error(e: &str) -> (&str, &str) {
    if let Some(pos) = e.find(':') {
        let code = &e[..pos];
        if !code.is_empty()
            && code
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
        {
            return (code, e[pos + 1..].trim());
        }
    }
    ("WASM_ERROR", e)
}

// ---------------------------------------------------------------------------
// Memory management exports (called by WasmBridge before/after each call)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn alloc(len: u32) -> *mut u8 {
    let mut buf = Vec::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` must be a pointer previously returned by `alloc` with the same `len`.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: u32) {
    let _ = Vec::from_raw_parts(ptr, 0, len as usize);
}

/// Returns a pointer into the LAST_RESULT buffer. Valid until the next WASM call.
#[no_mangle]
pub extern "C" fn last_result_ptr() -> *const u8 {
    LAST_RESULT.with(|lr| lr.borrow().as_ptr())
}

/// Returns the byte length of the LAST_RESULT buffer.
#[no_mangle]
pub extern "C" fn last_result_len() -> u32 {
    LAST_RESULT.with(|lr| lr.borrow().len() as u32)
}

// ---------------------------------------------------------------------------
// Tree lifecycle exports
// ---------------------------------------------------------------------------

/// Verifies the WASM module is responding.
#[no_mangle]
pub extern "C" fn ping() -> i32 {
    write_ok();
    0
}

/// Initialize the tree from a CommitmentTree v0 frontier.
///
/// # Safety
/// `ptr` must point to `len` valid bytes in WASM linear memory, as written by `WasmBridge.call`.
#[no_mangle]
pub unsafe extern "C" fn from_frontier(ptr: *const u8, len: u32) -> i32 {
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    match FromFrontierRequest::decode(bytes) {
        Err(e) => write_error("DECODE_ERROR", &e.to_string()),
        Ok(req) => match zcash::tree::OwnedTree::from_frontier(&req.frontier, req.block_height) {
            Ok(tree) => {
                TREE.with(|t| *t.borrow_mut() = Some(tree));
                write_ok();
            }
            Err(e) => {
                let (code, msg) = split_error(&e);
                write_error(code, msg);
            }
        },
    }
    0
}

/// Restore the tree from bytes produced by `save_state`.
///
/// # Safety
/// `ptr` must point to `len` valid bytes in WASM linear memory, as written by `WasmBridge.call`.
#[no_mangle]
pub unsafe extern "C" fn from_state(ptr: *const u8, len: u32) -> i32 {
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    match zcash::tree::OwnedTree::from_state(bytes) {
        Ok(tree) => {
            TREE.with(|t| *t.borrow_mut() = Some(tree));
            write_ok();
        }
        Err(e) => {
            let (code, msg) = split_error(&e);
            write_error(code, msg);
        }
    }
    0
}

/// Drop the tree, releasing all in-memory state.
#[no_mangle]
pub extern "C" fn drop_tree() -> i32 {
    TREE.with(|t| *t.borrow_mut() = None);
    write_ok();
    0
}

// ---------------------------------------------------------------------------
// Tree operation exports
// ---------------------------------------------------------------------------

/// Append note commitments for a block, checkpoint the tree, optionally verify root.
///
/// # Safety
/// `ptr` must point to `len` valid bytes in WASM linear memory, as written by `WasmBridge.call`.
#[no_mangle]
pub unsafe extern "C" fn append_commitments(ptr: *const u8, len: u32) -> i32 {
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    match AppendCommitmentsRequest::decode(bytes) {
        Err(e) => write_error("DECODE_ERROR", &e.to_string()),
        Ok(req) => {
            let expected_root = req.expected_root;
            TREE.with(|t| {
                let mut borrow = t.borrow_mut();
                match borrow.as_mut() {
                    None => write_error("NO_TREE", "tree not initialized"),
                    Some(tree) => {
                        let commitments: Vec<Vec<u8>> =
                            req.commitments.iter().map(|b| b.to_vec()).collect();
                        let exp = expected_root.as_deref();
                        match tree.append_commitments(req.block_height, commitments, exp) {
                            Ok(root) => write_ok_bytes(root),
                            Err(e) => {
                                let (code, msg) = split_error(&e);
                                write_error(code, msg);
                            }
                        }
                    }
                }
            });
        }
    }
    0
}

/// Roll back the tree to the checkpoint at `block_height`.
///
/// # Safety
/// `ptr` must point to `len` valid bytes in WASM linear memory, as written by `WasmBridge.call`.
#[no_mangle]
pub unsafe extern "C" fn truncate_to_checkpoint(ptr: *const u8, len: u32) -> i32 {
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    match TruncateRequest::decode(bytes) {
        Err(e) => write_error("DECODE_ERROR", &e.to_string()),
        Ok(req) => {
            TREE.with(|t| {
                let mut borrow = t.borrow_mut();
                match borrow.as_mut() {
                    None => write_error("NO_TREE", "tree not initialized"),
                    Some(tree) => match tree.truncate_to_checkpoint(req.block_height) {
                        Ok(root) => write_ok_bytes(root),
                        Err(e) => {
                            let (code, msg) = split_error(&e);
                            write_error(code, msg);
                        }
                    },
                }
            });
        }
    }
    0
}

/// Serialize the tree state to bytes for later restoration via `from_state`.
#[no_mangle]
pub extern "C" fn save_state() -> i32 {
    TREE.with(|t| match t.borrow().as_ref() {
        None => write_error("NO_TREE", "tree not initialized"),
        Some(tree) => match tree.save() {
            Ok(bytes) => write_ok_bytes(bytes),
            Err(e) => write_error("SAVE_ERROR", &e),
        },
    });
    0
}

/// Return metadata about the current tree state.
#[no_mangle]
pub extern "C" fn get_info() -> i32 {
    TREE.with(|t| match t.borrow().as_ref() {
        None => write_error("NO_TREE", "tree not initialized"),
        Some(tree) => match tree.get_info() {
            Ok((tip_height, leaf_count, checkpoint_count)) => {
                set_last_result(Response {
                    result: Some(response::Result::InfoValue(TreeInfo {
                        tip_height,
                        leaf_count,
                        checkpoint_count,
                    })),
                });
            }
            Err(e) => write_error("GET_INFO_ERROR", &e),
        },
    });
    0
}
