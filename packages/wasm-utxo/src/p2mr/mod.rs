//! BIP-360 Pay-to-Merkle-Root (P2MR) support.
//!
//! Implements Merkle tree construction and control block generation for
//! SegWit v2 P2MR outputs. The tree structure is identical to Taproot
//! (BIP-341) but without key-path spending or TapTweak.
//!
//! See `bips/bip-0360/bip-0360.mediawiki` for the full specification.

use miniscript::bitcoin::hashes::Hash;
use miniscript::bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use miniscript::bitcoin::{Script, ScriptBuf};

/// Default leaf version for TapScript (BIP 342).
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

/// Convert a raw leaf version byte to `LeafVersion`.
fn leaf_version_from_u8(v: u8) -> LeafVersion {
    if v == TAPSCRIPT_LEAF_VERSION {
        LeafVersion::TapScript
    } else {
        LeafVersion::from_consensus(v).expect("valid even leaf version")
    }
}

/// Compute the TapLeafHash for a script and leaf version.
pub fn tap_leaf_hash(script: &[u8], leaf_version: u8) -> [u8; 32] {
    TapLeafHash::from_script(
        Script::from_bytes(script),
        leaf_version_from_u8(leaf_version),
    )
    .to_byte_array()
}

/// Compute the TapBranchHash from two node hashes (lexicographically sorted).
pub fn tap_branch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    TapNodeHash::from_node_hashes(
        TapNodeHash::assume_hidden(*a),
        TapNodeHash::assume_hidden(*b),
    )
    .to_byte_array()
}

/// P2MR control byte: leaf_version with parity bit forced to 1 (BIP-360 consensus rule).
///
/// Unlike Taproot where the parity bit encodes the output key's Y parity,
/// P2MR always sets the LSB to 1 as a distinguisher.
pub fn p2mr_control_byte(leaf_version: u8) -> u8 {
    (leaf_version & 0xfe) | 0x01
}

/// Build the 34-byte P2MR scriptPubKey: `OP_2 (0x52) OP_PUSHBYTES_32 (0x20) <merkle_root>`
pub fn build_p2mr_script_pubkey(merkle_root: &[u8; 32]) -> ScriptBuf {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0x52); // OP_2
    bytes.push(0x20); // OP_PUSHBYTES_32
    bytes.extend_from_slice(merkle_root);
    ScriptBuf::from(bytes)
}

/// A node in a P2MR script tree (recursive structure matching BIP-360 test vectors).
///
/// Trees are specified as either a single leaf or a pair of branches:
/// - Single leaf: `Leaf { script, leaf_version }`
/// - Two branches: `Branch(left, right)` where each side is another `ScriptTreeNode`
///
/// The BIP-360 test vectors use JSON arrays for branches and objects for leaves:
/// - `{ "script": "...", "leafVersion": 192 }` → leaf
/// - `[node, node]` → branch
#[derive(Debug, Clone)]
pub enum ScriptTreeNode {
    Leaf { script: Vec<u8>, leaf_version: u8 },
    Branch(Box<ScriptTreeNode>, Box<ScriptTreeNode>),
}

/// Per-leaf spending info produced by tree construction.
#[derive(Debug, Clone)]
pub struct P2mrLeafInfo {
    /// The TapLeafHash for this leaf.
    pub leaf_hash: [u8; 32],
    /// Serialized control block: `control_byte || merkle_path_siblings`.
    /// Length is `1 + 32 * depth`.
    pub control_block: Vec<u8>,
}

/// Complete P2MR tree info.
#[derive(Debug, Clone)]
pub struct P2mrTreeInfo {
    /// The 32-byte Merkle root (committed in the scriptPubKey).
    pub merkle_root: [u8; 32],
    /// Per-leaf spending info, in left-to-right DFS order.
    pub leaves: Vec<P2mrLeafInfo>,
}

/// Intermediate leaf data collected during tree traversal: (leaf_hash, leaf_version, merkle_path).
type LeafCollector = Vec<([u8; 32], u8, Vec<[u8; 32]>)>;

/// Build a P2MR Merkle tree from a script tree definition.
///
/// Returns the Merkle root and per-leaf spending info (leaf hash + control block).
/// Leaves are returned in left-to-right DFS order matching the input tree structure.
pub fn build_p2mr_tree(tree: &ScriptTreeNode) -> P2mrTreeInfo {
    let mut leaves: LeafCollector = Vec::new();
    let merkle_root = compute_node(tree, &mut leaves);

    let leaf_infos = leaves
        .into_iter()
        .map(|(leaf_hash, leaf_version, path)| {
            let mut control_block = vec![p2mr_control_byte(leaf_version)];
            for sibling in &path {
                control_block.extend_from_slice(sibling);
            }
            P2mrLeafInfo {
                leaf_hash,
                control_block,
            }
        })
        .collect();

    P2mrTreeInfo {
        merkle_root,
        leaves: leaf_infos,
    }
}

/// Recursively compute the hash of a tree node, collecting leaf info along the way.
///
/// Each leaf entry stores (leaf_hash, leaf_version, merkle_path_siblings).
/// Leaves are output in input DFS order (left subtree before right subtree).
fn compute_node(node: &ScriptTreeNode, leaves: &mut LeafCollector) -> [u8; 32] {
    match node {
        ScriptTreeNode::Leaf {
            script,
            leaf_version,
        } => {
            let hash = tap_leaf_hash(script, *leaf_version);
            leaves.push((hash, *leaf_version, Vec::new()));
            hash
        }
        ScriptTreeNode::Branch(left, right) => {
            let left_start = leaves.len();
            let left_hash = compute_node(left, leaves);
            let right_start = leaves.len();
            let right_hash = compute_node(right, leaves);

            // Add sibling hashes to the merkle proof paths.
            // Left subtree leaves need right_hash as sibling, and vice versa.
            for leaf in leaves[left_start..right_start].iter_mut() {
                leaf.2.push(right_hash);
            }
            for leaf in leaves[right_start..].iter_mut() {
                leaf.2.push(left_hash);
            }

            tap_branch_hash(&left_hash, &right_hash)
        }
    }
}

/// Verify a P2MR control block against a leaf hash and expected merkle root.
///
/// Walks the merkle path in the control block, combining with `tap_branch_hash`
/// at each step, and checks the result matches the expected root.
pub fn verify_control_block(
    leaf_hash: &[u8; 32],
    control_block: &[u8],
    expected_root: &[u8; 32],
) -> bool {
    if control_block.is_empty() {
        return false;
    }
    // Control block: 1 byte (control_byte) + 32*d bytes (merkle path)
    let path_bytes = &control_block[1..];
    if !path_bytes.len().is_multiple_of(32) {
        return false;
    }

    let mut current = *leaf_hash;
    for chunk in path_bytes.chunks_exact(32) {
        let sibling: [u8; 32] = chunk.try_into().unwrap();
        current = tap_branch_hash(&current, &sibling);
    }
    current == *expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_fixture() -> serde_json::Value {
        let content = std::fs::read_to_string("test/fixtures/p2mr/p2mr_construction.json")
            .expect("Failed to load p2mr_construction.json");
        serde_json::from_str(&content).expect("Failed to parse fixture")
    }

    fn get_vector(fixture: &serde_json::Value, id: &str) -> serde_json::Value {
        fixture["test_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("Vector '{}' not found", id))
            .clone()
    }

    /// Parse a fixture scriptTree node into our ScriptTreeNode.
    fn parse_fixture_tree(node: &serde_json::Value) -> ScriptTreeNode {
        if node.is_array() {
            let arr = node.as_array().unwrap();
            assert_eq!(arr.len(), 2);
            ScriptTreeNode::Branch(
                Box::new(parse_fixture_tree(&arr[0])),
                Box::new(parse_fixture_tree(&arr[1])),
            )
        } else {
            ScriptTreeNode::Leaf {
                script: hex::decode(node["script"].as_str().unwrap()).unwrap(),
                leaf_version: node["leafVersion"].as_u64().unwrap() as u8,
            }
        }
    }

    /// Run a construction test vector: build the tree and verify merkle root,
    /// leaf hashes, scriptPubKey, and control blocks against the fixture.
    fn run_construction_vector(id: &str) {
        let fixture = load_fixture();
        let vector = get_vector(&fixture, id);

        let script_tree = &vector["given"]["scriptTree"];
        let tree = parse_fixture_tree(script_tree);
        let info = build_p2mr_tree(&tree);

        // Verify merkle root
        let expected_root = vector["intermediary"]["merkleRoot"].as_str().unwrap();
        assert_eq!(hex::encode(info.merkle_root), expected_root, "merkle root");

        // Verify leaf hashes
        let expected_leaf_hashes: Vec<&str> = vector["intermediary"]["leafHashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(info.leaves.len(), expected_leaf_hashes.len(), "leaf count");
        let actual_leaf_hashes: Vec<String> = info
            .leaves
            .iter()
            .map(|l| hex::encode(l.leaf_hash))
            .collect();
        for expected in &expected_leaf_hashes {
            assert!(
                actual_leaf_hashes.contains(&expected.to_string()),
                "missing leaf hash: {}",
                expected
            );
        }

        // Verify scriptPubKey
        let expected_spk = vector["expected"]["scriptPubKey"].as_str().unwrap();
        let spk = build_p2mr_script_pubkey(&info.merkle_root);
        assert_eq!(hex::encode(spk.as_bytes()), expected_spk, "scriptPubKey");

        // Verify bip350 address if present
        if let Some(expected_addr) = vector["expected"]["bip350Address"].as_str() {
            let addr = crate::from_output_script_with_coin(&spk, "btc")
                .expect("failed to encode P2MR address");
            assert_eq!(addr, expected_addr, "bip350Address");
        }

        // Verify control blocks (order-independent, validated cryptographically)
        let expected_cbs: Vec<&str> = vector["expected"]["scriptPathControlBlocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(info.leaves.len(), expected_cbs.len(), "control block count");

        // Each generated control block must verify against the merkle root
        for leaf in &info.leaves {
            assert!(
                verify_control_block(&leaf.leaf_hash, &leaf.control_block, &info.merkle_root),
                "control block for leaf {} doesn't verify",
                hex::encode(leaf.leaf_hash)
            );
        }
        // Each expected control block must verify against some leaf
        for cb_hex in &expected_cbs {
            let cb = hex::decode(cb_hex).unwrap();
            let verified = info
                .leaves
                .iter()
                .any(|l| verify_control_block(&l.leaf_hash, &cb, &info.merkle_root));
            assert!(
                verified,
                "expected control block doesn't verify: {}",
                cb_hex
            );
        }
    }

    #[test]
    fn test_p2mr_control_byte() {
        assert_eq!(p2mr_control_byte(0xc0), 0xc1);
        assert_eq!(p2mr_control_byte(0xfa), 0xfb);
        assert_eq!(p2mr_control_byte(0xc1), 0xc1);
    }

    #[test]
    fn test_single_leaf_tree() {
        run_construction_vector("p2mr_single_leaf_script_tree");
    }

    #[test]
    fn test_two_leaf_same_version() {
        run_construction_vector("p2mr_two_leaf_same_version");
    }

    #[test]
    fn test_different_version_leaves() {
        run_construction_vector("p2mr_different_version_leaves");
    }

    #[test]
    fn test_simple_lightning_contract() {
        run_construction_vector("p2mr_simple_lightning_contract");
    }

    #[test]
    fn test_three_leaf_complex() {
        run_construction_vector("p2mr_three_leaf_complex");
    }

    #[test]
    fn test_three_leaf_alternative() {
        run_construction_vector("p2mr_three_leaf_alternative");
    }
}
