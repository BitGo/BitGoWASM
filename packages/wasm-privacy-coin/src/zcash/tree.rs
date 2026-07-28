use incrementalmerkletree::{Address, Hashable, Level, Marking, Position, Retention};
use orchard::tree::MerkleHashOrchard;
use serde::{Deserialize, Serialize};
use shardtree::{
    store::memory::MemoryShardStore,
    store::{Checkpoint, ShardStore, TreeState},
    LocatedPrunableTree, Node, RetentionFlags, ShardTree, Tree,
};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Shielded commitment tree depth
pub const DEPTH: u8 = 32;
/// Number of checkpoints to retain (allows reorgs up to this depth)
pub const MAX_CHECKPOINTS: usize = 100;
/// Shard height for the tree (log2 of shard size)
pub const SHARD_HEIGHT: u8 = 16;

pub type ShieldedShardTree =
    ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, DEPTH, SHARD_HEIGHT>;

type PrunableT = Tree<Option<Arc<MerkleHashOrchard>>, (MerkleHashOrchard, RetentionFlags)>;

// ---------------------------------------------------------------------------
// Structural serialization types (ported from coins-sandbox/orchard-wasm-shard)
// ---------------------------------------------------------------------------

/// Serde-tagged enum mirroring `PrunableTree<MerkleHashOrchard>`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TreeNode {
    Nil,
    Leaf {
        h: String,
        f: u8,
    },
    Parent {
        a: String,
        l: Box<TreeNode>,
        r: Box<TreeNode>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedShard {
    pub root_addr_level: u8,
    pub root_addr_index: u64,
    pub tree: TreeNode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedCheckpoint {
    pub id: u32,
    pub position: Option<u64>,
    pub marks_removed: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedShardTreeState {
    pub shards: Vec<SerializedShard>,
    pub cap: TreeNode,
    pub checkpoints: Vec<SerializedCheckpoint>,
    pub tip_height: Option<u32>,
    pub leaf_count: u64,
    pub max_checkpoints: usize,
}

// ---------------------------------------------------------------------------
// Tree <-> TreeNode conversion
// ---------------------------------------------------------------------------

fn serialize_tree(tree: &PrunableT) -> TreeNode {
    match &**tree {
        Node::Nil => TreeNode::Nil,
        Node::Leaf { value: (h, flags) } => TreeNode::Leaf {
            h: hex::encode(h.to_bytes()),
            f: flags.bits(),
        },
        Node::Parent { ann, left, right } => TreeNode::Parent {
            a: ann
                .as_ref()
                .map(|h| hex::encode(h.to_bytes()))
                .unwrap_or_default(),
            l: Box::new(serialize_tree(left)),
            r: Box::new(serialize_tree(right)),
        },
    }
}

fn deserialize_tree(node: &TreeNode, depth: u8) -> Result<PrunableT, String> {
    if depth > DEPTH {
        return Err(format!("tree node depth exceeds maximum {}", DEPTH));
    }
    match node {
        TreeNode::Nil => Ok(Tree::empty()),
        TreeNode::Leaf { h, f } => {
            let hash = parse_hash_hex(h)?;
            let flags = RetentionFlags::from_bits(*f)
                .ok_or_else(|| format!("invalid retention flags: {}", f))?;
            Ok(Tree::leaf((hash, flags)))
        }
        TreeNode::Parent { a, l, r } => {
            let ann = if a.is_empty() {
                None
            } else {
                Some(Arc::new(parse_hash_hex(a)?))
            };
            Ok(Tree::parent(
                ann,
                deserialize_tree(l, depth + 1)?,
                deserialize_tree(r, depth + 1)?,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// ShardTree <-> PersistedShardTreeState extraction / restoration
// ---------------------------------------------------------------------------

pub fn extract_state(
    tree: &ShieldedShardTree,
    tip_height: Option<u32>,
    leaf_count: u64,
    max_checkpoints: usize,
) -> Result<PersistedShardTreeState, String> {
    let store = tree.store();

    let shard_roots = store
        .get_shard_roots()
        .map_err(|e| format!("get_shard_roots error: {:?}", e))?;

    let mut shards: Vec<SerializedShard> = Vec::new();
    for addr in shard_roots {
        let shard = store
            .get_shard(addr)
            .map_err(|e| format!("get_shard error: {:?}", e))?;
        if let Some(shard) = shard {
            shards.push(SerializedShard {
                root_addr_level: shard.root_addr().level().into(),
                root_addr_index: shard.root_addr().index(),
                tree: serialize_tree(shard.root()),
            });
        }
    }

    let cap = serialize_tree(
        &store
            .get_cap()
            .map_err(|e| format!("get_cap error: {:?}", e))?,
    );

    let count = store
        .checkpoint_count()
        .map_err(|e| format!("checkpoint_count error: {:?}", e))?;

    let mut checkpoints: Vec<SerializedCheckpoint> = Vec::new();
    if count > 0 {
        store
            .for_each_checkpoint(count, |id, cp| {
                checkpoints.push(SerializedCheckpoint {
                    id: *id,
                    position: match cp.tree_state() {
                        TreeState::Empty => None,
                        TreeState::AtPosition(pos) => Some(u64::from(pos)),
                    },
                    marks_removed: cp.marks_removed().iter().map(|p| u64::from(*p)).collect(),
                });
                Ok(())
            })
            .map_err(|e| format!("for_each_checkpoint error: {:?}", e))?;
    }

    Ok(PersistedShardTreeState {
        shards,
        cap,
        checkpoints,
        tip_height,
        leaf_count,
        max_checkpoints,
    })
}

pub fn restore_state(state: &PersistedShardTreeState) -> Result<ShieldedShardTree, String> {
    let mut store = MemoryShardStore::empty();

    for s in &state.shards {
        let addr = Address::from_parts(Level::from(s.root_addr_level), s.root_addr_index);
        let tree = deserialize_tree(&s.tree, 0)?;
        let located = LocatedPrunableTree::from_parts(addr, tree)
            .map_err(|a| format!("invalid shard address: {:?}", a))?;
        store
            .put_shard(located)
            .map_err(|e| format!("put_shard error: {:?}", e))?;
    }

    let cap_tree = deserialize_tree(&state.cap, 0)?;
    store
        .put_cap(cap_tree)
        .map_err(|e| format!("put_cap error: {:?}", e))?;

    for cp in &state.checkpoints {
        let tree_state = match cp.position {
            None => TreeState::Empty,
            Some(pos) => TreeState::AtPosition(Position::from(pos)),
        };
        let marks_removed: BTreeSet<Position> = cp
            .marks_removed
            .iter()
            .map(|p| Position::from(*p))
            .collect();
        let checkpoint = Checkpoint::from_parts(tree_state, marks_removed);
        store
            .add_checkpoint(cp.id, checkpoint)
            .map_err(|e| format!("add_checkpoint error: {:?}", e))?;
    }

    Ok(ShardTree::new(store, state.max_checkpoints))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a hex-encoded hash string into a MerkleHashOrchard.
pub fn parse_hash_hex(hex_str: &str) -> Result<MerkleHashOrchard, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode error: {}", e))?;
    parse_hash_bytes(&bytes)
}

/// Parse a raw 32-byte slice into a MerkleHashOrchard.
pub fn parse_hash_bytes(bytes: &[u8]) -> Result<MerkleHashOrchard, String> {
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Option::from(MerkleHashOrchard::from_bytes(&arr))
        .ok_or_else(|| "invalid MerkleHashOrchard value".to_string())
}

/// Get the root hash at the most recent checkpoint as raw bytes.
///
/// We use `root_at_checkpoint_depth(Some(0))` — the root computed from the last checkpoint
/// — rather than the tree's `frontier()` because after a `save()`/`from_state()` round-trip
/// the in-memory frontier is gone; only checkpoint data survives serialization.
/// This approach produces the correct root in both the live-tree and restored-tree cases.
fn get_checkpoint_root_bytes(tree: &ShieldedShardTree) -> Result<Vec<u8>, String> {
    let root = tree
        .root_at_checkpoint_depth(Some(0))
        .map_err(|e| format!("root_at_checkpoint error: {:?}", e))?
        .ok_or("no checkpoint available to compute root")?;
    Ok(root.to_bytes().to_vec())
}

fn read_compact_size(data: &[u8]) -> Result<(u64, usize), String> {
    if data.is_empty() {
        return Err("unexpected EOF reading compact size".to_string());
    }
    match data[0] {
        0..=252 => Ok((data[0] as u64, 1)),
        253 => {
            if data.len() < 3 {
                return Err("unexpected EOF reading compact size u16".to_string());
            }
            Ok((u16::from_le_bytes([data[1], data[2]]) as u64, 3))
        }
        254 => {
            if data.len() < 5 {
                return Err("unexpected EOF reading compact size u32".to_string());
            }
            Ok((
                u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64,
                5,
            ))
        }
        255 => {
            if data.len() < 9 {
                return Err("unexpected EOF reading compact size u64".to_string());
            }
            Ok((
                u64::from_le_bytes([
                    data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                ]),
                9,
            ))
        }
    }
}

fn read_hash(data: &[u8]) -> Result<(MerkleHashOrchard, usize), String> {
    if data.len() < 32 {
        return Err("unexpected EOF reading hash".to_string());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&data[..32]);
    let hash = Option::from(MerkleHashOrchard::from_bytes(&arr))
        .ok_or_else(|| "invalid MerkleHashOrchard value in frontier".to_string())?;
    Ok((hash, 32))
}

fn read_optional_hash(data: &[u8]) -> Result<(Option<MerkleHashOrchard>, usize), String> {
    if data.is_empty() {
        return Err("unexpected EOF reading optional flag".to_string());
    }
    match data[0] {
        0x00 => Ok((None, 1)),
        0x01 => {
            let (hash, n) = read_hash(&data[1..])?;
            Ok((Some(hash), 1 + n))
        }
        b => Err(format!("invalid optional flag byte: 0x{:02x}", b)),
    }
}

// ---------------------------------------------------------------------------
// OwnedTree — per-instance tree state (replaces the global TREE mutex)
// ---------------------------------------------------------------------------

/// Self-contained shielded tree with its own in-memory state.
///
/// One `OwnedTree` per Chicory WASM instance; each instance owns its own linear memory.
pub struct OwnedTree {
    tree: ShieldedShardTree,
    tip_height: Option<u32>,
    leaf_count: u64,
    max_checkpoints: usize,
}

impl OwnedTree {
    /// Restore from bytes produced by [`OwnedTree::save`].
    pub fn from_state(state: &[u8]) -> Result<Self, String> {
        let json = std::str::from_utf8(state).map_err(|e| format!("invalid UTF-8: {}", e))?;
        let persisted: PersistedShardTreeState =
            serde_json::from_str(json).map_err(|e| format!("JSON parse error: {}", e))?;
        let tree = restore_state(&persisted)?;
        Ok(Self {
            tree,
            tip_height: persisted.tip_height,
            leaf_count: persisted.leaf_count,
            max_checkpoints: persisted.max_checkpoints,
        })
    }

    /// Initialize from a CommitmentTree v0 frontier (raw bytes, not hex-encoded).
    pub fn from_frontier(
        frontier: &[u8],
        block_height: u32,
        max_checkpoints: Option<usize>,
    ) -> Result<Self, String> {
        let max_checkpoints = max_checkpoints.unwrap_or(MAX_CHECKPOINTS);
        use incrementalmerkletree::frontier::NonEmptyFrontier;

        let mut offset = 0;

        let (left, n) = read_optional_hash(&frontier[offset..])?;
        offset += n;

        let (right, n) = read_optional_hash(&frontier[offset..])?;
        offset += n;

        let (parent_count, n) = read_compact_size(&frontier[offset..])?;
        offset += n;

        if parent_count > DEPTH as u64 {
            return Err(format!(
                "parent_count {} exceeds tree depth {}",
                parent_count, DEPTH
            ));
        }

        let mut parents: Vec<Option<MerkleHashOrchard>> = Vec::with_capacity(parent_count as usize);
        for _ in 0..parent_count {
            let (parent, n) = read_optional_hash(&frontier[offset..])?;
            offset += n;
            parents.push(parent);
        }

        if offset != frontier.len() {
            return Err(format!(
                "frontier has {} unexpected trailing bytes after offset {}",
                frontier.len() - offset,
                offset
            ));
        }

        let left = left.ok_or("commitment tree has no left leaf — tree is empty")?;

        let (leaf, mut ommers, mut position_val) = if let Some(right_hash) = right {
            (right_hash, vec![left], 1u64)
        } else {
            (left, vec![], 0u64)
        };

        for (i, parent) in parents.iter().enumerate() {
            if let Some(hash) = parent {
                position_val |= 1u64 << (i + 1);
                ommers.push(*hash);
            }
        }

        let position = Position::from(position_val);
        let nef = NonEmptyFrontier::from_parts(position, leaf, ommers)
            .map_err(|e| format!("frontier construction error: {:?}", e))?;

        let leaf_count = u64::from(nef.position()) + 1;

        let mut tree = ShardTree::new(MemoryShardStore::empty(), max_checkpoints);
        tree.insert_frontier_nodes(
            nef,
            Retention::Checkpoint {
                id: block_height,
                marking: Marking::None,
            },
        )
        .map_err(|e| format!("insert_frontier_nodes error: {}", e))?;

        Ok(Self {
            tree,
            tip_height: Some(block_height),
            leaf_count,
            max_checkpoints,
        })
    }

    /// Serialize the tree state to bytes (UTF-8 JSON of `PersistedShardTreeState`).
    pub fn save(&self) -> Result<Vec<u8>, String> {
        let state = extract_state(
            &self.tree,
            self.tip_height,
            self.leaf_count,
            self.max_checkpoints,
        )?;
        serde_json::to_vec(&state).map_err(|e| format!("JSON serialize error: {}", e))
    }

    /// Append raw 32-byte commitments, checkpoint at `block_height`, verify root.
    ///
    /// Returns the 32-byte root after appending.
    pub fn append_commitments(
        &mut self,
        block_height: u32,
        commitments: Vec<Vec<u8>>,
        owned: Vec<bool>,
        expected_root: Option<&[u8]>,
    ) -> Result<Vec<u8>, String> {
        if commitments.is_empty() {
            self.tree
                .checkpoint(block_height)
                .map_err(|e| format!("checkpoint error: {}", e))?;
            self.tip_height = Some(block_height);
            if self.leaf_count == 0 {
                let empty_root = MerkleHashOrchard::empty_root(Level::from(DEPTH));
                return Ok(empty_root.to_bytes().to_vec());
            }
            return get_checkpoint_root_bytes(&self.tree);
        }

        if !owned.is_empty() && owned.len() != commitments.len() {
            return Err(format!(
                "owned length {} does not match commitments length {}",
                owned.len(),
                commitments.len()
            ));
        }

        // Validate ALL commitments before mutating any tree state.
        // This prevents a partial-append scenario where some leaves are inserted and then
        // an invalid commitment causes an error, leaving the tree in an inconsistent state
        // with orphaned leaf nodes that cannot be rolled back without a checkpoint.
        let hashes: Result<Vec<MerkleHashOrchard>, String> =
            commitments.iter().map(|c| parse_hash_bytes(c)).collect();
        let hashes = hashes?;

        let last_idx = hashes.len() - 1;
        for (i, hash) in hashes.into_iter().enumerate() {
            let is_owned = owned.get(i).copied().unwrap_or(false);
            let retention = if i == last_idx {
                Retention::Checkpoint {
                    id: block_height,
                    marking: if is_owned {
                        Marking::Marked
                    } else {
                        Marking::None
                    },
                }
            } else if is_owned {
                Retention::Marked
            } else {
                Retention::Ephemeral
            };
            self.tree
                .append(hash, retention)
                .map_err(|e| format!("append error: {}", e))?;
            self.leaf_count += 1;
        }

        self.tip_height = Some(block_height);

        let root = get_checkpoint_root_bytes(&self.tree)?;

        if let Some(expected) = expected_root {
            if !expected.is_empty() && root != expected {
                return Err(format!(
                    "ROOT_MISMATCH: computed {} but expected {}",
                    hex::encode(&root),
                    hex::encode(expected)
                ));
            }
        }

        Ok(root)
    }

    /// Roll back to the checkpoint at `block_height`.
    ///
    /// Returns the 32-byte root at the restored checkpoint.
    pub fn truncate_to_checkpoint(&mut self, block_height: u32) -> Result<Vec<u8>, String> {
        let ok = self
            .tree
            .truncate_to_checkpoint(&block_height)
            .map_err(|e| format!("truncate error: {:?}", e))?;
        if !ok {
            return Err(format!(
                "CHECKPOINT_NOT_FOUND: no checkpoint for block height {}",
                block_height
            ));
        }
        self.tip_height = Some(block_height);
        self.leaf_count = self
            .tree
            .max_leaf_position(Some(0))
            .map_err(|e| format!("max_leaf_position error: {:?}", e))?
            .map(|p| u64::from(p) + 1)
            .unwrap_or(0);
        get_checkpoint_root_bytes(&self.tree)
    }

    /// Return `(tip_height, leaf_count, checkpoint_count)`.
    pub fn get_info(&self) -> Result<(Option<u32>, u64, u32), String> {
        let checkpoint_count = self
            .tree
            .store()
            .checkpoint_count()
            .map_err(|e| format!("checkpoint_count error: {:?}", e))?;
        Ok((self.tip_height, self.leaf_count, checkpoint_count as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const F_CHECKPOINT: u8 = 1;
    const F_MARKED: u8 = 2;
    const F_CHECKPOINT_MARKED: u8 = 3;

    fn empty_tree() -> OwnedTree {
        let json = r#"{"shards":[],"cap":{"type":"Nil"},"checkpoints":[],"tip_height":null,"leaf_count":0,"max_checkpoints":100}"#;
        OwnedTree::from_state(json.as_bytes()).expect("empty state")
    }

    fn cmx(byte: u8) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[0] = byte;
        v
    }

    fn find_leaf_f(node: &TreeNode, target_h: &str) -> Option<u8> {
        match node {
            TreeNode::Leaf { h, f } if h == target_h => Some(*f),
            TreeNode::Parent { l, r, .. } => {
                find_leaf_f(l, target_h).or_else(|| find_leaf_f(r, target_h))
            }
            _ => None,
        }
    }

    fn find_f_in_state(state: &PersistedShardTreeState, target_h: &str) -> Option<u8> {
        for shard in &state.shards {
            if let Some(f) = find_leaf_f(&shard.tree, target_h) {
                return Some(f);
            }
        }
        find_leaf_f(&state.cap, target_h)
    }

    #[test]
    fn owned_flags_set_correct_retention() {
        let cmx1_hex = "0100000000000000000000000000000000000000000000000000000000000000";
        let cmx3_hex = "0300000000000000000000000000000000000000000000000000000000000000";

        let mut tree = empty_tree();
        tree.append_commitments(
            1,
            vec![cmx(1), cmx(2), cmx(3)],
            vec![true, false, true],
            None,
        )
        .unwrap();
        let state = extract_state(
            &tree.tree,
            tree.tip_height,
            tree.leaf_count,
            tree.max_checkpoints,
        )
        .unwrap();

        assert_eq!(
            find_f_in_state(&state, cmx1_hex),
            Some(F_MARKED),
            "CMX: owned, not last → MARKED"
        );
        assert_eq!(
            find_f_in_state(&state, cmx3_hex),
            Some(F_CHECKPOINT_MARKED),
            "CMX_3: owned, last → CHECKPOINT|MARKED"
        );
    }

    #[test]
    fn not_owned_last_leaf_is_checkpoint_only() {
        let cmx_hex = "0100000000000000000000000000000000000000000000000000000000000000";

        let mut tree = empty_tree();
        tree.append_commitments(1, vec![cmx(1)], vec![false], None)
            .unwrap();
        let state = extract_state(
            &tree.tree,
            tree.tip_height,
            tree.leaf_count,
            tree.max_checkpoints,
        )
        .unwrap();

        assert_eq!(
            find_f_in_state(&state, cmx_hex),
            Some(F_CHECKPOINT),
            "not owned, last → CHECKPOINT"
        );
    }

    #[test]
    fn owned_length_mismatch_returns_err() {
        let mut tree = empty_tree();
        let result =
            tree.append_commitments(1, vec![cmx(1), cmx(2)], vec![true, false, true], None);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // max_checkpoints
    // -------------------------------------------------------------------------

    fn frontier_bytes() -> Vec<u8> {
        hex::decode("0101000000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
    }

    #[test]
    fn from_frontier_defaults_max_checkpoints_when_not_specified() {
        let tree = OwnedTree::from_frontier(&frontier_bytes(), 1, None).unwrap();
        assert_eq!(tree.max_checkpoints, MAX_CHECKPOINTS);
    }

    #[test]
    fn from_frontier_uses_custom_max_checkpoints_when_specified() {
        let tree = OwnedTree::from_frontier(&frontier_bytes(), 1, Some(5)).unwrap();
        assert_eq!(tree.max_checkpoints, 5);
    }

    #[test]
    fn max_checkpoints_enforced_evicts_oldest_checkpoint() {
        let mut tree = OwnedTree::from_frontier(&frontier_bytes(), 1, Some(2)).unwrap();
        tree.append_commitments(2, vec![], vec![], None).unwrap();
        tree.append_commitments(3, vec![], vec![], None).unwrap();
        tree.append_commitments(4, vec![], vec![], None).unwrap();

        let (_, _, checkpoint_count) = tree.get_info().unwrap();
        assert_eq!(
            checkpoint_count, 2,
            "checkpoint_count should be capped at 2"
        );

        let result = tree.truncate_to_checkpoint(1);
        assert!(
            result.is_err(),
            "oldest checkpoint should have been evicted"
        );
    }

    #[test]
    fn save_round_trip_preserves_max_checkpoints() {
        let tree = OwnedTree::from_frontier(&frontier_bytes(), 1, Some(7)).unwrap();
        let bytes = tree.save().unwrap();
        let restored = OwnedTree::from_state(&bytes).unwrap();
        assert_eq!(restored.max_checkpoints, 7);
    }
}
