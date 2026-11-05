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

    let cap_tree = materialize_cap(tree, leaf_count)?;
    verify_cap_root(tree, &cap_tree, leaf_count)?;
    let cap = serialize_tree(&cap_tree);

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
    // The persisted cap embeds the in-progress shard so external consumers can walk
    // it standalone; the store cap must not carry that sub-shard structure (see
    // [`sanitize_store_cap`]).
    let store_cap = sanitize_store_cap(
        &cap_tree,
        Address::from_parts(Level::from(DEPTH), 0),
        Level::from(SHARD_HEIGHT),
    );
    store
        .put_cap(store_cap)
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

/// Strip sub-shard structure from a materialized cap before installing it as a store
/// cap.
///
/// The materialized cap embeds the in-progress shard (nodes below the shard-root
/// level) so external consumers can walk it standalone. The shardtree crate's own cap
/// invariant is "nodes at the shard-root level or higher" (`ShardTree::insert`): its
/// `root_internal` leaf-split branch re-parents a straddling cached leaf at the leaf's
/// own address, which only has children above the shard-root level. A stale embedded
/// shard left in the store cap — a reorg whose target falls inside a range the cap
/// records as a completed shard makes `truncate_to_position` fail on the cap and leaves
/// it untouched — would therefore panic `ShardTree::root` at a level-0 leaf.
///
/// Dropping the embedded structure costs nothing: `ShardTree::root` backfills `Nil`
/// cap holes from the shard store via `root_from_shards`, and `materialize_cap`
/// re-embeds the live shard on every save. The `Leaf` entries — completed-shard roots
/// and bootstrap ommers, the only record of shard ranges whose detail was never
/// retained — are kept verbatim.
fn sanitize_store_cap(cap: &PrunableT, addr: Address, shard_root_level: Level) -> PrunableT {
    if addr.level() == shard_root_level {
        // Only leaves are valid at the shard-root level: completed-shard roots and
        // bootstrap ommers. Anything else is embedded shard structure.
        return match &**cap {
            Node::Leaf { value } => Tree::leaf(*value),
            _ => Tree::empty(),
        };
    }
    match &**cap {
        Node::Parent { ann, left, right } => {
            let (l_addr, r_addr) = addr
                .children()
                .expect("cap address above the shard-root level always has children");
            let l = sanitize_store_cap(left, l_addr, shard_root_level);
            let r = sanitize_store_cap(right, r_addr, shard_root_level);
            match (&*l, &*r) {
                // Collapse fully-empty parents so the shape stays crate-canonical.
                (Node::Nil, Node::Nil) if ann.is_none() => Tree::empty(),
                _ => Tree::parent(ann.clone(), l, r),
            }
        }
        Node::Leaf { value } => Tree::leaf(*value),
        Node::Nil => Tree::empty(),
    }
}

/// Re-materialize the cap at `leaf_count`, verify it, and install its sanitized form
/// as the store cap.
///
/// Called after operations that can invalidate the store cap: `restore_state`
/// installs a sanitized cap directly, and `OwnedTree::truncate_to_checkpoint` heals
/// through here (see the call site for why the crate's own cap truncation is not
/// enough). Installing rather than merely reading keeps `ShardTree::root`'s cache
/// fast paths consistent with the shard store after a reorg, while `materialize_cap`
/// keeps benefiting from the reused completed-shard leaves on subsequent saves.
///
/// The `DEPTH`/`SHARD_HEIGHT` const generics shadow the module constants of the same
/// name; the tests exercise this helper with a smaller tree.
fn refresh_store_cap<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &mut ShardTree<S, DEPTH, SHARD_HEIGHT>,
    leaf_count: u64,
) -> Result<(), String>
where
    S: ShardStore<H = MerkleHashOrchard>,
    S::CheckpointId: Clone + std::fmt::Debug + Ord,
{
    let materialized = materialize_cap(tree, leaf_count)?;
    verify_cap_root(tree, &materialized, leaf_count)?;
    let store_cap = sanitize_store_cap(
        &materialized,
        Address::from_parts(Level::from(DEPTH), 0),
        Level::from(SHARD_HEIGHT),
    );
    tree.store_mut()
        .put_cap(store_cap)
        .map_err(|e| format!("put_cap error: {:?}", e))
}

/// Materialize the persisted-state cap: the complete tree above every shard, down to (and
/// including) shard-root nodes.
///
/// `ShardTree::append` never writes completed shard roots into the store cap — the crate
/// treats the cap as an optional cache and backfills holes from the shard store inside
/// `ShardTree::root`. Until the first `restore_state` the cap therefore only ever
/// contains bootstrap-frontier ommer leaves; after a restore it holds the previously
/// materialized cap (completed-shard leaves plus the embedded in-progress shard),
/// which `rebuild_cap_node` reuses the same way.
///
/// The materialized cap has two kinds of entries:
/// - frozen: roots of completed shards (`Leaf` at the shard-root address) plus any cached
///   `Leaf` already present in the store cap (bootstrap ommers are the only record of
///   shard ranges whose leaf detail was never retained, so they are reused as-is). Each is
///   written once and never changes.
/// - moving right edge: the in-progress shard is embedded as a copy of its live shard
///   tree, so consumers can compute the truncated (partial) shard root themselves. It
///   changes with every append, mirroring the frontier, because witnesses are checked
///   against the current root.
///
/// Embedding the live shard tree — rather than caching its truncated root — keeps the
/// persisted cap safe to restore: every value in it is a real leaf or a complete-subtree
/// root, never a truncation-dependent hash (a cached truncated root would poison
/// `ShardTree::root` after the shard fills: the crate's cache check cannot distinguish a
/// truncated value from a complete one).
///
/// Cost: completed-shard roots absent from the store cap are recomputed from the shard
/// store on each save; the reused cap leaves (present after every `restore_state`) make
/// that a one-time cost per shard in the restore-per-use indexer lifecycle. The embedded
/// in-progress shard duplicates part of the persisted shard list, so the state grows by
/// the shard's retained structure (bounded by its marked/checkpointed nodes, not by its
/// full `2^SHARD_HEIGHT` leaves).
///
/// The `DEPTH`/`SHARD_HEIGHT` const generics shadow the module constants of the same
/// name; the tests exercise these helpers with a smaller tree.
fn materialize_cap<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<S, DEPTH, SHARD_HEIGHT>,
    leaf_count: u64,
) -> Result<PrunableT, String>
where
    S: ShardStore<H = MerkleHashOrchard>,
    S::CheckpointId: Clone + std::fmt::Debug + Ord,
{
    let existing = tree
        .store()
        .get_cap()
        .map_err(|e| format!("get_cap error: {:?}", e))?;
    rebuild_cap_node(
        tree,
        &existing,
        Address::from_parts(Level::from(DEPTH), 0),
        leaf_count,
    )
}

/// Recursive step of [`materialize_cap`]: build the cap subtree covering `addr`, reusing
/// valid cached nodes from `existing` (the store cap, walked in lockstep with `addr`).
///
/// Invariant of the result, for every address whose position range starts before
/// `leaf_count`: the node is either a `Leaf` carrying the true root of its complete
/// subtree, or a `Parent` whose children satisfy the same invariant down to the
/// shard-root level, where the in-progress shard is embedded verbatim. Ranges at or
/// beyond `leaf_count` stay `Nil`: consumers treat them as canonically empty (the
/// note-commitment tree only ever grows, so `leaf_count` is a well-defined truncation
/// boundary).
///
/// The `DEPTH`/`SHARD_HEIGHT` const generics shadow the module constants of the same
/// name.
fn rebuild_cap_node<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<S, DEPTH, SHARD_HEIGHT>,
    existing: &PrunableT,
    addr: Address,
    leaf_count: u64,
) -> Result<PrunableT, String>
where
    S: ShardStore<H = MerkleHashOrchard>,
    S::CheckpointId: Clone + std::fmt::Debug + Ord,
{
    if u64::from(addr.position_range_start()) >= leaf_count {
        return Ok(Tree::empty());
    }
    let range_end = u64::from(addr.position_range_end());

    // At the shard-root level: a completed shard's entry is a single cached `Leaf`
    // carrying its (immutable) root — either reused from the store cap or computed
    // via `ShardTree::root` (which falls back to the shard store for cap holes).
    // Only the in-progress shard is embedded verbatim: its truncated root moves
    // with every append, so consumers must recompute it from real structure rather
    // than trust a cached, truncation-dependent value.
    if addr.level() == ShardTree::<S, DEPTH, SHARD_HEIGHT>::subtree_level() {
        if let Node::Leaf { value } = &**existing {
            if range_end <= leaf_count {
                return Ok(Tree::leaf(*value));
            }
        }
        let shard = tree
            .store()
            .get_shard(addr)
            .map_err(|e| format!("get_shard error: {:?}", e))?
            .ok_or_else(|| format!("shard {:?} missing from the store", addr))?;
        if range_end <= leaf_count {
            let root = tree.root(addr, Position::from(leaf_count)).map_err(|e| {
                format!(
                    "completed-shard root computation failed at {:?}: {:?}",
                    addr, e
                )
            })?;
            return Ok(Tree::leaf((root, RetentionFlags::EPHEMERAL)));
        }
        return Ok(shard.root().clone());
    }

    match &**existing {
        // A cached leaf whose subtree is complete is a valid permanent entry: bootstrap
        // ommers (the only record of shard ranges whose detail was never retained) and
        // previously materialized completed-shard roots both land here.
        Node::Leaf { value } if range_end <= leaf_count => Ok(Tree::leaf(*value)),
        Node::Parent { ann, left, right } => {
            let (l_addr, r_addr) = addr
                .children()
                .expect("interior cap address always has children");
            Ok(Tree::parent(
                // A cached annotation stays valid only where the rebuild leaves the
                // subtree unchanged: complete subtrees keep their children verbatim,
                // straddling ones are re-derived, so force a recompute there. In
                // practice store-cap annotations are always `None` (bootstrap caps are
                // built unannotated and materialized caps inherit that); the filter
                // keeps the persisted `a` field honest if that ever changes.
                ann.clone().filter(|_| range_end <= leaf_count),
                rebuild_cap_node(tree, left, l_addr, leaf_count)?,
                rebuild_cap_node(tree, right, r_addr, leaf_count)?,
            ))
        }
        // Nil nodes, and cached leaves straddling the truncation boundary (values that
        // would be wrong today): rebuild from the shard store.
        _ => {
            let (l_addr, r_addr) = addr
                .children()
                .expect("interior cap address always has children");
            Ok(Tree::parent(
                None,
                rebuild_cap_node(tree, &Tree::empty(), l_addr, leaf_count)?,
                rebuild_cap_node(tree, &Tree::empty(), r_addr, leaf_count)?,
            ))
        }
    }
}

/// Verify that a materialized cap independently reproduces the tree's current root: the
/// cap is hashed as a standalone tree — no shard store, exactly the way witness
/// consumers walk it — truncated at `leaf_count`. The reference root is the root at the
/// most recent checkpoint, the same root `OwnedTree::append_commitments` checks against
/// the node's expected root and the indexer persists as `currentRoot`; a cap that passes
/// here is therefore consistent with the anchor every z→z build is verified against.
///
/// Precondition: the most recent checkpoint sits at the tree's tip (position
/// `leaf_count - 1`). Every `OwnedTree` flow maintains this — each block checkpoints
/// its last commitment, and `truncate_to_checkpoint` rewinds `leaf_count` to the target
/// checkpoint — but `extract_state` is public, so a tree whose tip is not checkpointed
/// fails here with a precise error instead of a misleading root mismatch. The
/// `DEPTH`/`SHARD_HEIGHT` const generics shadow the module constants of the same name.
fn verify_cap_root<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<S, DEPTH, SHARD_HEIGHT>,
    cap_tree: &PrunableT,
    leaf_count: u64,
) -> Result<(), String>
where
    S: ShardStore<H = MerkleHashOrchard>,
    S::CheckpointId: Clone + std::fmt::Debug + Ord,
{
    if leaf_count == 0 {
        return Ok(());
    }
    // The reference root is taken at the most recent checkpoint while the cap is
    // hashed at `leaf_count`; the comparison is only meaningful when the two
    // truncations coincide (see the precondition above).
    let checkpoint_tip = tree
        .max_leaf_position(Some(0))
        .map_err(|e| format!("max_leaf_position error: {:?}", e))?
        .ok_or_else(|| "no retained checkpoint: cannot verify the cap root".to_string())?;
    if u64::from(checkpoint_tip) + 1 != leaf_count {
        return Err(format!(
            "cap root cannot be verified: latest checkpoint is at position {}, but the tree tip is at {} leaves",
            u64::from(checkpoint_tip),
            leaf_count
        ));
    }
    let located = LocatedPrunableTree::from_parts(
        Address::from_parts(Level::from(DEPTH), 0),
        cap_tree.clone(),
    )
    .map_err(|a| format!("materialized cap invalid at {:?}", a))?;
    let cap_root = located
        .root_hash(Position::from(leaf_count))
        .map_err(|missing| {
            format!(
                "materialized cap is not root-computable, missing {:?}",
                missing
            )
        })?;
    let expected = get_checkpoint_root_bytes(tree)?;
    if cap_root.to_bytes().as_slice() != expected.as_slice() {
        return Err(format!(
            "MATERIALIZED_CAP_ROOT_MISMATCH: cap root {} != tree root {}",
            hex::encode(cap_root.to_bytes()),
            hex::encode(&expected)
        ));
    }
    Ok(())
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
/// The `DEPTH`/`SHARD_HEIGHT` const generics shadow the module constants of the same
/// name.
fn get_checkpoint_root_bytes<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<S, DEPTH, SHARD_HEIGHT>,
) -> Result<Vec<u8>, String>
where
    S: ShardStore<H = MerkleHashOrchard>,
    S::CheckpointId: Clone + std::fmt::Debug + Ord,
{
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

        // Heal the store cap for the rewound tip. The crate's own cap truncation can
        // fail (a cached completed-shard `Leaf` cannot be split), which would leave
        // roots from the pre-reorg chain in the cap; once a divergent chain refills
        // past them, `ShardTree::root`'s cache fast path keeps serving those stale
        // roots — and since the cap-root check compares against a root computed
        // through the same cache, a save would silently persist the pre-reorg root
        // rather than fail. Re-materializing at the rewound tip replaces them with
        // the truncated in-progress shard — a structure snapshot that `root`
        // backfills from the shard store as the new chain grows.
        refresh_store_cap(&mut self.tree, self.leaf_count)?;

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

    // -------------------------------------------------------------------------
    // cap materialization
    // -------------------------------------------------------------------------

    /// Small stand-in for `ShieldedShardTree` (DEPTH 32 / SHARD_HEIGHT 16): an 8-level
    /// tree with 4-leaf shards, so tests can cross shard boundaries cheaply.
    type SmallTree = ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 8, 2>;
    const SMALL_DEPTH: u8 = 8;
    const SMALL_SHARD_LEVEL: u8 = 2;

    fn small_cmx(i: u8) -> MerkleHashOrchard {
        parse_hash_bytes(&cmx(i)).unwrap()
    }

    /// A small tree with `leaf_count` leaves over the given store: all marked, the last
    /// one checkpointed — mirroring production, where every block's final commitment is a
    /// checkpoint (and the anchor `verify_cap_root` compares against is the root at the
    /// most recent checkpoint).
    fn small_tree_over(
        store: MemoryShardStore<MerkleHashOrchard, u32>,
        leaf_count: u64,
    ) -> SmallTree {
        let mut tree = SmallTree::new(store, 10);
        for i in 0..(leaf_count - 1) as u8 {
            tree.append(small_cmx(i), Retention::Marked).unwrap();
        }
        tree.append(
            small_cmx((leaf_count - 1) as u8),
            Retention::Checkpoint {
                id: 1,
                marking: Marking::Marked,
            },
        )
        .unwrap();
        tree
    }

    fn small_tree(leaf_count: u64) -> SmallTree {
        small_tree_over(MemoryShardStore::empty(), leaf_count)
    }

    /// The serialized-shape node at `(target_level, target_index)` of a cap rooted at
    /// `(root_level, 0)` (or `None` if the descent hits a Leaf/Nil first).
    fn node_at(
        cap: &TreeNode,
        root_level: u8,
        target_level: u8,
        target_index: u64,
    ) -> Option<&TreeNode> {
        let steps = root_level - target_level;
        let mut dirs = Vec::with_capacity(steps as usize);
        let mut idx = target_index;
        for _ in 0..steps {
            dirs.push(idx % 2 == 1);
            idx /= 2;
        }
        dirs.reverse();
        let mut cur = cap;
        for right in dirs {
            cur = match cur {
                TreeNode::Parent { l, r, .. } => {
                    if right {
                        r
                    } else {
                        l
                    }
                }
                _ => return None,
            };
        }
        Some(cur)
    }

    #[test]
    fn materialize_cap_matches_root_and_resolves_sibling_addresses() {
        // 11 leaves: shards 0 and 1 complete, shard 2 in progress (3 of 4 slots).
        let leaf_count = 11u64;
        let tree = small_tree(leaf_count);
        let cap = materialize_cap(&tree, leaf_count).unwrap();
        verify_cap_root(&tree, &cap, leaf_count).unwrap();

        let ser = serialize_tree(&cap);
        // Completed shard roots are present as cap leaves...
        assert!(
            matches!(
                node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL, 0),
                Some(TreeNode::Leaf { .. })
            ),
            "completed shard 0 must be a cap leaf"
        );
        assert!(
            matches!(
                node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL, 1),
                Some(TreeNode::Leaf { .. })
            ),
            "completed shard 1 must be a cap leaf"
        );
        // ...the in-progress shard is embedded (real structure, not a Nil)...
        assert!(
            matches!(
                node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL, 2),
                Some(TreeNode::Parent { .. })
            ),
            "in-progress shard 2 must be embedded in the cap"
        );
        // ...and the unfilled tail is canonically empty (Nil for the walker).
        assert!(
            matches!(
                node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL, 3),
                Some(TreeNode::Nil)
            ),
            "shard 3 is beyond the truncation boundary"
        );

        // Consumer contract for a note at position 9 (in-progress shard 2): the walk from
        // (2,2) upward needs sibling (2,3) (beyond truncation → empty) and (3,0)
        // (complete → cached leaf), both fine, plus the straddling ancestors containing
        // shard 2 — all present because the shard itself is embedded.
        for (level, index) in [(3u8, 0u64), (4, 0), (5, 0), (6, 0), (7, 0)] {
            assert!(
                matches!(
                    node_at(&ser, SMALL_DEPTH, level, index),
                    Some(TreeNode::Leaf { .. }) | Some(TreeNode::Parent { .. })
                ),
                "cap node at ({level},{index}) must resolve"
            );
        }

        // Consumer contract for a note at position 5 (completed shard 1): the sibling at
        // level 2 is shard 0's root (leaf), and the level-3 sibling (3,1) straddles the
        // truncation boundary — its left half must carry the embedded shard 2 so the
        // truncated root is computable.
        assert!(
            matches!(
                node_at(&ser, SMALL_DEPTH, 3, 1),
                Some(TreeNode::Parent { .. })
            ),
            "straddling node (3,1) must be rebuilt with the embedded shard"
        );
    }

    #[test]
    fn materialize_cap_reuses_bootstrap_ommer_and_rebuilds_the_rest() {
        // Reproduce the exact production failure shape: the store cap holds only the
        // bootstrap ommers (here a single leaf covering shards 0-1, i.e. address (3,0))
        // and Nil everywhere else, while the shard store has since grown past it.
        let leaf_count = 11u64;
        let clean = small_tree(leaf_count);
        let ommer_value = clean
            .root(
                Address::from_parts(Level::from(SMALL_SHARD_LEVEL + 1), 0),
                Position::from(leaf_count),
            )
            .unwrap();

        let mut store = MemoryShardStore::empty();
        // Stale cap: left spine down to (4,0), a cached leaf at (3,0) (the ommer), Nil
        // for everything at or right of (3,1) — the shape `get_cap()` used to persist.
        let stale = {
            let at4 = Tree::parent(
                None,
                Tree::leaf((ommer_value, RetentionFlags::EPHEMERAL)),
                Tree::empty(),
            );
            let at5 = Tree::parent(None, at4, Tree::empty());
            let at6 = Tree::parent(None, at5, Tree::empty());
            let at7 = Tree::parent(None, at6, Tree::empty());
            Tree::parent(None, at7, Tree::empty())
        };
        store.put_cap(stale).unwrap();

        let tree = small_tree_over(store, leaf_count);

        let cap = materialize_cap(&tree, leaf_count).unwrap();
        verify_cap_root(&tree, &cap, leaf_count).unwrap();

        let ser = serialize_tree(&cap);
        // The ommer leaf is reused verbatim (it is the only record of shards 0-1)...
        let reused = match node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL + 1, 0) {
            Some(TreeNode::Leaf { h, .. }) => h.clone(),
            other => panic!("expected reused ommer leaf at (3,0), got {other:?}"),
        };
        assert_eq!(reused, hex::encode(ommer_value.to_bytes()));
        // ...the straddling range is rebuilt (embedded in-progress shard, Nil tail)...
        assert!(matches!(
            node_at(&ser, SMALL_DEPTH, 3, 1),
            Some(TreeNode::Parent { .. })
        ));
        // ...and the assembled cap still hashes to the tree's current root.
    }

    /// Rebuild a materialized cap (rooted at `(SMALL_DEPTH, 0)`) with the leaf value at
    /// `(target_level, target_index)` replaced — fault injection for the root check
    /// (children are `Arc`-shared, so the path is rebuilt rather than mutated).
    fn corrupt_cap_leaf(
        cap: &PrunableT,
        target_level: u8,
        target_index: u64,
        wrong: MerkleHashOrchard,
    ) -> PrunableT {
        fn descend(node: &PrunableT, steps: &[bool], wrong: MerkleHashOrchard) -> PrunableT {
            if steps.is_empty() {
                let flags = match &**node {
                    Node::Leaf { value } => value.1,
                    _ => panic!("expected Leaf at the corrupt target"),
                };
                return Tree::leaf((wrong, flags));
            }
            match &**node {
                Node::Parent { ann, left, right } => {
                    let (l, r) = if steps[0] {
                        (
                            left.as_ref().clone(),
                            descend(right.as_ref(), &steps[1..], wrong),
                        )
                    } else {
                        (
                            descend(left.as_ref(), &steps[1..], wrong),
                            right.as_ref().clone(),
                        )
                    };
                    Tree::parent(ann.clone(), l, r)
                }
                _ => panic!("expected Parent during cap descent"),
            }
        }
        let mut steps = Vec::with_capacity((SMALL_DEPTH - target_level) as usize);
        let mut idx = target_index;
        for _ in 0..(SMALL_DEPTH - target_level) {
            steps.push(idx % 2 == 1);
            idx /= 2;
        }
        steps.reverse();
        descend(cap, &steps, wrong)
    }

    #[test]
    fn verify_cap_root_rejects_a_cap_that_does_not_match_the_tree() {
        // The verification is the persisted-cap invariant's safety net: a cap whose
        // standalone root differs from the tree's current root must fail the save
        // loudly. (A poison cached in the *store* cap is instead caught upstream by the
        // indexer's per-block expected-root check against the node, which shares that
        // cache path.)
        let leaf_count = 11u64;
        let tree = small_tree(leaf_count);
        let cap = materialize_cap(&tree, leaf_count).unwrap();
        verify_cap_root(&tree, &cap, leaf_count).unwrap();

        let corrupted = corrupt_cap_leaf(&cap, SMALL_SHARD_LEVEL, 0, small_cmx(9));
        let err = verify_cap_root(&tree, &corrupted, leaf_count).unwrap_err();
        assert!(
            err.starts_with("MATERIALIZED_CAP_ROOT_MISMATCH"),
            "expected root mismatch, got: {err}"
        );
    }

    #[test]
    fn save_materializes_cap_and_survives_restore_round_trip() {
        // End-to-end on the production type (DEPTH 32 / SHARD_HEIGHT 16), below the
        // shard boundary: the persisted cap is a 16-level spine whose left descent ends
        // in the embedded in-progress shard, and the whole state round-trips.
        let mut tree = empty_tree();
        let root1 = tree
            .append_commitments(
                1,
                vec![cmx(1), cmx(2), cmx(3)],
                vec![true, false, false],
                None,
            )
            .unwrap();
        let bytes1 = tree.save().unwrap(); // runs the cap-root assertion

        let state: PersistedShardTreeState = serde_json::from_slice(&bytes1).unwrap();
        let mut node = &state.cap;
        for depth in 0..(DEPTH - SHARD_HEIGHT) {
            node = match node {
                TreeNode::Parent { l, .. } => l,
                other => panic!("expected spine Parent at depth {depth}, got {other:?}"),
            };
        }
        assert!(
            matches!(node, TreeNode::Parent { .. }),
            "in-progress shard must be embedded at the bottom of the cap spine"
        );

        let mut restored = OwnedTree::from_state(&bytes1).unwrap();
        let root2 = restored
            .append_commitments(2, vec![cmx(9)], vec![false], None)
            .unwrap();
        assert_ne!(root1, root2);
        restored.save().unwrap(); // assertion holds after restore + append too
    }

    /// A small tree where every leaf is its own checkpoint (id = position + 1), all
    /// marked — a one-block-per-commitment indexer — so reorgs have interior
    /// checkpoints to rewind to (unlike `small_tree_over`, which checkpoints only
    /// the last leaf).
    fn small_tree_with_checkpoints(leaf_count: u64) -> SmallTree {
        small_tree_with_checkpoints_over(MemoryShardStore::empty(), leaf_count)
    }

    fn small_tree_with_checkpoints_over(
        store: MemoryShardStore<MerkleHashOrchard, u32>,
        leaf_count: u64,
    ) -> SmallTree {
        let mut tree = SmallTree::new(store, 10);
        for i in 0..leaf_count as u8 {
            tree.append(
                small_cmx(i),
                Retention::Checkpoint {
                    id: u32::from(i) + 1,
                    marking: Marking::Marked,
                },
            )
            .unwrap();
        }
        tree
    }

    /// Rebuild a `SmallTree` the way `restore_state` does: same shards, same
    /// checkpoints, and the sanitized materialized cap as the store cap.
    fn restored_small_tree(tree: &SmallTree, cap: &PrunableT) -> SmallTree {
        let mut store = MemoryShardStore::empty();
        for addr in tree.store().get_shard_roots().unwrap() {
            if let Some(shard) = tree.store().get_shard(addr).unwrap() {
                store.put_shard(shard).unwrap();
            }
        }
        let count = tree.store().checkpoint_count().unwrap();
        if count > 0 {
            tree.store()
                .for_each_checkpoint(count, |id, cp| {
                    store.add_checkpoint(*id, cp.clone()).unwrap();
                    Ok(())
                })
                .unwrap();
        }
        store
            .put_cap(sanitize_store_cap(
                cap,
                Address::from_parts(Level::from(SMALL_DEPTH), 0),
                Level::from(SMALL_SHARD_LEVEL),
            ))
            .unwrap();
        SmallTree::new(store, 10)
    }

    #[test]
    fn sanitize_store_cap_strips_the_embedded_shard_and_keeps_cached_leaves() {
        let leaf_count = 11u64; // shards 0-1 complete, shard 2 in progress
        let tree = small_tree(leaf_count);
        let cap = materialize_cap(&tree, leaf_count).unwrap();

        let sanitized = sanitize_store_cap(
            &cap,
            Address::from_parts(Level::from(SMALL_DEPTH), 0),
            Level::from(SMALL_SHARD_LEVEL),
        );
        let ser = serialize_tree(&sanitized);

        // completed-shard roots stay cached (they are the only record alongside the
        // persisted shards, and materialize_cap reuses them)...
        assert!(matches!(
            node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL, 0),
            Some(TreeNode::Leaf { .. })
        ));
        assert!(matches!(
            node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL, 1),
            Some(TreeNode::Leaf { .. })
        ));
        // ...the embedded in-progress shard is gone: the subtree that carried it
        // collapses to Nil (ShardTree::root backfills such holes from the shard
        // store), and the descent toward the old shard-root slots stops at it.
        assert!(matches!(
            node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL + 1, 1),
            Some(TreeNode::Nil)
        ));
        assert!(matches!(
            node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL, 2),
            None | Some(TreeNode::Nil)
        ));
        assert!(matches!(
            node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL, 3),
            None | Some(TreeNode::Nil)
        ));
    }

    #[test]
    fn restored_store_cap_survives_reorg_across_a_completed_shard() {
        // Regression (shardtree 0.6.2 panic): installing the materialized cap —
        // which embeds the in-progress shard below shard-root level — as the store
        // cap made a reorg whose target falls inside a completed shard leave the cap
        // untruncated (a cached Leaf cannot be split), and the next ShardTree::root
        // walk panicked re-parenting a straddling level-0 leaf in root_internal's
        // leaf-split branch. `restore_state` now sanitizes the store cap, and
        // `truncate_to_checkpoint` heals it via `refresh_store_cap` — this test
        // exercises both through the same helpers the production paths call.
        let leaf_count = 12u64; // shards 0-2 complete
        let tree = small_tree_with_checkpoints(leaf_count);
        let cap = materialize_cap(&tree, leaf_count).unwrap();
        verify_cap_root(&tree, &cap, leaf_count).unwrap();

        let mut restored = restored_small_tree(&tree, &cap);

        // Shallow reorg: rewind to the checkpoint at position 9, inside what was the
        // in-progress shard 2 at save time.
        restored.truncate_to_checkpoint(&10u32).unwrap();
        refresh_store_cap(&mut restored, 10).unwrap();
        let _ = get_checkpoint_root_bytes(&restored).unwrap(); // must not panic
        let cap_now = materialize_cap(&restored, 10).unwrap();
        verify_cap_root(&restored, &cap_now, 10).unwrap();

        // Deep reorg: rewind to the checkpoint at position 2, inside completed shard
        // 0. The store cap still caches shard 0's completed root as a Leaf, so the
        // crate's cap truncation fails and leaves the cap stale — the exact shape
        // that used to panic on the next root computation.
        restored.truncate_to_checkpoint(&3u32).unwrap();
        refresh_store_cap(&mut restored, 3).unwrap();
        let _ = get_checkpoint_root_bytes(&restored).unwrap(); // must not panic
        let cap_now = materialize_cap(&restored, 3).unwrap();
        verify_cap_root(&restored, &cap_now, 3).unwrap();

        // The rewound shard is in progress again: re-embedded, not a cached leaf...
        let ser = serialize_tree(&cap_now);
        assert!(
            matches!(
                node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL, 0),
                Some(TreeNode::Parent { .. })
            ),
            "rewound shard 0 must be re-embedded, not cached as a completed root"
        );
        assert!(matches!(
            node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL, 1),
            Some(TreeNode::Nil)
        ));

        // Divergent re-append completing shard 0 with a different leaf than the
        // pre-reorg chain. Without the heal, the stale completed-shard Leaf would
        // be reused and the reference root would be computed through the same
        // poisoned cache, so the save would verify against — and silently
        // persist — the pre-reorg root. With the heal, the fresh shard root is
        // computed through the snapshot + shard-store backfill and must equal the
        // root of an independently built divergent chain.
        restored
            .append(
                small_cmx(0xEE),
                Retention::Checkpoint {
                    id: 4,
                    marking: Marking::Marked,
                },
            )
            .unwrap();
        let cap_divergent = materialize_cap(&restored, 4).unwrap();
        verify_cap_root(&restored, &cap_divergent, 4).unwrap();
        let ser = serialize_tree(&cap_divergent);
        assert!(
            matches!(
                node_at(&ser, SMALL_DEPTH, SMALL_SHARD_LEVEL, 0),
                Some(TreeNode::Leaf { .. })
            ),
            "divergently completed shard 0 must be cached as a fresh root"
        );

        // Independent reference for the divergent chain's true root: same four
        // leaves built fresh, with no stale cap anywhere.
        let mut reference = small_tree_with_checkpoints(3);
        reference
            .append(
                small_cmx(0xEE),
                Retention::Checkpoint {
                    id: 4,
                    marking: Marking::Marked,
                },
            )
            .unwrap();
        let true_root = get_checkpoint_root_bytes(&reference).unwrap();
        assert_eq!(
            get_checkpoint_root_bytes(&restored).unwrap(),
            true_root,
            "healed tree must serve the divergent chain's true root"
        );
    }

    #[test]
    fn restore_state_strips_the_embedded_shard_from_the_store_cap() {
        // Pins the production restore path: the persisted cap keeps the embedded
        // in-progress shard (external consumers walk it standalone), but the store
        // cap that ShardTree::root uses internally must not contain sub-shard
        // structure — that is what makes reorgs panic (see the regression test
        // above).
        let mut tree = empty_tree();
        tree.append_commitments(1, vec![cmx(1), cmx(2)], vec![false, false], None)
            .unwrap();
        let bytes = tree.save().unwrap();

        let state: PersistedShardTreeState = serde_json::from_slice(&bytes).unwrap();
        let mut node = &state.cap;
        for _ in 0..(DEPTH - SHARD_HEIGHT) {
            node = match node {
                TreeNode::Parent { l, .. } => l,
                other => panic!("expected spine Parent, got {other:?}"),
            };
        }
        assert!(
            matches!(node, TreeNode::Parent { .. }),
            "persisted cap must embed the in-progress shard for consumers"
        );

        let restored = restore_state(&state).unwrap();
        let store_cap = serialize_tree(&restored.store().get_cap().unwrap());
        // No `Parent` may exist below the shard-root level. (For a below-boundary
        // tree like this one the sanitized cap collapses to a single `Nil` — every
        // cache hole is backfilled from the shard store.)
        fn max_parent_depth(node: &TreeNode, depth: usize) -> usize {
            match node {
                TreeNode::Parent { l, r, .. } => {
                    max_parent_depth(l, depth + 1).max(max_parent_depth(r, depth + 1))
                }
                _ => depth,
            }
        }
        assert!(
            max_parent_depth(&store_cap, 0) <= usize::from(DEPTH - SHARD_HEIGHT),
            "store cap must not carry sub-shard structure: {store_cap:?}"
        );
    }

    #[test]
    #[ignore = "set ZEC_STAGING_STATE_JSON to an exported PersistedShardTreeState JSON to run"]
    fn staging_state_materializes_a_consumer_valid_cap() {
        // The production bug: staging TZEC's persisted cap was the frozen bootstrap
        // ommer snapshot, and the first real z→z spend died with CapNodeMissing.
        // This test replays the exact persisted state (metadata + shards exported
        // from the staging indexer Mongo) through the fixed save path.
        let path = std::env::var("ZEC_STAGING_STATE_JSON").expect("ZEC_STAGING_STATE_JSON not set");
        let bytes = std::fs::read(&path).expect("state file unreadable");
        let owned = OwnedTree::from_state(&bytes).expect("staging state must restore");

        // The failing staging note (wallet 6aec310c9a7bbaad2b72e18dfaf5fa5f, the
        // t→z output at leaf position 831321) must be inside the tree.
        const NOTE_POSITION: u64 = 831_321;
        assert!(
            owned.leaf_count > NOTE_POSITION,
            "exported tree ({} leaves) must contain the note at {NOTE_POSITION}",
            owned.leaf_count
        );

        // The fixed save path: materialize + standalone root verification against the
        // restored checkpoints' root. This is the exact code the indexer runs on its
        // first block after the fixed wasm deploys.
        let state = extract_state(
            &owned.tree,
            owned.tip_height,
            owned.leaf_count,
            owned.max_checkpoints,
        )
        .expect("staging state must materialize a self-consistent cap");

        // Consumer contract for that note's witness walk: from its shard root
        // (16, 12) up to the tree root, every sibling address below the truncation
        // boundary must resolve to a Leaf or Parent — never Nil. Before the fix,
        // the level-16 sibling (16, 11) hit Nil here (CapNodeMissing).
        let shard = NOTE_POSITION >> 16;
        let mut level = SHARD_HEIGHT;
        let mut index = shard;
        while level < DEPTH {
            let sibling_index = index ^ 1;
            let range_start = sibling_index << level;
            if range_start < owned.leaf_count {
                let node = node_at(&state.cap, DEPTH, level, sibling_index);
                assert!(
                    matches!(
                        node,
                        Some(TreeNode::Leaf { .. }) | Some(TreeNode::Parent { .. })
                    ),
                    "sibling ({level},{sibling_index}) must resolve in the materialized cap"
                );
            }
            level += 1;
            index >>= 1;
        }
    }
}
