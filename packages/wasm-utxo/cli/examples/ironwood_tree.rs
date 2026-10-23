//! Decode a `z_gettreestate` `finalState` blob for the Orchard/Ironwood note commitment tree,
//! verify it against the RPC's `finalRoot`, and produce Merkle witnesses.
//!
//! Wire format (validated against `finalRoot`): zebra serializes the zcashd-style
//! `CommitmentTree` (`zcash_primitives::merkle_tree::write_commitment_tree`) as
//! `Optional(left)` + `Optional(right)` + `CompactSize(parentCount)` + that many parent
//! `Optional`s, where `Optional` is `0x00` absent / `0x01 ‖ 32-byte hash`. The frontier
//! (position, leaf, ommers) is recovered with the library's own `CommitmentTree::to_frontier`.
//!
//! Mode 1 — tip verification/witness:
//!
//! ```text
//! ironwood_tree <finalState-hex> <finalRoot-hex> [--witness]
//! ```
//!
//! Verifies the frontier against `finalRoot`; `--witness` prints the tip leaf's 32-entry
//! auth path (valid only when the note IS the frontier tip).
//!
//! Mode 2 — interior witness:
//!
//! ```text
//! ironwood_tree <preBlockState-hex> <anchorRoot-hex> --append <leaves.json> --target <cmx>
//! ```
//!
//! Rebuilds the tree from the block-N-1 frontier, appends block N's Ironwood leaves in
//! order, checkpoints, and witnesses `--target` as of that checkpoint. `anchorRoot` is the
//! anchor block's `finalRoot`; `leaves.json` is a JSON array of the block's leaf cmx hex in
//! append order (transaction order, action order within each transaction).
//!
//! Output JSON: `{"position", "authPath": [...×32]}` (plus `"anchor"` in mode 2) — the
//! `position`/`authPath` pair is what `psbt build-witness` consumes, and the anchor doubles as
//! the notes-file `anchor`.

use anyhow::{bail, Context};
use incrementalmerkletree::frontier::{CommitmentTree, Frontier};
use incrementalmerkletree::{Hashable as _, Level};
use orchard::tree::MerkleHashOrchard;

const DEPTH: usize = 32;

/// `Optional<Node>`: `0x00` absent, `0x01` + 32-byte hash present (zcashd-compatible).
fn read_optional(cursor: &mut &[u8]) -> anyhow::Result<Option<MerkleHashOrchard>> {
    if cursor.is_empty() {
        bail!("truncated tree slot");
    }
    let flag = cursor[0];
    *cursor = &cursor[1..];
    if flag == 0x00 {
        return Ok(None);
    }
    if flag != 0x01 {
        bail!("unexpected tree slot flag {flag:#x}");
    }
    if cursor.len() < 32 {
        bail!("truncated tree slot hash");
    }
    let (hash, rest) = cursor.split_at(32);
    *cursor = rest;
    parse_node(hash.try_into().unwrap()).map(Some)
}

/// A tree node or leaf from its 32-byte encoding, rejecting non-canonical field elements.
fn parse_node(bytes: &[u8; 32]) -> anyhow::Result<MerkleHashOrchard> {
    Option::from(MerkleHashOrchard::from_bytes(bytes))
        .with_context(|| format!("{} is not a canonical tree node", hex::encode(bytes)))
}

/// zcashd CompactSize consensus encoding.
fn read_compact_size(cursor: &mut &[u8]) -> anyhow::Result<u64> {
    if cursor.is_empty() {
        bail!("eof reading compact size");
    }
    let first = cursor[0];
    if first < 0xfd {
        *cursor = &cursor[1..];
        return Ok(first as u64);
    }
    let len = match first {
        0xfd => 2,
        0xfe => 4,
        _ => 8,
    };
    if cursor.len() < 1 + len {
        bail!("truncated compact size");
    }
    let mut value_bytes = [0u8; 8];
    value_bytes[..len].copy_from_slice(&cursor[1..1 + len]);
    let value = u64::from_le_bytes(value_bytes);
    *cursor = &cursor[1 + len..];
    Ok(value)
}

/// Reconstruct the frontier from `write_commitment_tree` layout.
fn parse_flat_tree(bytes: &[u8]) -> anyhow::Result<Frontier<MerkleHashOrchard, 32>> {
    let mut cursor = bytes;
    let left = read_optional(&mut cursor)?;
    let right = read_optional(&mut cursor)?;
    let parent_count = read_compact_size(&mut cursor)? as usize;
    if parent_count >= DEPTH {
        bail!("parent count {parent_count} exceeds tree depth");
    }
    let mut parents = Vec::with_capacity(parent_count);
    for _ in 0..parent_count {
        parents.push(read_optional(&mut cursor)?);
    }
    if !cursor.is_empty() {
        bail!("{} trailing bytes after the parents vector", cursor.len());
    }
    let tree = CommitmentTree::<MerkleHashOrchard, 32>::from_parts(left, right, parents)
        .map_err(|_| anyhow::anyhow!("invalid commitment tree parts"))?;
    Ok(tree.to_frontier())
}

fn parse_args() -> anyhow::Result<(Vec<String>, [u8; 32])> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        bail!(
            "usage: ironwood_tree <finalState-hex> <finalRoot-hex> [--witness]\n       \
             ironwood_tree <preBlockState-hex> <anchorRoot-hex> --append <leaves.json> --target <cmx>"
        );
    }
    let root: [u8; 32] = hex::decode(args[2].trim())?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("root must be 32 bytes"))?;
    Ok((args, root))
}

fn main() -> anyhow::Result<()> {
    let (args, expected_root) = parse_args()?;
    let bytes = hex::decode(args[1].trim())?;
    let f = parse_flat_tree(&bytes)?;

    if args.iter().any(|a| a == "--append") {
        return run_append_mode(f, expected_root, &args);
    }
    run_tip_mode(f, expected_root, args.iter().any(|a| a == "--witness"))
}

/// Mode 1: verify the frontier against `finalRoot`; optionally print the tip witness.
fn run_tip_mode(
    f: Frontier<MerkleHashOrchard, 32>,
    expected_root: [u8; 32],
    want_witness: bool,
) -> anyhow::Result<()> {
    let nef = f.value().context("empty tree")?;
    let position = u64::from(nef.position());
    let leaf = *nef.leaf();
    let ommers = nef.ommers().to_vec();
    let root = f.root().to_bytes();
    if root != expected_root {
        bail!(
            "root mismatch: decoded {} != finalRoot {}",
            hex::encode(root),
            hex::encode(expected_root)
        );
    }
    println!(
        "{}",
        serde_json::json!({
            "verified": true,
            "tipLeafPosition": position,
            "leaves": position + 1,
            "tipLeaf": hex::encode(leaf.to_bytes()),
            "ommers": ommers.iter().map(|h| hex::encode(h.to_bytes())).collect::<Vec<_>>(),
            "root": hex::encode(root),
        })
    );
    if want_witness {
        // The frontier witnesses exactly its tip leaf; re-fold the path to prove that.
        let path = tip_auth_path(&f)?;
        let mut current = leaf;
        for (level, sibling) in path.iter().enumerate() {
            let sibling = parse_node(sibling)?;
            current = if position >> level & 1 == 1 {
                MerkleHashOrchard::combine(Level::from(level as u8), &sibling, &current)
            } else {
                MerkleHashOrchard::combine(Level::from(level as u8), &current, &sibling)
            };
        }
        if current.to_bytes() != expected_root {
            bail!("tip witness does not fold to finalRoot");
        }
        println!(
            "{}",
            serde_json::json!({
                "position": position,
                "authPath": path.iter().map(hex::encode).collect::<Vec<_>>(),
            })
        );
    }
    Ok(())
}

/// The frontier tip's auth path: present levels supply their ommer, absent levels the empty root.
fn tip_auth_path(frontier: &Frontier<MerkleHashOrchard, 32>) -> anyhow::Result<Vec<[u8; 32]>> {
    let nef = frontier.value().context("empty tree")?;
    let path = nef
        .witness(DEPTH as u8, |addr: incrementalmerkletree::Address| {
            Some(MerkleHashOrchard::empty_root(addr.level()))
        })
        .map_err(|addr: incrementalmerkletree::Address| {
            anyhow::anyhow!("missing complement at {addr:?}")
        })?;
    Ok(path.iter().map(|h| h.to_bytes()).collect())
}

/// Mode 2: interior witness via `ShardTree` (frontier + appended block leaves + checkpoint).
fn run_append_mode(
    f: Frontier<MerkleHashOrchard, 32>,
    expected_root: [u8; 32],
    args: &[String],
) -> anyhow::Result<()> {
    use incrementalmerkletree::{Position, Retention};
    use shardtree::store::memory::MemoryShardStore;
    use shardtree::ShardTree;

    let leaves_idx = args
        .iter()
        .position(|a| a == "--append")
        .context("--append missing")?;
    let leaves_path = args
        .get(leaves_idx + 1)
        .context("--append requires a JSON file path")?;
    let target_idx = args
        .iter()
        .position(|a| a == "--target")
        .context("--target required with --append")?;
    let target: [u8; 32] = hex::decode(args.get(target_idx + 1).context("--target requires hex")?)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("--target must be 32 bytes"))?;

    let leaves: Vec<[u8; 32]> =
        serde_json::from_str::<Vec<String>>(&std::fs::read_to_string(leaves_path)?)?
            .iter()
            .map(|h| {
                hex::decode(h)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("leaf must be 32 bytes"))
            })
            .collect::<Result<Vec<_>, _>>()?;
    let target_index = leaves
        .iter()
        .position(|l| *l == target)
        .context("target cmx is not among the appended leaves")?;

    let base = f.tree_size();
    let store = MemoryShardStore::<MerkleHashOrchard, u64>::empty();
    let mut tree: ShardTree<_, 32, 16> = ShardTree::new(store, 10);
    tree.insert_frontier(f, Retention::Reference)
        .map_err(|e| anyhow::anyhow!("inserting the pre-block frontier failed: {e:?}"))?;
    for (i, leaf) in leaves.iter().enumerate() {
        let retention = if i == target_index {
            Retention::Marked
        } else {
            Retention::Ephemeral
        };
        tree.append(parse_node(leaf)?, retention)
            .map_err(|e| anyhow::anyhow!("append failed: {e:?}"))?;
    }
    tree.checkpoint(0u64)
        .map_err(|e| anyhow::anyhow!("checkpoint failed: {e:?}"))?;

    let position = base + target_index as u64;
    let path = tree
        .witness_at_checkpoint_id(Position::from(position), &0)
        .map_err(|e| anyhow::anyhow!("witness failed: {e:?}"))?
        .context("no witness at the checkpoint")?;
    let anchor = path.root(parse_node(&target)?).to_bytes();
    if anchor != expected_root {
        bail!(
            "witness folds to {} but the anchor-block root is {}",
            hex::encode(anchor),
            hex::encode(expected_root)
        );
    }
    let checkpoint_root = tree
        .root_at_checkpoint_id(&0)
        .map_err(|e| anyhow::anyhow!("root_at_checkpoint_id failed: {e:?}"))?
        .context("no checkpoint root")?
        .to_bytes();
    if checkpoint_root != expected_root {
        bail!(
            "checkpoint root {} != expected root {}",
            hex::encode(checkpoint_root),
            hex::encode(expected_root)
        );
    }
    println!(
        "{}",
        serde_json::json!({
            "position": position,
            "authPath": path.path_elems().iter().map(|h: &MerkleHashOrchard| hex::encode(h.to_bytes())).collect::<Vec<_>>(),
            "anchor": hex::encode(anchor),
        })
    );
    Ok(())
}
