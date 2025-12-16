use miniscript::descriptor::TapTree;
use miniscript::{Miniscript, MiniscriptKey};

use crate::error::WasmUtxoError;

/// The recursive tap tree was removed from rust-miniscript in https://github.com/rust-bitcoin/rust-miniscript/pull/808
/// Our API is somewhat dependent on it and providing backwards compatibility is easier than rewriting everything.
pub enum RecursiveTapTree<Pk: MiniscriptKey> {
    Tree {
        left: Box<RecursiveTapTree<Pk>>,
        right: Box<RecursiveTapTree<Pk>>,
    },
    Leaf(Miniscript<Pk, miniscript::Tap>),
}

impl<Pk: MiniscriptKey + Clone> TryFrom<&TapTree<Pk>> for RecursiveTapTree<Pk> {
    type Error = WasmUtxoError;

    fn try_from(tree: &TapTree<Pk>) -> Result<Self, Self::Error> {
        use std::sync::Arc;

        // Collect leaves with depths (miniscript() returns Arc<Miniscript>)
        let leaves: Vec<(u8, Arc<Miniscript<Pk, miniscript::Tap>>)> = tree
            .leaves()
            .map(|item| (item.depth(), item.miniscript().clone()))
            .collect();

        if leaves.is_empty() {
            return Err(WasmUtxoError::new("Empty tap tree"));
        }

        // Stack-based reconstruction: process leaves left-to-right,
        // combining siblings at the same depth into Tree nodes
        let mut stack: Vec<(u8, RecursiveTapTree<Pk>)> = Vec::new();

        for (depth, ms) in leaves {
            // Clone the Miniscript from the Arc
            stack.push((depth, RecursiveTapTree::Leaf((*ms).clone())));

            // Combine nodes at the same depth
            while stack.len() >= 2 {
                let len = stack.len();
                if stack[len - 2].0 != stack[len - 1].0 {
                    break;
                }

                let (_, right) = stack.pop().unwrap();
                let (d, left) = stack.pop().unwrap();

                stack.push((
                    d - 1,
                    RecursiveTapTree::Tree {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                ));
            }
        }

        if stack.len() != 1 {
            return Err(WasmUtxoError::new("Invalid tap tree structure"));
        }

        Ok(stack.pop().unwrap().1)
    }
}
