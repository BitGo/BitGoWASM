use wasm_utxo::parse_node::{Node, Primitive};
use colored::*;
use ptree::print_tree;
#[cfg(test)]
use ptree::TreeBuilder;
use std::borrow::Cow;
use std::io;

/// Defines how different parts of the tree should be styled
#[derive(Clone, Debug)]
pub struct ColorScheme {
    /// Style for node labels (field names)
    pub label_style: fn(&str) -> String,
    /// Style for node values
    pub value_style: fn(&str) -> String,
    /// Style for buffer values specifically
    pub buffer_style: fn(&str) -> String,
    /// Style for numeric values specifically
    pub numeric_style: fn(&str) -> String,
    /// Style for string values specifically
    pub string_style: fn(&str) -> String,
    /// Style for boolean values specifically
    pub boolean_style: fn(&str) -> String,
}

impl ColorScheme {
    /// Default color scheme with bold labels and colored values
    pub fn default() -> Self {
        Self {
            label_style: |s| s.bold().to_string(),
            value_style: |s| s.to_string(),
            buffer_style: |s| s.cyan().to_string(),
            numeric_style: |s| s.yellow().to_string(),
            string_style: |s| s.green().to_string(),
            boolean_style: |s| s.magenta().to_string(),
        }
    }

    /// No color scheme - plain text output
    pub fn no_color() -> Self {
        Self {
            label_style: |s| s.to_string(),
            value_style: |s| s.to_string(),
            buffer_style: |s| s.to_string(),
            numeric_style: |s| s.to_string(),
            string_style: |s| s.to_string(),
            boolean_style: |s| s.to_string(),
        }
    }

    /// Apply appropriate styling to a primitive value based on its type
    pub fn style_primitive(&self, primitive: &Primitive, formatted_value: &str) -> String {
        match primitive {
            Primitive::Buffer(_) => (self.buffer_style)(formatted_value),
            Primitive::U8(_)
            | Primitive::U16(_)
            | Primitive::U32(_)
            | Primitive::U64(_)
            | Primitive::I8(_)
            | Primitive::I16(_)
            | Primitive::I32(_)
            | Primitive::I64(_)
            | Primitive::Integer(_) => (self.numeric_style)(formatted_value),
            Primitive::String(_) => (self.string_style)(formatted_value),
            Primitive::Boolean(_) => (self.boolean_style)(formatted_value),
            Primitive::None => (self.value_style)(formatted_value),
        }
    }
}

/// A wrapper to implement TreeItem for Node
#[derive(Clone)]
struct NodeTreeItem<'a> {
    node: &'a Node,
    color_scheme: &'a ColorScheme,
}

impl<'a> ptree::TreeItem for NodeTreeItem<'a> {
    type Child = Self;

    fn write_self<W: io::Write>(&self, f: &mut W, style: &ptree::Style) -> io::Result<()> {
        let styled_label = (self.color_scheme.label_style)(&self.node.label);
        if self.node.value.is_empty() {
            return write!(f, "{}", style.paint(styled_label));
        }
        let value_str = format_primitive_for_tree(&self.node.value);
        let styled_value = self
            .color_scheme
            .style_primitive(&self.node.value, &value_str);
        let text = format!("{}: {}", styled_label, styled_value);
        write!(f, "{}", style.paint(text))
    }

    fn children(&self) -> Cow<'_, [Self::Child]> {
        Cow::Owned(
            self.node
                .children
                .iter()
                .map(|child| NodeTreeItem {
                    node: child,
                    color_scheme: self.color_scheme,
                })
                .collect(),
        )
    }
}

/// Format the value of a primitive for display in a tree
pub fn format_primitive_for_tree(primitive: &Primitive) -> String {
    match primitive {
        Primitive::Buffer(b) => {
            // Convert bytes to hex string
            let hex = b.iter().map(|b| format!("{:02x}", b)).collect::<String>();

            // For long buffers, truncate with ellipsis and show length
            let hex_trimmed = if hex.len() <= 512 {
                hex
            } else {
                format!("{}...", &hex[0..512])
            };

            format!("{} ({} bytes)", hex_trimmed, b.len())
        }
        // Use to_string() for all other types (numbers, booleans, None)
        _ => primitive.to_string(),
    }
}

/// Render a Node tree to a string with the specified color scheme
#[cfg(test)]
pub(super) fn node_to_string_with_scheme(
    node: &Node,
    color_scheme: &ColorScheme,
) -> Result<String, io::Error> {
    let styled_label = (color_scheme.label_style)(&node.label);
    let value_str = format_primitive_for_tree(&node.value);
    let styled_value = color_scheme.style_primitive(&node.value, &value_str);
    let root_text = format!("{}: {}", styled_label, styled_value);
    let mut tree = TreeBuilder::new(root_text);

    // Add children
    for child in &node.children {
        add_node_to_tree_with_scheme(&mut tree, child, color_scheme);
    }

    // Build the tree
    let tree = tree.build();

    // Render to string
    let mut output = Vec::new();
    ptree::write_tree(&tree, &mut output)?;
    Ok(String::from_utf8_lossy(&output).to_string())
}

/// Helper function to add a node and its children to a tree with color scheme
#[cfg(test)]
fn add_node_to_tree_with_scheme(tree: &mut TreeBuilder, node: &Node, color_scheme: &ColorScheme) {
    let styled_label = (color_scheme.label_style)(&node.label);
    let value_str = format_primitive_for_tree(&node.value);
    let styled_value = color_scheme.style_primitive(&node.value, &value_str);
    let node_text = format!("{}: {}", styled_label, styled_value);
    tree.begin_child(node_text);

    for child in &node.children {
        add_node_to_tree_with_scheme(tree, child, color_scheme);
    }

    tree.end_child();
}

/// Render a Node tree to the terminal with the specified color scheme
pub fn render_tree_with_scheme(node: &Node, color_scheme: &ColorScheme) -> Result<(), io::Error> {
    let tree_item = NodeTreeItem { node, color_scheme };
    print_tree(&tree_item)
}
