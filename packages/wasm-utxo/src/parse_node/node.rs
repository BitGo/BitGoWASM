use num_bigint::BigInt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub type Buffer = Vec<u8>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Primitive {
    String(String),
    #[serde(
        serialize_with = "serialize_buffer",
        deserialize_with = "deserialize_buffer"
    )]
    Buffer(Buffer),
    #[serde(
        serialize_with = "serialize_bigint",
        deserialize_with = "deserialize_bigint"
    )]
    Integer(BigInt),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Boolean(bool),
    None,
}

fn serialize_buffer<S>(buffer: &Buffer, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(buffer))
}

fn deserialize_buffer<'de, D>(deserializer: D) -> Result<Buffer, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    hex::decode(&s).map_err(serde::de::Error::custom)
}

fn serialize_bigint<S>(bigint: &BigInt, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&bigint.to_string())
}

fn deserialize_bigint<'de, D>(deserializer: D) -> Result<BigInt, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    BigInt::parse_bytes(s.as_bytes(), 10).ok_or_else(|| serde::de::Error::custom("Invalid BigInt"))
}

impl Primitive {
    pub fn is_empty(&self) -> bool {
        matches!(self, Primitive::None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub label: String,
    pub value: Primitive,
    pub children: Vec<Node>,
}

impl Node {
    pub fn new(label: impl Into<String>, value: Primitive) -> Self {
        Self {
            label: label.into(),
            value,
            children: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn with_children(label: impl Into<String>, value: Primitive, children: Vec<Node>) -> Self {
        Self {
            label: label.into(),
            value,
            children,
        }
    }

    pub fn add_child(&mut self, child: Node) {
        self.children.push(child);
    }

    pub fn extend(&mut self, nodes: impl IntoIterator<Item = Node>) {
        self.children.extend(nodes);
    }

    #[cfg(test)]
    pub fn child_count(&self) -> usize {
        self.children.len()
    }
}

impl fmt::Display for Primitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Primitive::String(s) => write!(f, "{}", s),
            Primitive::Buffer(b) => write!(f, "{:?}", b),
            Primitive::Integer(n) => write!(f, "{}", n),
            Primitive::I8(n) => write!(f, "{}i8", n),
            Primitive::I16(n) => write!(f, "{}i16", n),
            Primitive::I32(n) => write!(f, "{}i32", n),
            Primitive::I64(n) => write!(f, "{}i64", n),
            Primitive::U8(n) => write!(f, "{}u8", n),
            Primitive::U16(n) => write!(f, "{}u16", n),
            Primitive::U32(n) => write!(f, "{}u32", n),
            Primitive::U64(n) => write!(f, "{}u64", n),
            Primitive::Boolean(b) => write!(f, "{}", b),
            Primitive::None => write!(f, "None"),
        }
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.label, self.value)?;
        if !self.children.is_empty() {
            write!(f, " with {} children", self.children.len())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_creation() {
        let node = Node::new("name", Primitive::String("John".to_string()));
        assert_eq!(node.label, "name");
        assert_eq!(node.child_count(), 0);

        let int_value = BigInt::from(30);
        let node = Node::new("age", Primitive::Integer(int_value.clone()));
        assert_eq!(node.label, "age");
        if let Primitive::Integer(value) = &node.value {
            assert_eq!(value, &int_value);
        } else {
            panic!("Expected Integer value");
        }

        let large_int =
            BigInt::parse_bytes(b"12345678901234567890123456789012345678901234567890", 10).unwrap();
        let node = Node::new("big_num", Primitive::Integer(large_int.clone()));
        if let Primitive::Integer(value) = &node.value {
            assert_eq!(value, &large_int);
        } else {
            panic!("Expected Integer value");
        }

        let node = Node::new("active", Primitive::Boolean(true));
        assert_eq!(node.label, "active");

        let buffer = vec![1, 2, 3, 4];
        let node = Node::new("data", Primitive::Buffer(buffer.clone()));
        match &node.value {
            Primitive::Buffer(b) => assert_eq!(b, &buffer),
            _ => panic!("Expected Buffer value"),
        }

        let node = Node::new("empty", Primitive::None);
        assert_eq!(node.label, "empty");
    }

    #[test]
    fn test_node_with_children() {
        let child1 = Node::new("child1", Primitive::String("Child 1".to_string()));
        let child2 = Node::new("child2", Primitive::Integer(BigInt::from(42)));

        let mut parent = Node::new("parent", Primitive::None);
        assert_eq!(parent.child_count(), 0);

        parent.add_child(child1);
        assert_eq!(parent.child_count(), 1);

        parent.add_child(child2);
        assert_eq!(parent.child_count(), 2);

        assert_eq!(parent.children[0].label, "child1");
        assert_eq!(parent.children[1].label, "child2");
    }

    #[test]
    fn test_node_with_children_constructor() {
        let child1 = Node::new("child1", Primitive::String("Child 1".to_string()));
        let child2 = Node::new("child2", Primitive::Integer(BigInt::from(42)));

        let children = vec![child1, child2];
        let parent = Node::with_children("parent", Primitive::None, children);

        assert_eq!(parent.child_count(), 2);
        assert_eq!(parent.children[0].label, "child1");
        assert_eq!(parent.children[1].label, "child2");
    }

    #[test]
    fn test_large_integers() {
        let large_int =
            BigInt::parse_bytes(b"9999999999999999999999999999999999999999999999999999", 10)
                .unwrap();
        let node = Node::new("very_large", Primitive::Integer(large_int.clone()));

        if let Primitive::Integer(value) = &node.value {
            assert_eq!(value, &large_int);
        } else {
            panic!("Expected Integer value");
        }

        let display = format!("{}", node.value);
        assert_eq!(
            display,
            "9999999999999999999999999999999999999999999999999999"
        );
    }

    #[test]
    fn test_integer_variants() {
        let i8_node = Node::new("i8_val", Primitive::I8(-42));
        let i16_node = Node::new("i16_val", Primitive::I16(-1000));
        let i32_node = Node::new("i32_val", Primitive::I32(-100000));
        let i64_node = Node::new("i64_val", Primitive::I64(-5000000000));

        match &i8_node.value {
            Primitive::I8(val) => assert_eq!(*val, -42),
            _ => panic!("Expected I8 value"),
        }

        match &i16_node.value {
            Primitive::I16(val) => assert_eq!(*val, -1000),
            _ => panic!("Expected I16 value"),
        }

        match &i32_node.value {
            Primitive::I32(val) => assert_eq!(*val, -100000),
            _ => panic!("Expected I32 value"),
        }

        match &i64_node.value {
            Primitive::I64(val) => assert_eq!(*val, -5000000000),
            _ => panic!("Expected I64 value"),
        }

        let u8_node = Node::new("u8_val", Primitive::U8(200));
        let u16_node = Node::new("u16_val", Primitive::U16(60000));
        let u32_node = Node::new("u32_val", Primitive::U32(3000000000));
        let u64_node = Node::new("u64_val", Primitive::U64(9000000000000000000));

        match &u8_node.value {
            Primitive::U8(val) => assert_eq!(*val, 200),
            _ => panic!("Expected U8 value"),
        }

        match &u16_node.value {
            Primitive::U16(val) => assert_eq!(*val, 60000),
            _ => panic!("Expected U16 value"),
        }

        match &u32_node.value {
            Primitive::U32(val) => assert_eq!(*val, 3000000000),
            _ => panic!("Expected U32 value"),
        }

        match &u64_node.value {
            Primitive::U64(val) => assert_eq!(*val, 9000000000000000000),
            _ => panic!("Expected U64 value"),
        }
    }

    #[test]
    fn test_integer_display() {
        assert_eq!(format!("{}", Primitive::I8(-42)), "-42i8");
        assert_eq!(format!("{}", Primitive::I16(-1000)), "-1000i16");
        assert_eq!(format!("{}", Primitive::I32(-100000)), "-100000i32");
        assert_eq!(format!("{}", Primitive::I64(-5000000000)), "-5000000000i64");

        assert_eq!(format!("{}", Primitive::U8(200)), "200u8");
        assert_eq!(format!("{}", Primitive::U16(60000)), "60000u16");
        assert_eq!(format!("{}", Primitive::U32(3000000000)), "3000000000u32");
        assert_eq!(
            format!("{}", Primitive::U64(9000000000000000000)),
            "9000000000000000000u64"
        );
    }

    #[test]
    fn test_serde_serialization() {
        let node = Node::new("test", Primitive::String("hello".to_string()));
        let json = serde_json::to_string(&node).unwrap();
        let deserialized: Node = serde_json::from_str(&json).unwrap();
        assert_eq!(node.label, deserialized.label);

        let buffer_node = Node::new("buffer", Primitive::Buffer(vec![0x01, 0x02, 0x03]));
        let json = serde_json::to_string(&buffer_node).unwrap();
        assert!(json.contains("010203"));
        let deserialized: Node = serde_json::from_str(&json).unwrap();
        if let Primitive::Buffer(b) = &deserialized.value {
            assert_eq!(b, &vec![0x01, 0x02, 0x03]);
        } else {
            panic!("Expected Buffer");
        }

        let bigint_node = Node::new("bigint", Primitive::Integer(BigInt::from(12345)));
        let json = serde_json::to_string(&bigint_node).unwrap();
        assert!(json.contains("12345"));
        let deserialized: Node = serde_json::from_str(&json).unwrap();
        if let Primitive::Integer(i) = &deserialized.value {
            assert_eq!(i, &BigInt::from(12345));
        } else {
            panic!("Expected Integer");
        }
    }

    #[test]
    fn test_serde_with_children() {
        let child1 = Node::new("child1", Primitive::U32(42));
        let child2 = Node::new("child2", Primitive::Boolean(true));
        let parent = Node::with_children("parent", Primitive::None, vec![child1, child2]);

        let json = serde_json::to_string(&parent).unwrap();
        let deserialized: Node = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.label, "parent");
        assert_eq!(deserialized.children.len(), 2);
        assert_eq!(deserialized.children[0].label, "child1");
        assert_eq!(deserialized.children[1].label, "child2");
    }
}

