use crate::format::fixtures::assert_or_update_fixture;
use crate::node::{Node, Primitive};
use num_bigint::BigInt;

#[test]
fn test_simple_tree() -> std::io::Result<()> {
    // Create a simple tree
    let child1 = Node::new("name", Primitive::String("Alice".to_string()));
    let child2 = Node::new("age", Primitive::U8(30));
    let child3 = Node::new("active", Primitive::Boolean(true));

    let mut parent = Node::new("person", Primitive::None);
    parent.add_child(child1);
    parent.add_child(child2);
    parent.add_child(child3);

    // Check against fixture
    assert_or_update_fixture(&parent, "simple_tree")?;
    Ok(())
}

#[test]
fn test_complex_tree() -> std::io::Result<()> {
    // Create a more complex tree
    let address_street = Node::new("street", Primitive::String("123 Main St".to_string()));
    let address_city = Node::new("city", Primitive::String("Anytown".to_string()));
    let address_zip = Node::new("zip", Primitive::U16(12345));

    let mut address = Node::new("address", Primitive::None);
    address.add_child(address_street);
    address.add_child(address_city);
    address.add_child(address_zip);

    let phone1 = Node::new("home", Primitive::String("555-1234".to_string()));
    let phone2 = Node::new("work", Primitive::String("555-5678".to_string()));

    let mut phones = Node::new("phones", Primitive::None);
    phones.add_child(phone1);
    phones.add_child(phone2);

    let account_number = Node::new(
        "number",
        Primitive::Integer(BigInt::parse_bytes(b"9876543210123456", 10).unwrap()),
    );
    let account_balance = Node::new("balance", Primitive::I32(5000));

    let mut account = Node::new("account", Primitive::None);
    account.add_child(account_number);
    account.add_child(account_balance);

    let name = Node::new("name", Primitive::String("John Doe".to_string()));
    let age = Node::new("age", Primitive::U8(35));

    let mut person = Node::new("person", Primitive::None);
    person.add_child(name);
    person.add_child(age);
    person.add_child(address);
    person.add_child(phones);
    person.add_child(account);

    // Check against fixture
    assert_or_update_fixture(&person, "complex_tree")?;
    Ok(())
}

#[test]
fn test_buffer_display() -> std::io::Result<()> {
    // Test how binary data is formatted in the tree
    let small_buffer = Node::new("small", Primitive::Buffer(vec![1, 2, 3, 4]));
    assert_or_update_fixture(&small_buffer, "small_buffer")?;

    let large_buffer = Node::new("large", Primitive::Buffer((0..100).collect()));
    assert_or_update_fixture(&large_buffer, "large_buffer")?;

    Ok(())
}

#[test]
fn test_numeric_types() -> std::io::Result<()> {
    // Create a tree with all the numeric types
    let mut numbers = Node::new("numbers", Primitive::None);

    // Add signed integers
    numbers.add_child(Node::new("i8_min", Primitive::I8(i8::MIN)));
    numbers.add_child(Node::new("i8_max", Primitive::I8(i8::MAX)));
    numbers.add_child(Node::new("i16_min", Primitive::I16(i16::MIN)));
    numbers.add_child(Node::new("i16_max", Primitive::I16(i16::MAX)));
    numbers.add_child(Node::new("i32_min", Primitive::I32(i32::MIN)));
    numbers.add_child(Node::new("i32_max", Primitive::I32(i32::MAX)));
    numbers.add_child(Node::new("i64_min", Primitive::I64(i64::MIN)));
    numbers.add_child(Node::new("i64_max", Primitive::I64(i64::MAX)));

    // Add unsigned integers
    numbers.add_child(Node::new("u8_max", Primitive::U8(u8::MAX)));
    numbers.add_child(Node::new("u16_max", Primitive::U16(u16::MAX)));
    numbers.add_child(Node::new("u32_max", Primitive::U32(u32::MAX)));
    numbers.add_child(Node::new("u64_max", Primitive::U64(u64::MAX)));

    // Add a big integer
    numbers.add_child(Node::new(
        "bigint",
        Primitive::Integer(
            BigInt::parse_bytes(b"12345678901234567890123456789012345678901234567890", 10).unwrap(),
        ),
    ));

    // Check against fixture
    assert_or_update_fixture(&numbers, "numeric_types")?;
    Ok(())
}
