#[cfg(test)]
use super::tree::{node_to_string_with_scheme, ColorScheme};
#[cfg(test)]
use crate::node::Node;
#[cfg(test)]
use std::env;
#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::io::{self, Write};

/// Ensure the generated tree output matches the fixture file
/// If the fixture doesn't exist, it will be created
#[cfg(test)]
pub fn assert_tree_matches_fixture(node: &Node, name: &str) -> Result<(), io::Error> {
    let no_color_scheme = ColorScheme::no_color();
    let generated = node_to_string_with_scheme(node, &no_color_scheme)?;

    let project_dir = env::current_dir().expect("Failed to get current directory");
    let fixtures_dir = project_dir.join("test").join("fixtures");
    let fixture_path = fixtures_dir.join(format!("{}.txt", name));

    if fixture_path.exists() {
        let fixture_content = fs::read_to_string(&fixture_path)?;
        // Compare the generated output to the fixture
        assert_eq!(
            generated, fixture_content,
            "Generated tree output doesn't match fixture file: {}",
            name
        );
    } else {
        // Create the fixture if it doesn't exist
        fs::create_dir_all(&fixtures_dir)?;
        let mut file = fs::File::create(&fixture_path)?;
        file.write_all(generated.as_bytes())?;
        println!("Created new fixture: {}.txt", name);
    }

    Ok(())
}

/// Assert tree matches fixture, updating if needed or requested
#[cfg(test)]
pub fn assert_or_update_fixture(node: &Node, name: &str) -> Result<(), io::Error> {
    let no_color_scheme = ColorScheme::no_color();
    let generated = node_to_string_with_scheme(node, &no_color_scheme)?;

    let project_dir = env::current_dir().expect("Failed to get current directory");
    let fixtures_dir = project_dir.join("test").join("fixtures");
    let fixture_path = fixtures_dir.join(format!("{}.txt", name));

    let update_fixtures = env::var("UPDATE_FIXTURES").is_ok();

    if fixture_path.exists() {
        let fixture_content = fs::read_to_string(&fixture_path)?;
        if update_fixtures || generated != fixture_content {
            let mut file = fs::File::create(&fixture_path)?;
            file.write_all(generated.as_bytes())?;
            println!("Updated fixture: {}.txt", name);
        } else {
            assert_eq!(
                generated, fixture_content,
                "Generated tree output doesn't match fixture file: {}",
                name
            );
        }
    } else {
        // Create the fixture if it doesn't exist
        fs::create_dir_all(&fixtures_dir)?;
        let mut file = fs::File::create(&fixture_path)?;
        file.write_all(generated.as_bytes())?;
        println!("Created new fixture: {}.txt", name);
    }

    Ok(())
}
