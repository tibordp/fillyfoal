//! Lists every registered format: `cargo run --example formats`.

fn main() {
    let formats = fillyfoal::formats::FORMATS;
    for f in formats {
        println!("{:<14} {:<48} {}", f.name, f.title, f.extensions.join(", "));
    }
    println!("\n{} formats", formats.len());
}
