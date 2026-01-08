//! Run with: cargo +nightly -Zscript tools/create_ico.rs
//! Or compile and run: rustc tools/create_ico.rs -o create_ico && ./create_ico
//!
//! This creates a Windows ICO file from the PNG icon.

use std::fs::File;
use std::io::{Write, BufWriter};
use std::path::Path;

fn main() {
    let png_path = "assets/icon.png";
    let ico_path = "assets/icon.ico";

    // Read PNG file
    let png_data = std::fs::read(png_path).expect("Failed to read PNG file");

    // ICO format: we'll embed the PNG directly (modern ICO supports PNG)
    // ICO header: 6 bytes
    // ICO directory entry: 16 bytes per image
    // Image data: PNG bytes

    let mut ico = BufWriter::new(File::create(ico_path).expect("Failed to create ICO file"));

    // ICO Header (6 bytes)
    ico.write_all(&[0, 0]).unwrap();      // Reserved (must be 0)
    ico.write_all(&[1, 0]).unwrap();      // Type (1 = ICO)
    ico.write_all(&[1, 0]).unwrap();      // Number of images (1)

    // ICO Directory Entry (16 bytes)
    ico.write_all(&[0]).unwrap();         // Width (0 = 256)
    ico.write_all(&[0]).unwrap();         // Height (0 = 256)
    ico.write_all(&[0]).unwrap();         // Color palette (0 = no palette)
    ico.write_all(&[0]).unwrap();         // Reserved
    ico.write_all(&[1, 0]).unwrap();      // Color planes
    ico.write_all(&[32, 0]).unwrap();     // Bits per pixel

    // Size of image data (4 bytes, little-endian)
    let size = png_data.len() as u32;
    ico.write_all(&size.to_le_bytes()).unwrap();

    // Offset to image data (4 bytes, little-endian) = 6 + 16 = 22
    ico.write_all(&22u32.to_le_bytes()).unwrap();

    // PNG data
    ico.write_all(&png_data).unwrap();

    println!("Created {} ({} bytes)", ico_path, 22 + png_data.len());
}