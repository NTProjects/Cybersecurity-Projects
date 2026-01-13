"""Create application icon from an image file.

Usage:
    python tools/create_icon.py path/to/image.png

This will create icon.ico in src/soc_audit/gui/assets/

Requirements:
    pip install Pillow
"""
import sys
from pathlib import Path

def create_icon(image_path: str) -> None:
    """Convert image to .ico format with multiple sizes."""
    try:
        from PIL import Image
    except ImportError:
        print("Error: Pillow not installed. Run: pip install Pillow")
        sys.exit(1)
    
    # Load the image
    img = Image.open(image_path)
    
    # Convert to RGBA if needed (for transparency)
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    # Create multiple icon sizes
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    
    # Output path
    output_dir = Path(__file__).parent.parent / "src" / "soc_audit" / "gui" / "assets"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "icon.ico"
    
    # Also save as PNG for cross-platform support
    png_path = output_dir / "icon.png"
    
    # Resize to largest size and save as PNG
    img_256 = img.resize((256, 256), Image.Resampling.LANCZOS)
    img_256.save(png_path, format='PNG')
    print(f"Created: {png_path}")
    
    # Create .ico with multiple sizes
    icons = []
    for size in sizes:
        resized = img.resize(size, Image.Resampling.LANCZOS)
        icons.append(resized)
    
    # Save as .ico (first image is used, others are alternatives)
    icons[0].save(
        output_path,
        format='ICO',
        sizes=[(icon.width, icon.height) for icon in icons],
        append_images=icons[1:]
    )
    print(f"Created: {output_path}")
    print("\nIcon created successfully! Restart the GUI to see the new icon.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/create_icon.py path/to/image.png")
        print("\nTip: Use an image with transparent background for best results.")
        sys.exit(1)
    
    create_icon(sys.argv[1])
