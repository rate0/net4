# Logo generator for Net4 reporting

import io
from PIL import Image, ImageDraw, ImageFont
import base64

def generate_logo(width=400, height=100, format='PNG'):
    """
    Generate a Net4 logo
    
    Args:
        width: Image width
        height: Image height
        format: Output format (PNG, JPEG)
        
    Returns:
        BytesIO object containing the image
    """
    # Create a transparent background image
    img = Image.new('RGBA', (width, height), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Define colors
    blue = (52, 152, 219)  # Main blue color
    accent = (41, 128, 185) # Accent blue
    dark = (24, 77, 110)    # Dark blue
    highlight = (231, 76, 60) # Red highlight
    
    # Draw a network-like background pattern
    for x in range(0, width, 30):
        for y in range(0, height, 30):
            if (x + y) % 60 == 0:
                # Draw connection nodes
                draw.ellipse((x-3, y-3, x+3, y+3), fill=dark)
            
            # Draw some connecting lines
            if x < width - 30 and y < height - 30:
                # Diagonal line
                draw.line((x, y, x+30, y+30), fill=dark, width=1)
                
                # Horizontal or vertical line (alternating)
                if (x + y) % 60 == 0:
                    draw.line((x, y, x+30, y), fill=dark, width=1)
                else:
                    draw.line((x, y, x, y+30), fill=dark, width=1)
    
    # Draw a stylized "NET4" text with a cyber-security look
    font_size = height // 2
    try:
        # Try to use Arial Bold if available
        font = ImageFont.truetype("Arial Bold", font_size)
    except IOError:
        # Fallback to default font
        font = ImageFont.load_default()
        
    # Calculate text position for centering
    text = "NET4"
    text_width = draw.textlength(text, font=font)
    text_x = (width - text_width) // 2
    text_y = (height - font_size) // 2 - 5
    
    # Draw text shadow for depth
    draw.text((text_x+2, text_y+2), text, font=font, fill=dark)
    
    # Draw main text
    draw.text((text_x, text_y), text, font=font, fill=blue)
    
    # Draw a highlight accent on the "4"
    accent_x = text_x + draw.textlength("NET", font=font)
    accent_width = draw.textlength("4", font=font)
    draw.text((accent_x, text_y), "4", font=font, fill=highlight)
    
    # Draw a tagline
    tagline = "Network Forensics Platform"
    try:
        # Try to use Arial if available
        small_font = ImageFont.truetype("Arial", height // 6)
    except IOError:
        # Fallback to default font
        small_font = ImageFont.load_default()
        
    tagline_width = draw.textlength(tagline, font=small_font)
    draw.text(
        ((width - tagline_width) // 2, text_y + font_size + 5),
        tagline,
        font=small_font,
        fill=accent
    )
    
    # Add a subtle shield icon behind the text to represent security
    shield_width = width // 4
    shield_height = height // 2
    shield_x = (width - shield_width) // 2
    shield_y = (height - shield_height) // 2
    
    # Shield path
    shield_points = [
        (shield_x, shield_y),
        (shield_x + shield_width, shield_y),
        (shield_x + shield_width, shield_y + shield_height * 0.7),
        (shield_x + shield_width // 2, shield_y + shield_height),
        (shield_x, shield_y + shield_height * 0.7)
    ]
    
    # Draw shield outline (behind text)
    for i in range(len(shield_points)):
        if i < len(shield_points) - 1:
            draw.line((shield_points[i], shield_points[i+1]), fill=accent, width=2)
        else:
            draw.line((shield_points[i], shield_points[0]), fill=accent, width=2)
    
    # Convert to desired format and return
    buffer = io.BytesIO()
    
    # If PNG format requested (with transparency)
    if format.upper() == 'PNG':
        img.save(buffer, format='PNG')
    else:
        # Convert to RGB for JPEG (no transparency)
        rgb_img = Image.new('RGB', img.size, (255, 255, 255))
        rgb_img.paste(img, mask=img.split()[3])  # Use alpha as mask
        rgb_img.save(buffer, format=format.upper())
    
    buffer.seek(0)
    return buffer

# Function to save logo to file
def save_logo(output_path, width=400, height=100, format='PNG'):
    buffer = generate_logo(width, height, format)
    with open(output_path, 'wb') as f:
        f.write(buffer.getvalue())
    return output_path

# Function to get logo as base64 encoded string
def get_logo_base64(width=400, height=100, format='PNG'):
    buffer = generate_logo(width, height, format)
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

# Generate logo if this script is run directly
if __name__ == "__main__":
    save_logo("net4_logo.png")
    print("Logo saved to net4_logo.png")
