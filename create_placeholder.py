from PIL import Image, ImageDraw, ImageFont
import os

def create_placeholder_image():
    # Create a 200x200 image with a light gray background
    width = 200
    height = 200
    image = Image.new('RGB', (width, height), '#f8f9fa')
    draw = ImageDraw.Draw(image)
    
    # Draw a border
    draw.rectangle([(0, 0), (width-1, height-1)], outline='#dee2e6', width=2)
    
    # Draw a question mark
    try:
        # Try to use Arial font, fallback to default if not available
        font = ImageFont.truetype("Arial", 60)
    except:
        font = ImageFont.load_default()
    
    # Draw the question mark
    text = "?"
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    x = (width - text_width) // 2
    y = (height - text_height) // 2
    draw.text((x, y), text, fill='#6c757d', font=font)
    
    # Ensure the directory exists
    os.makedirs('static/images', exist_ok=True)
    
    # Save the image
    image.save('static/images/no-chord.png')

if __name__ == '__main__':
    create_placeholder_image() 