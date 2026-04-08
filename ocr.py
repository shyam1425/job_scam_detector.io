import pytesseract
from pdf2image import convert_from_bytes
from PIL import Image
import io

def extract_text(file_content, is_pdf=True):
    if is_pdf:
        images = convert_from_bytes(file_content)
        text = ''
        for img in images:
            text += pytesseract.image_to_string(img) + '\n'
    else:  # Image
        img = Image.open(io.BytesIO(file_content))
        text = pytesseract.image_to_string(img)
    return text.strip()
