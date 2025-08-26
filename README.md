# Image Steganography Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A secure image steganography application with encryption capabilities for hiding and extracting messages in images. This tool uses LSB (Least Significant Bit) steganography combined with Fernet symmetric encryption to provide a secure way to hide sensitive information within image files.

## Features

- **Message Hiding**: Embed encrypted messages within PNG or BMP image files
- **Message Extraction**: Extract and decrypt hidden messages from images
- **Password Protection**: Secure your hidden messages with password-based encryption
- **User-Friendly Interface**: Simple and intuitive GUI for easy operation
- **End-of-Message Detection**: Reliable message extraction with delimiter-based detection

## How It Works

1. **LSB Steganography**: The tool modifies the least significant bit of each color channel (RGB) in the image pixels to store the binary representation of the message. This causes minimal visual change to the image.

2. **Encryption**: Before hiding, the message is encrypted using Fernet symmetric encryption with a key derived from the user's password.

3. **Message Delimiter**: A special bit pattern is added to mark the end of the message, allowing for reliable extraction.

## Requirements

- Python 3.6+
- Pillow (PIL Fork)
- cryptography
- tkinter (usually comes with Python)

## Installation

```bash
# Clone the repository
git clone https://github.com/RYUO-00/Image-Steganography.git
cd Image-Steganography

# Install required packages
pip install -r requirements.txt
```

## Usage

```bash
python image_steganography.py
```

### Hiding a Message

1. Click "Browse" to select an input image (PNG or BMP format recommended)
2. Enter the message you want to hide in the text area
3. Click "Save As" to choose where to save the output image
4. Click "Hide Message" and enter a password when prompted
5. Your message is now securely hidden in the image

### Extracting a Message

1. Click "Browse" to select an image containing a hidden message
2. Click "Extract Message" and enter the password when prompted
3. The hidden message will appear in the text area

## Security Considerations

- The security of this tool relies on keeping your password secret
- Use strong, unique passwords for important messages
- The tool is intended for educational and legitimate privacy purposes
- Always comply with applicable laws and regulations

## Limitations

- Works best with lossless image formats (PNG, BMP)
- JPEG and other lossy formats may corrupt the hidden message due to compression
- Large messages require larger images to hide them
- The modified image should not be edited or resaved in a lossy format

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- This tool was created for educational purposes to demonstrate steganography and encryption concepts
- Uses the Fernet implementation from the Python cryptography package
