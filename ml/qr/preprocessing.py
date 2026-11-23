from io import BytesIO

import numpy as np
from PIL import Image

QR_IMAGE_SIZE = 69


def preprocess_qr_image(image_bytes: bytes) -> np.ndarray:
    """Convert an uploaded QR image to the dataset's 69x69 binary pixel format."""
    with Image.open(BytesIO(image_bytes)) as image:
        grayscale = image.convert("L").resize(
            (QR_IMAGE_SIZE, QR_IMAGE_SIZE),
            resample=Image.Resampling.NEAREST,
        )
        pixels = np.asarray(grayscale, dtype=np.uint8)
    return (pixels > 127).astype(np.uint8).reshape(1, -1)
