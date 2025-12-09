import fitz  # PyMuPDF
import numpy as np
import os.path


def render_page_as_array(doc, page_number, zoom=2.0):
    page = doc.load_page(page_number)
    mat = fitz.Matrix(zoom, zoom)  # higher zoom = more precision
    pix = page.get_pixmap(matrix=mat, alpha=False)  # RGB only

    # Convert to numpy array (H, W, 3)
    img = np.frombuffer(pix.samples, dtype=np.uint8)
    img = img.reshape(pix.height, pix.width, 3)
    return img


def compare_images(img1, img2, tolerance=0):
    """Return True if different, False if identical."""
    if img1.shape != img2.shape:
        return True  # different size = visually different

    diff = np.abs(img1.astype(int) - img2.astype(int))
    if tolerance == 0:
        return np.any(diff != 0)
    else:
        return np.any(diff > tolerance)


def compare_pdfs_visually(pdf1_path, pdf2_path, zoom=2.0, tolerance=0):
    if not os.path.isfile(pdf2_path):
        return False
    doc1 = fitz.open(pdf1_path)
    doc2 = fitz.open(pdf2_path)

    if len(doc1) != len(doc2):
        print("Different number of pages.")
        return True

    visually_different = False

    for i in range(len(doc1)):
        print(f"Comparing page {i+1}/{len(doc1)}...")

        img1 = render_page_as_array(doc1, i, zoom)
        img2 = render_page_as_array(doc2, i, zoom)

        if compare_images(img1, img2, tolerance):
            print(f"Page {i+1} differs!")
            visually_different = True
        else:
            print(f"Page {i+1} is visually identical.")

    return visually_different
