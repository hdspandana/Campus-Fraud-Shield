from PIL import Image
import pytesseract
import numpy as np
import cv2
import os

# ── Set Tesseract path (Windows) ─────────────────────────────────────────────
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Optional: Fix ZBar DLL path (only if needed)
try:
    os.add_dll_directory(r"C:\Program Files (x86)\ZBar\bin\bin")
except Exception:
    pass


# ─────────────────────────────────────────────────────────────────────────────
# OCR FUNCTION
# ─────────────────────────────────────────────────────────────────────────────
def extract_text_from_image(image_file) -> tuple[bool, str]:
    try:
        img = Image.open(image_file).convert("RGB")
        img_np = np.array(img)

        # Preprocessing
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)
        gray = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        gray = cv2.GaussianBlur(gray, (5, 5), 0)
        _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)

        config = r'--oem 3 --psm 6'
        text = pytesseract.image_to_string(thresh, config=config).strip()

        if not text:
            return False, "No text found in image. Try a clearer screenshot."

        return True, text

    except Exception as e:
        return False, f"OCR error: {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
# QR FUNCTION (Hybrid)
# ─────────────────────────────────────────────────────────────────────────────
def decode_qr_code(image_file) -> tuple[bool, str]:
    try:
        import cv2
        import numpy as np
        from PIL import Image

        img = Image.open(image_file).convert("RGB")
        img_np = np.array(img)

        # ---------- FIX 1: Add white border (quiet zone) ----------
        img_np = cv2.copyMakeBorder(
            img_np, 50, 50, 50, 50,
            cv2.BORDER_CONSTANT, value=[255, 255, 255]
        )

        # ---------- FIX 2: Remove bottom-right logo area ----------
        h, w = img_np.shape[:2]
        img_np = img_np[0:int(h*0.9), 0:int(w*0.9)]

        detector = cv2.QRCodeDetector()

        # ---------- 1. Original ----------
        data, _, _ = detector.detectAndDecode(img_np)
        if data:
            return True, f"[OpenCV] {data}"

        # ---------- 2. Grayscale ----------
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)
        data, _, _ = detector.detectAndDecode(gray)
        if data:
            return True, f"[Gray] {data}"

        # ---------- 3. Resize (VERY IMPORTANT) ----------
        resized = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        data, _, _ = detector.detectAndDecode(resized)
        if data:
            return True, f"[Resized] {data}"

        # ---------- 4. Threshold ----------
        _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)
        data, _, _ = detector.detectAndDecode(thresh)
        if data:
            return True, f"[Threshold] {data}"

        # ---------- 5. pyzbar fallback ----------
        try:
            from pyzbar.pyzbar import decode as pyzbar_decode

            decoded = pyzbar_decode(img_np) or pyzbar_decode(gray)

            if decoded:
                return True, f"[pyzbar] {decoded[0].data.decode('utf-8')}"

        except Exception:
            pass

        return False, "No QR detected. Try zooming/cropping the QR area."

    except Exception as e:
        return False, f"QR decode error: {str(e)}"

# ─────────────────────────────────────────────────────────────────────────────
# MAIN HANDLER (IMPORTANT FOR IMPORT)
# ─────────────────────────────────────────────────────────────────────────────
def process_upload(image_file, mode: str) -> tuple[bool, str, str]:
    if mode == "ocr":
        ok, text = extract_text_from_image(image_file)
        return ok, text, "📸 Extracted from screenshot (OCR)"

    elif mode == "qr":
        ok, text = decode_qr_code(image_file)
        return ok, text, "📷 Decoded from QR code"

    else:
        return False, "Unknown mode", ""