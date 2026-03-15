import os
import cv2
import time
import logging
import concurrent.futures
import base64
import json
import hashlib
import re
import tkinter as tk
from tkinter import messagebox, simpledialog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Modular Imports
from detection.object_detector import detect_pii
from detection.face_detector import detect_faces
from ocr.text_extractor import extract_text_with_indices, get_pii_boxes_advanced
from nlp.presidio_engine import analyze_text

# --- 1. SETTINGS ---
os.environ['KMP_DUPLICATE_LIB_OK'] = 'True'
logging.getLogger("ultralytics").setLevel(logging.ERROR)

SCREENSHOT_DIR = r"C:\Users\naden\OneDrive\Screenshots"
OUTPUT_DIR = r"C:\pythonprojects\output"

# Configuration constants from your research parameters
SURGICAL_PADDING = 5
MOSAIC_RATIO = 0.05
DARKNESS_FACTOR = 0.5

SENSITIVE_LABELS = {
    'credit_card', 'id_number', 'card_number', 'email',
    'aadhaar_number', 'face', 'phone_number', 'in_pan', 'pan',
    'permanent_account_number', 'financial_data'
}


# --- 2. BOX UTILITIES ---
def merge_overlapping_boxes(boxes, tolerance=5):
    if not boxes: return []
    boxes = sorted(boxes, key=lambda x: x[1])
    merged = []
    while boxes:
        curr = boxes.pop(0)
        has_overlap = False
        for i, m in enumerate(merged):
            if not (curr[0] > m[2] + tolerance or curr[2] < m[0] - tolerance or
                    curr[1] > m[3] + tolerance or curr[3] < m[1] - tolerance):
                merged[i] = [min(curr[0], m[0]), min(curr[1], m[1]),
                             max(curr[2], m[2]), max(curr[3], m[3])]
                has_overlap = True
                break
        if not has_overlap:
            merged.append(curr)
    return merged


# --- 3. HTML ENGINE ---
def generate_interactive_html(img_path, key_data, output_html_path, password):
    try:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        with open(img_path, "rb") as img_file:
            img_base64 = base64.b64encode(img_file.read()).decode('utf-8')

        js_vault = []
        for item in key_data:
            x1, y1, x2, y2 = map(int, item['bbox'])
            _, buffer = cv2.imencode('.png', item['pixels'])
            js_vault.append({
                "x": x1, "y": y1, "w": x2 - x1, "h": y2 - y1,
                "data": base64.b64encode(buffer).decode('utf-8')
            })

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Viewer</title>
            <style>
                body {{ font-family: sans-serif; text-align: center; background: #0a0a0a; color: white; padding: 20px; }}
                canvas {{ border: 1px solid #00e676; border-radius: 8px; max-width: 95%; }}
                .btn {{ background: #00e676; color: #000; border: none; padding: 10px 20px; font-weight: bold; cursor: pointer; border-radius: 5px; }}
            </style>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
        </head>
        <body>
            <h2> PII Guard Secure Viewer</h2>
            <button class="btn" onclick="ul()">REVEAL CONTENT</button><br><br>
            <canvas id="cvs"></canvas>
            <script>
                const v = {json.dumps(js_vault)};
                const h = "{password_hash}";
                const cvs = document.getElementById('cvs');
                const ctx = cvs.getContext('2d');
                const m = new Image();
                m.src = "data:image/png;base64,{img_base64}";
                m.onload = () => {{ cvs.width = m.width; cvs.height = m.height; ctx.drawImage(m, 0, 0); }};
                function ul() {{
                    const p = prompt("Password:");
                    if(CryptoJS.SHA256(p).toString() === h) {{
                        v.forEach(i => {{
                            const pImg = new Image();
                            pImg.onload = () => ctx.drawImage(pImg, i.x, i.y, i.w, i.h);
                            pImg.src = "data:image/png;base64," + i.data;
                        }});
                    }} else {{ alert("Invalid password."); }}
                }}
            </script>
        </body>
        </html>
        """
        with open(output_html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return True
    except Exception as e:
        print(f"❌ HTML Error: {e}")
        return False


# --- 4. CORE PROCESSING ---
class ScreenshotHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            time.sleep(2.5)
            self.process_image(event.src_path)

    @staticmethod
    def process_image(image_path):
        img_name = os.path.basename(image_path)
        image = cv2.imread(image_path)
        if image is None: return
        h, w = image.shape[:2]

        # Parallel Detection Streams
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            f_ocr = executor.submit(extract_text_with_indices, image)
            f_yolo = executor.submit(detect_pii, image)
            f_face = executor.submit(detect_faces, image)
            full_text, ocr_items = f_ocr.result()
            raw_yolo = f_yolo.result()
            faces = f_face.result()
        model_stats = {"NLP Engine": 0, "YOLO Detector": 0, "Face Detector": 0, "PAN Regex": 0}

        # PAN Logic utilizing spatial analysis
        pan_pattern = re.compile(r'[A-Z]{5}[0-9]{4}[A-Z]{1}')
        pan_matches = []

        for item in ocr_items:
            clean_item = "".join(item['text'].split()).upper()
            if pan_pattern.search(clean_item):
                pan_matches.append({'bbox': item['bbox']})
                model_stats["PAN Regex"] += 1

        if model_stats["PAN Regex"] == 0:
            clean_full = "".join(full_text.split()).upper()
            if pan_pattern.search(clean_full):
                for item in ocr_items:
                    part_text = "".join(item['text'].split()).upper()
                    if any(char in part_text for char in "0123456789"):
                        pan_matches.append({'bbox': item['bbox']})
                model_stats["PAN Regex"] = 1

        nlp_boxes = get_pii_boxes_advanced(ocr_items, analyze_text(full_text))  #
        model_stats["NLP Engine"] = len(nlp_boxes)

        yolo_boxes = [obj for obj in raw_yolo if str(obj.get('label', '')).lower() in SENSITIVE_LABELS]  #
        model_stats["YOLO Detector"] = len(yolo_boxes)
        model_stats["Face Detector"] = len(faces)

        all_detections = nlp_boxes + yolo_boxes + faces + pan_matches
        if not all_detections:
            print(f"✅ Clean: {img_name}")
            return

        rects = [[max(0, int(b[0]) - SURGICAL_PADDING), max(0, int(b[1]) - SURGICAL_PADDING),
                  min(w, int(b[2]) + SURGICAL_PADDING), min(h, int(b[3]) + SURGICAL_PADDING)]
                 for det in all_detections if (b := det.get('bbox') or det.get('box'))]

        final_rects = merge_overlapping_boxes(rects)

        # --- UPDATED POPUP WITH RISK ANALYSIS ---
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)

        # Risk assessment logic
        is_high_risk = model_stats["PAN Regex"] > 0 or model_stats["YOLO Detector"] > 0
        risk_level = "HIGH RISK" if is_high_risk else "MODERATE RISK"

        breakdown = "\n".join([f"• {m}: {c}" for m, c in model_stats.items() if c > 0])
        display_text = (
            f"Risk Analysis: {risk_level}\n"
            f"----------------------------------------\n"
            f"Breakdown for {img_name}:\n\n"
            f"{breakdown}\n\n"
            f"Secure file?"
        )

        if messagebox.askyesno("PII Detected", display_text):
            pw = simpledialog.askstring("Security", "Set password:", show='*')
            if pw:
                redacted = image.copy()
                key_data = []
                for box in final_rects:
                    x1, y1, x2, y2 = map(int, box)
                    key_data.append({'bbox': [x1, y1, x2, y2], 'pixels': image[y1:y2, x1:x2].copy()})

                    # Your original Mosaic-resize blurring logic
                    roi = redacted[y1:y2, x1:x2]
                    if roi.size > 0:
                        rh, rw = roi.shape[:2]
                        small = cv2.resize(roi, (max(1, int(rw * MOSAIC_RATIO)), max(1, int(rh * MOSAIC_RATIO))),
                                           interpolation=cv2.INTER_LINEAR)
                        redacted[y1:y2, x1:x2] = cv2.convertScaleAbs(
                            cv2.resize(small, (rw, rh), interpolation=cv2.INTER_NEAREST), alpha=DARKNESS_FACTOR, beta=0)

                ts = int(time.time())
                out_fn = os.path.join(OUTPUT_DIR, f"SAFE_{ts}_{img_name.split('.')[0]}")
                cv2.imwrite(f"{out_fn}.png", redacted)
                generate_interactive_html(f"{out_fn}.png", key_data, f"{out_fn}.html", pw)
                print(f"🛡️ SECURED: {out_fn}.html")
        root.destroy()


def start_watcher():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    obs = Observer()
    obs.schedule(ScreenshotHandler(), SCREENSHOT_DIR, recursive=False)
    obs.start()
    print("📡 WATCHER ACTIVE...")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        obs.stop();
        obs.join()


if __name__ == "__main__":
    start_watcher()