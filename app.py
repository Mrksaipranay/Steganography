"""
Steganography Tools — Flask Web Application
Run: python app.py
"""

import os
import sys
import uuid
import json
import threading
from pathlib import Path
from flask import Flask, request, jsonify, send_file, render_template_string
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules import image_steg, text_steg, audio_steg, steganalysis, batch_encode

# ── Config ────────────────────────────────────────────────────────────────────
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
OUTPUT_FOLDER = os.path.join(os.path.dirname(__file__), 'outputs')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

ALLOWED_IMAGE = {'png', 'jpg', 'jpeg', 'bmp'}
ALLOWED_AUDIO = {'wav'}
ALLOWED_TEXT  = {'txt'}


def allowed(filename, exts):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in exts


def save_upload(file, allowed_exts):
    if not allowed(file.filename, allowed_exts):
        raise ValueError(f"Unsupported file type. Allowed: {allowed_exts}")
    ext = file.filename.rsplit('.', 1)[1].lower()
    name = f"{uuid.uuid4().hex}.{ext}"
    path = os.path.join(UPLOAD_FOLDER, name)
    file.save(path)
    return path


def out_path(ext):
    return os.path.join(OUTPUT_FOLDER, f"{uuid.uuid4().hex}.{ext}")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    with open(os.path.join(os.path.dirname(__file__), 'web', 'index.html'), 'r', encoding='utf-8') as f:
        return f.read()


# --- Image Steganography ------------------------------------------------------

@app.route('/api/image/encode', methods=['POST'])
def image_encode():
    try:
        file = request.files.get('image')
        if not file:
            return jsonify(error="No image uploaded"), 400
        msg = request.form.get('message', '').strip()
        if not msg:
            return jsonify(error="Message is required"), 400
        pw = request.form.get('password', '')

        src = save_upload(file, ALLOWED_IMAGE)
        dst = out_path('png')
        image_steg.encode(src, dst, msg, pw)
        os.remove(src)
        return jsonify(success=True, file_id=os.path.basename(dst),
                       filename='stego_image.png')
    except Exception as e:
        return jsonify(error=str(e)), 400


@app.route('/api/image/decode', methods=['POST'])
def image_decode():
    try:
        file = request.files.get('image')
        if not file:
            return jsonify(error="No image uploaded"), 400
        pw = request.form.get('password', '')

        src = save_upload(file, ALLOWED_IMAGE)
        msg = image_steg.decode(src, pw)
        os.remove(src)
        return jsonify(success=True, message=msg)
    except Exception as e:
        return jsonify(error=str(e)), 400


# --- Text Steganography -------------------------------------------------------

@app.route('/api/text/encode', methods=['POST'])
def text_encode():
    try:
        cover = request.files.get('cover')
        if not cover:
            return jsonify(error="No cover text file uploaded"), 400
        msg = request.form.get('message', '').strip()
        if not msg:
            return jsonify(error="Message is required"), 400

        src = save_upload(cover, ALLOWED_TEXT)
        dst = out_path('txt')
        text_steg.encode(src, dst, msg)
        os.remove(src)
        return jsonify(success=True, file_id=os.path.basename(dst),
                       filename='stego_text.txt')
    except Exception as e:
        return jsonify(error=str(e)), 400


@app.route('/api/text/decode', methods=['POST'])
def text_decode():
    try:
        stego = request.files.get('stego')
        if not stego:
            return jsonify(error="No stego text file uploaded"), 400

        src = save_upload(stego, ALLOWED_TEXT)
        msg = text_steg.decode(src)
        os.remove(src)
        return jsonify(success=True, message=msg)
    except Exception as e:
        return jsonify(error=str(e)), 400


# --- Audio Steganography ------------------------------------------------------

@app.route('/api/audio/encode', methods=['POST'])
def audio_encode():
    try:
        file = request.files.get('audio')
        if not file:
            return jsonify(error="No audio file uploaded"), 400
        msg = request.form.get('message', '').strip()
        if not msg:
            return jsonify(error="Message is required"), 400

        src = save_upload(file, ALLOWED_AUDIO)
        dst = out_path('wav')
        audio_steg.encode(src, dst, msg)
        os.remove(src)
        return jsonify(success=True, file_id=os.path.basename(dst),
                       filename='stego_audio.wav')
    except Exception as e:
        return jsonify(error=str(e)), 400


@app.route('/api/audio/decode', methods=['POST'])
def audio_decode():
    try:
        file = request.files.get('audio')
        if not file:
            return jsonify(error="No audio file uploaded"), 400

        src = save_upload(file, ALLOWED_AUDIO)
        msg = audio_steg.decode(src)
        os.remove(src)
        return jsonify(success=True, message=msg)
    except Exception as e:
        return jsonify(error=str(e)), 400


# --- Steganalysis -------------------------------------------------------------

@app.route('/api/steganalysis', methods=['POST'])
def steg_analyse():
    try:
        files = request.files.getlist('images')
        if not files:
            return jsonify(error="No images uploaded"), 400

        paths = []
        names = []
        for f in files:
            p = save_upload(f, ALLOWED_IMAGE)
            paths.append(p)
            names.append(f.filename)

        results = steganalysis.batch_analyse(paths)
        for i, r in enumerate(results):
            r['filename'] = names[i]

        for p in paths:
            try: os.remove(p)
            except: pass

        return jsonify(success=True, results=results)
    except Exception as e:
        return jsonify(error=str(e)), 400


# --- Batch Encode -------------------------------------------------------------

@app.route('/api/batch/encode', methods=['POST'])
def batch_enc():
    try:
        files = request.files.getlist('images')
        if not files:
            return jsonify(error="No images uploaded"), 400
        msg = request.form.get('message', '').strip()
        if not msg:
            return jsonify(error="Message is required"), 400
        pw = request.form.get('password', '')

        paths = [save_upload(f, ALLOWED_IMAGE) for f in files]
        out_dir = os.path.join(OUTPUT_FOLDER, uuid.uuid4().hex)
        os.makedirs(out_dir, exist_ok=True)

        out_paths = batch_encode.encode_batch(paths, out_dir, msg, pw)
        for p in paths:
            try: os.remove(p)
            except: pass

        file_ids = [os.path.relpath(p, OUTPUT_FOLDER).replace('\\', '/') for p in out_paths]
        return jsonify(success=True, file_ids=file_ids,
                       count=len(out_paths))
    except Exception as e:
        return jsonify(error=str(e)), 400


@app.route('/api/batch/decode', methods=['POST'])
def batch_dec():
    try:
        files = request.files.getlist('images')
        if not files:
            return jsonify(error="No images uploaded"), 400
        pw = request.form.get('password', '')

        paths = [save_upload(f, ALLOWED_IMAGE) for f in files]
        msg = batch_encode.decode_batch(paths, pw)

        for p in paths:
            try: os.remove(p)
            except: pass

        return jsonify(success=True, message=msg)
    except Exception as e:
        return jsonify(error=str(e)), 400


# --- Download -----------------------------------------------------------------

@app.route('/api/download/<path:file_id>')
def download(file_id):
    # Prevent path traversal
    safe = os.path.normpath(os.path.join(OUTPUT_FOLDER, file_id))
    if not safe.startswith(os.path.normpath(OUTPUT_FOLDER)):
        return jsonify(error="Invalid file id"), 400
    if not os.path.exists(safe):
        return jsonify(error="File not found"), 404
    return send_file(safe, as_attachment=True)


# --- Image capacity info -------------------------------------------------------

@app.route('/api/image/capacity', methods=['POST'])
def image_capacity():
    try:
        file = request.files.get('image')
        if not file:
            return jsonify(error="No image uploaded"), 400
        src = save_upload(file, ALLOWED_IMAGE)
        cap = image_steg.max_capacity(src)
        os.remove(src)
        return jsonify(success=True, capacity_bytes=cap)
    except Exception as e:
        return jsonify(error=str(e)), 400


if __name__ == '__main__':
    print("\n🛡  Steganography Tools Web App")
    print("🌐  http://localhost:5000\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
