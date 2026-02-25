#!/usr/bin/env python
"""
Steganography Tools — Modern GUI
Dark-themed Tkinter application with sidebar navigation.
Supports: Image / Text / Audio / Video steganography + Steganalysis + Batch Encode
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys

# Ensure modules directory is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import image_steg, text_steg, audio_steg, video_steg, steganalysis, batch_encode

# ── Color Palette ─────────────────────────────────────────────────────────────
BG_DARK      = "#0d1117"
BG_PANEL     = "#161b22"
BG_CARD      = "#21262d"
BG_INPUT     = "#1c2128"
ACCENT       = "#58a6ff"
ACCENT_HOVER = "#79c0ff"
SUCCESS      = "#3fb950"
WARNING      = "#d29922"
DANGER       = "#f85149"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
BORDER       = "#30363d"
SIDEBAR_W    = 200


# ── Helper Widgets ────────────────────────────────────────────────────────────

class StyledButton(tk.Button):
    def __init__(self, parent, text, command=None, color=ACCENT, **kw):
        super().__init__(
            parent, text=text, command=command,
            bg=color, fg=BG_DARK, activebackground=ACCENT_HOVER,
            activeforeground=BG_DARK, relief="flat", cursor="hand2",
            font=("Segoe UI", 10, "bold"), padx=14, pady=7,
            bd=0, **kw
        )
        self.bind("<Enter>", lambda e: self.config(bg=ACCENT_HOVER))
        self.bind("<Leave>", lambda e: self.config(bg=color))


class FilePickerRow(tk.Frame):
    """Label + entry + Browse button on one row."""
    def __init__(self, parent, label, filetypes=None, save=False, **kw):
        super().__init__(parent, bg=BG_CARD, **kw)
        self._save = save
        self._filetypes = filetypes or [("All files", "*.*")]
        tk.Label(self, text=label, bg=BG_CARD, fg=TEXT_MUTED,
                 font=("Segoe UI", 9), width=18, anchor="w").pack(side="left")
        self.var = tk.StringVar()
        tk.Entry(self, textvariable=self.var, bg=BG_INPUT, fg=TEXT_PRIMARY,
                 insertbackground=TEXT_PRIMARY, relief="flat",
                 font=("Segoe UI", 9), bd=4).pack(side="left", fill="x", expand=True)
        tk.Button(self, text="…", bg=BG_PANEL, fg=ACCENT, relief="flat",
                  cursor="hand2", command=self._browse,
                  font=("Segoe UI", 9, "bold"), padx=6).pack(side="left", padx=(4, 0))

    def _browse(self):
        if self._save:
            path = filedialog.asksaveasfilename(filetypes=self._filetypes)
        else:
            path = filedialog.askopenfilename(filetypes=self._filetypes)
        if path:
            self.var.set(path)

    def get(self):
        return self.var.get().strip()

    def set(self, val):
        self.var.set(val)


class StatusBar(tk.Label):
    def __init__(self, parent, **kw):
        super().__init__(parent, text="Ready", bg=BG_PANEL, fg=TEXT_MUTED,
                         font=("Segoe UI", 9), anchor="w", padx=10, **kw)

    def set(self, msg, color=TEXT_MUTED):
        self.config(text=msg, fg=color)
        self.update_idletasks()

    def success(self, msg): self.set("✔  " + msg, SUCCESS)
    def error(self, msg):   self.set("✘  " + msg, DANGER)
    def info(self, msg):    self.set("ℹ  " + msg, ACCENT)


def labeled_entry(parent, label, show=None, width=40):
    """Return (frame, StringVar)."""
    f = tk.Frame(parent, bg=BG_CARD)
    tk.Label(f, text=label, bg=BG_CARD, fg=TEXT_MUTED,
             font=("Segoe UI", 9), width=18, anchor="w").pack(side="left")
    var = tk.StringVar()
    tk.Entry(f, textvariable=var, bg=BG_INPUT, fg=TEXT_PRIMARY,
             insertbackground=TEXT_PRIMARY, relief="flat",
             font=("Segoe UI", 9), bd=4, show=show, width=width).pack(side="left", fill="x", expand=True)
    return f, var


def section_title(parent, text):
    tk.Label(parent, text=text, bg=BG_CARD, fg=ACCENT,
             font=("Segoe UI", 13, "bold"), anchor="w").pack(fill="x", padx=20, pady=(18, 4))
    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=20, pady=(0, 12))


def msg_box(parent):
    """Scrolled text box for message input/output."""
    f = tk.Frame(parent, bg=BG_CARD)
    tk.Label(f, text="Message", bg=BG_CARD, fg=TEXT_MUTED,
             font=("Segoe UI", 9), anchor="w").pack(fill="x", padx=20)
    txt = scrolledtext.ScrolledText(f, height=5, bg=BG_INPUT, fg=TEXT_PRIMARY,
                                    insertbackground=TEXT_PRIMARY, relief="flat",
                                    font=("Consolas", 10), bd=6, wrap="word",
                                    selectbackground=ACCENT)
    txt.pack(fill="x", padx=20, pady=(2, 10))
    return f, txt


# ── Panels ────────────────────────────────────────────────────────────────────

class ImagePanel(tk.Frame):
    def __init__(self, parent, status: StatusBar):
        super().__init__(parent, bg=BG_CARD)
        self._status = status
        self._build()

    def _build(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=16, pady=16)
        self._enc = tk.Frame(nb, bg=BG_CARD)
        self._dec = tk.Frame(nb, bg=BG_CARD)
        nb.add(self._enc, text="  Encode  ")
        nb.add(self._dec, text="  Decode  ")
        self._build_encode()
        self._build_decode()

    def _build_encode(self):
        p = self._enc
        section_title(p, "Image Steganography — Encode")
        self._e_cover = FilePickerRow(p, "Cover Image",
                                      [("Images", "*.png *.jpg *.jpeg *.bmp")])
        self._e_cover.pack(fill="x", padx=20, pady=3)
        self._e_out = FilePickerRow(p, "Output Image",
                                    [("PNG", "*.png"), ("BMP", "*.bmp")], save=True)
        self._e_out.pack(fill="x", padx=20, pady=3)
        ef, self._e_pw = labeled_entry(p, "Password (AES, optional)", show="•")
        ef.pack(fill="x", padx=20, pady=3)
        mf, self._e_msg = msg_box(p)
        mf.pack(fill="x")
        self._e_prog = ttk.Progressbar(p, mode="indeterminate")
        self._e_prog.pack(fill="x", padx=20, pady=(4, 0))
        StyledButton(p, "  🔒  Encode & Save", self._encode).pack(padx=20, pady=12, anchor="w")

    def _build_decode(self):
        p = self._dec
        section_title(p, "Image Steganography — Decode")
        self._d_stego = FilePickerRow(p, "Stego Image",
                                      [("Images", "*.png *.jpg *.jpeg *.bmp")])
        self._d_stego.pack(fill="x", padx=20, pady=3)
        df, self._d_pw = labeled_entry(p, "Password (if used)", show="•")
        df.pack(fill="x", padx=20, pady=3)
        section_title(p, "Recovered Message")
        self._d_out = scrolledtext.ScrolledText(p, height=6, state="disabled",
                                                bg=BG_INPUT, fg=SUCCESS, relief="flat",
                                                font=("Consolas", 10), bd=6, wrap="word")
        self._d_out.pack(fill="x", padx=20, pady=(0, 10))
        StyledButton(p, "  🔓  Decode", self._decode).pack(padx=20, pady=4, anchor="w")

    def _encode(self):
        cover = self._e_cover.get()
        out   = self._e_out.get()
        pw    = self._e_pw.get()
        msg   = self._e_msg.get("1.0", "end-1c").strip()
        if not cover or not out or not msg:
            self._status.error("Cover image, output path and message are required.")
            return
        self._e_prog.start(10)
        self._status.info("Encoding…")
        def run():
            try:
                image_steg.encode(cover, out, msg, pw)
                self._e_prog.stop(); self._e_prog["value"] = 0
                self._status.success(f"Encoded successfully → {os.path.basename(out)}")
            except Exception as ex:
                self._e_prog.stop()
                self._status.error(str(ex))
        threading.Thread(target=run, daemon=True).start()

    def _decode(self):
        stego = self._d_stego.get()
        pw    = self._d_pw.get()
        if not stego:
            self._status.error("Please select a stego image.")
            return
        self._status.info("Decoding…")
        def run():
            try:
                msg = image_steg.decode(stego, pw)
                self._d_out.config(state="normal")
                self._d_out.delete("1.0", "end")
                self._d_out.insert("end", msg)
                self._d_out.config(state="disabled")
                self._status.success("Message decoded successfully.")
            except Exception as ex:
                self._status.error(str(ex))
        threading.Thread(target=run, daemon=True).start()


class TextPanel(tk.Frame):
    def __init__(self, parent, status: StatusBar):
        super().__init__(parent, bg=BG_CARD)
        self._status = status
        self._build()

    def _build(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=16, pady=16)
        enc = tk.Frame(nb, bg=BG_CARD); dec = tk.Frame(nb, bg=BG_CARD)
        nb.add(enc, text="  Encode  "); nb.add(dec, text="  Decode  ")

        # Encode tab
        section_title(enc, "Text Steganography — Encode")
        self._e_cover = FilePickerRow(enc, "Cover Text File", [("Text", "*.txt")])
        self._e_cover.pack(fill="x", padx=20, pady=3)
        self._e_out = FilePickerRow(enc, "Output Stego File", [("Text", "*.txt")], save=True)
        self._e_out.pack(fill="x", padx=20, pady=3)
        mf, self._e_msg = msg_box(enc); mf.pack(fill="x")
        StyledButton(enc, "  🔒  Encode & Save", self._encode).pack(padx=20, pady=12, anchor="w")

        # Decode tab
        section_title(dec, "Text Steganography — Decode")
        self._d_stego = FilePickerRow(dec, "Stego Text File", [("Text", "*.txt")])
        self._d_stego.pack(fill="x", padx=20, pady=3)
        section_title(dec, "Recovered Message")
        self._d_out = scrolledtext.ScrolledText(dec, height=6, state="disabled",
                                                bg=BG_INPUT, fg=SUCCESS, relief="flat",
                                                font=("Consolas", 10), bd=6, wrap="word")
        self._d_out.pack(fill="x", padx=20, pady=(0, 10))
        StyledButton(dec, "  🔓  Decode", self._decode).pack(padx=20, pady=4, anchor="w")

    def _encode(self):
        cover = self._e_cover.get(); out = self._e_out.get()
        msg = self._e_msg.get("1.0", "end-1c").strip()
        if not cover or not out or not msg:
            self._status.error("Cover file, output path and message are required."); return
        try:
            text_steg.encode(cover, out, msg)
            self._status.success(f"Encoded → {os.path.basename(out)}")
        except Exception as ex:
            self._status.error(str(ex))

    def _decode(self):
        stego = self._d_stego.get()
        if not stego:
            self._status.error("Please select a stego file."); return
        try:
            msg = text_steg.decode(stego)
            self._d_out.config(state="normal"); self._d_out.delete("1.0", "end")
            self._d_out.insert("end", msg); self._d_out.config(state="disabled")
            self._status.success("Message decoded.")
        except Exception as ex:
            self._status.error(str(ex))


class AudioPanel(tk.Frame):
    def __init__(self, parent, status: StatusBar):
        super().__init__(parent, bg=BG_CARD)
        self._status = status
        self._build()

    def _build(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=16, pady=16)
        enc = tk.Frame(nb, bg=BG_CARD); dec = tk.Frame(nb, bg=BG_CARD)
        nb.add(enc, text="  Encode  "); nb.add(dec, text="  Decode  ")

        # Encode
        section_title(enc, "Audio Steganography — Encode")
        self._e_cover = FilePickerRow(enc, "Cover WAV File", [("WAV", "*.wav")])
        self._e_cover.pack(fill="x", padx=20, pady=3)
        self._e_out = FilePickerRow(enc, "Output Stego WAV", [("WAV", "*.wav")], save=True)
        self._e_out.pack(fill="x", padx=20, pady=3)
        mf, self._e_msg = msg_box(enc); mf.pack(fill="x")
        self._e_prog = ttk.Progressbar(enc, mode="indeterminate")
        self._e_prog.pack(fill="x", padx=20, pady=(4, 0))
        StyledButton(enc, "  🔒  Encode & Save", self._encode).pack(padx=20, pady=12, anchor="w")

        # Decode
        section_title(dec, "Audio Steganography — Decode")
        self._d_stego = FilePickerRow(dec, "Stego WAV File", [("WAV", "*.wav")])
        self._d_stego.pack(fill="x", padx=20, pady=3)
        section_title(dec, "Recovered Message")
        self._d_out = scrolledtext.ScrolledText(dec, height=6, state="disabled",
                                                bg=BG_INPUT, fg=SUCCESS, relief="flat",
                                                font=("Consolas", 10), bd=6, wrap="word")
        self._d_out.pack(fill="x", padx=20, pady=(0, 10))
        StyledButton(dec, "  🔓  Decode", self._decode).pack(padx=20, pady=4, anchor="w")

    def _encode(self):
        cover = self._e_cover.get(); out = self._e_out.get()
        msg = self._e_msg.get("1.0", "end-1c").strip()
        if not cover or not out or not msg:
            self._status.error("All fields required."); return
        self._e_prog.start(10); self._status.info("Encoding audio…")
        def run():
            try:
                audio_steg.encode(cover, out, msg)
                self._e_prog.stop()
                self._status.success(f"Audio encoded → {os.path.basename(out)}")
            except Exception as ex:
                self._e_prog.stop(); self._status.error(str(ex))
        threading.Thread(target=run, daemon=True).start()

    def _decode(self):
        stego = self._d_stego.get()
        if not stego:
            self._status.error("Select a stego WAV file."); return
        self._status.info("Decoding audio…")
        def run():
            try:
                msg = audio_steg.decode(stego)
                self._d_out.config(state="normal"); self._d_out.delete("1.0", "end")
                self._d_out.insert("end", msg); self._d_out.config(state="disabled")
                self._status.success("Message decoded.")
            except Exception as ex:
                self._status.error(str(ex))
        threading.Thread(target=run, daemon=True).start()


class VideoPanel(tk.Frame):
    def __init__(self, parent, status: StatusBar):
        super().__init__(parent, bg=BG_CARD)
        self._status = status
        self._build()

    def _build(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=16, pady=16)
        enc = tk.Frame(nb, bg=BG_CARD); dec = tk.Frame(nb, bg=BG_CARD)
        nb.add(enc, text="  Encode  "); nb.add(dec, text="  Decode  ")

        # Encode
        section_title(enc, "Video Steganography — Encode")
        self._e_cover = FilePickerRow(enc, "Cover Video", [("Video", "*.mp4 *.avi")])
        self._e_cover.pack(fill="x", padx=20, pady=3)
        self._e_out = FilePickerRow(enc, "Output Stego Video", [("AVI", "*.avi")], save=True)
        self._e_out.pack(fill="x", padx=20, pady=3)
        ef, self._e_key = labeled_entry(enc, "RC4 Key", show="•")
        ef.pack(fill="x", padx=20, pady=3)
        ff, self._e_frame = labeled_entry(enc, "Frame Number")
        ff.pack(fill="x", padx=20, pady=3)
        self._e_frame.set("1")
        mf, self._e_msg = msg_box(enc); mf.pack(fill="x")
        self._e_prog = ttk.Progressbar(enc, mode="indeterminate")
        self._e_prog.pack(fill="x", padx=20, pady=(4, 0))
        StyledButton(enc, "  🔒  Encode & Save", self._encode).pack(padx=20, pady=12, anchor="w")

        # Decode
        section_title(dec, "Video Steganography — Decode")
        self._d_stego = FilePickerRow(dec, "Stego Video", [("Video", "*.mp4 *.avi")])
        self._d_stego.pack(fill="x", padx=20, pady=3)
        dk, self._d_key = labeled_entry(dec, "RC4 Key", show="•")
        dk.pack(fill="x", padx=20, pady=3)
        dnf, self._d_frame = labeled_entry(dec, "Frame Number")
        dnf.pack(fill="x", padx=20, pady=3)
        self._d_frame.set("1")
        section_title(dec, "Recovered Message")
        self._d_out = scrolledtext.ScrolledText(dec, height=6, state="disabled",
                                                bg=BG_INPUT, fg=SUCCESS, relief="flat",
                                                font=("Consolas", 10), bd=6, wrap="word")
        self._d_out.pack(fill="x", padx=20, pady=(0, 10))
        StyledButton(dec, "  🔓  Decode", self._decode).pack(padx=20, pady=4, anchor="w")

    def _encode(self):
        cover = self._e_cover.get(); out = self._e_out.get()
        key = self._e_key.get(); msg = self._e_msg.get("1.0", "end-1c").strip()
        try: fn = int(self._e_frame.get())
        except ValueError:
            self._status.error("Frame number must be an integer."); return
        if not cover or not out or not key or not msg:
            self._status.error("All fields are required."); return
        self._e_prog.start(10); self._status.info("Encoding video (this may take a while)…")
        def run():
            try:
                video_steg.encode(cover, out, msg, key, fn)
                self._e_prog.stop()
                self._status.success(f"Video encoded → {os.path.basename(out)}")
            except Exception as ex:
                self._e_prog.stop(); self._status.error(str(ex))
        threading.Thread(target=run, daemon=True).start()

    def _decode(self):
        stego = self._d_stego.get(); key = self._d_key.get()
        try: fn = int(self._d_frame.get())
        except ValueError:
            self._status.error("Frame number must be an integer."); return
        if not stego or not key:
            self._status.error("Stego video and RC4 key are required."); return
        self._status.info("Decoding video…")
        def run():
            try:
                msg = video_steg.decode(stego, key, fn)
                self._d_out.config(state="normal"); self._d_out.delete("1.0", "end")
                self._d_out.insert("end", msg); self._d_out.config(state="disabled")
                self._status.success("Message decoded.")
            except Exception as ex:
                self._status.error(str(ex))
        threading.Thread(target=run, daemon=True).start()


class SteganalysisPanel(tk.Frame):
    def __init__(self, parent, status: StatusBar):
        super().__init__(parent, bg=BG_CARD)
        self._status = status
        self._files = []
        self._build()

    def _build(self):
        section_title(self, "Chi-Square Steganalysis")
        tk.Label(self, text="Detect whether an image likely contains hidden data.",
                 bg=BG_CARD, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(0, 10))

        btn_frame = tk.Frame(self, bg=BG_CARD)
        btn_frame.pack(fill="x", padx=20, pady=4)
        StyledButton(btn_frame, "  📂  Select Image(s)", self._pick).pack(side="left")
        self._lbl = tk.StringVar(value="No files selected")
        tk.Label(btn_frame, textvariable=self._lbl,
                 bg=BG_CARD, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(side="left", padx=12)

        self._prog = ttk.Progressbar(self, mode="indeterminate")
        self._prog.pack(fill="x", padx=20, pady=(6, 0))
        StyledButton(self, "  🔍  Analyse", self._analyse, color="#388bfd").pack(padx=20, pady=10, anchor="w")

        section_title(self, "Results")
        cols = ("File", "Chi-Stat", "Stego Probability", "Verdict")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", height=8)
        for c in cols:
            self._tree.heading(c, text=c)
            self._tree.column(c, anchor="w", minwidth=80)
        self._tree.column("File", width=180)
        self._tree.column("Chi-Stat", width=90)
        self._tree.column("Stego Probability", width=110)
        self._tree.column("Verdict", width=300)
        self._tree.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        style = ttk.Style()
        style.configure("Treeview", background=BG_INPUT, foreground=TEXT_PRIMARY,
                         rowheight=26, fieldbackground=BG_INPUT, borderwidth=0)
        style.configure("Treeview.Heading", background=BG_PANEL, foreground=ACCENT,
                         font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", ACCENT)])

    def _pick(self):
        paths = filedialog.askopenfilenames(
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp"), ("All", "*.*")])
        if paths:
            self._files = list(paths)
            self._lbl.set(f"{len(self._files)} file(s) selected")

    def _analyse(self):
        if not self._files:
            self._status.error("Select at least one image."); return
        self._prog.start(10); self._status.info("Analysing…")
        self._tree.delete(*self._tree.get_children())
        def run():
            results = steganalysis.batch_analyse(self._files)
            for r in results:
                tag = "danger" if (r["probability"] or 0) > 0.75 else \
                      "warn"   if (r["probability"] or 0) > 0.45 else "ok"
                self._tree.insert("", "end", values=(
                    os.path.basename(r["path"]),
                    r["chi_stat"] or "N/A",
                    f'{r["probability"]:.1%}' if r["probability"] is not None else "N/A",
                    r["verdict"]
                ), tags=(tag,))
            self._tree.tag_configure("danger", foreground=DANGER)
            self._tree.tag_configure("warn",   foreground=WARNING)
            self._tree.tag_configure("ok",     foreground=SUCCESS)
            self._prog.stop()
            self._status.success("Analysis complete.")
        threading.Thread(target=run, daemon=True).start()


class BatchPanel(tk.Frame):
    def __init__(self, parent, status: StatusBar):
        super().__init__(parent, bg=BG_CARD)
        self._status = status
        self._encode_images = []
        self._decode_images = []
        self._build()

    def _build(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=16, pady=16)
        enc = tk.Frame(nb, bg=BG_CARD); dec = tk.Frame(nb, bg=BG_CARD)
        nb.add(enc, text="  Batch Encode  "); nb.add(dec, text="  Batch Decode  ")
        self._build_encode(enc); self._build_decode(dec)

    def _build_encode(self, p):
        section_title(p, "Batch Encode — Spread Message Across Images")
        tk.Label(p, text="Select multiple cover images. The message will be split evenly across them.",
                 bg=BG_CARD, fg=TEXT_MUTED, font=("Segoe UI", 9), wraplength=520, justify="left"
                 ).pack(anchor="w", padx=20, pady=(0, 10))

        bf = tk.Frame(p, bg=BG_CARD); bf.pack(fill="x", padx=20, pady=4)
        StyledButton(bf, "  📂  Select Cover Images", self._pick_encode).pack(side="left")
        self._e_lbl = tk.Label(bf, text="No images selected", bg=BG_CARD, fg=TEXT_MUTED,
                                font=("Segoe UI", 9))
        self._e_lbl.pack(side="left", padx=12)

        of = tk.Frame(p, bg=BG_CARD); of.pack(fill="x", padx=20, pady=4)
        tk.Label(of, text="Output Directory", bg=BG_CARD, fg=TEXT_MUTED,
                 font=("Segoe UI", 9), width=18, anchor="w").pack(side="left")
        self._e_outdir = tk.StringVar()
        tk.Entry(of, textvariable=self._e_outdir, bg=BG_INPUT, fg=TEXT_PRIMARY,
                 insertbackground=TEXT_PRIMARY, relief="flat", font=("Segoe UI", 9), bd=4
                 ).pack(side="left", fill="x", expand=True)
        tk.Button(of, text="…", bg=BG_PANEL, fg=ACCENT, relief="flat", cursor="hand2",
                  command=self._pick_outdir, font=("Segoe UI", 9, "bold"), padx=6
                  ).pack(side="left", padx=(4, 0))

        pf, self._e_pw = labeled_entry(p, "Password (optional)", show="•")
        pf.pack(fill="x", padx=20, pady=3)
        mf, self._e_msg = msg_box(p); mf.pack(fill="x")
        StyledButton(p, "  🔒  Batch Encode", self._encode).pack(padx=20, pady=12, anchor="w")

        self._e_result = scrolledtext.ScrolledText(p, height=4, state="disabled",
                                                   bg=BG_INPUT, fg=SUCCESS, relief="flat",
                                                   font=("Consolas", 9), bd=6, wrap="word")
        self._e_result.pack(fill="x", padx=20, pady=(0, 10))

    def _build_decode(self, p):
        section_title(p, "Batch Decode — Reassemble Message")
        tk.Label(p, text="Select all stego images produced by Batch Encode (any order).",
                 bg=BG_CARD, fg=TEXT_MUTED, font=("Segoe UI", 9), wraplength=520, justify="left"
                 ).pack(anchor="w", padx=20, pady=(0, 10))

        bf = tk.Frame(p, bg=BG_CARD); bf.pack(fill="x", padx=20, pady=4)
        StyledButton(bf, "  📂  Select Stego Images", self._pick_decode).pack(side="left")
        self._d_lbl = tk.Label(bf, text="No images selected", bg=BG_CARD, fg=TEXT_MUTED,
                                font=("Segoe UI", 9))
        self._d_lbl.pack(side="left", padx=12)

        pf, self._d_pw = labeled_entry(p, "Password (if used)", show="•")
        pf.pack(fill="x", padx=20, pady=3)
        StyledButton(p, "  🔓  Batch Decode", self._decode).pack(padx=20, pady=12, anchor="w")

        section_title(p, "Reconstructed Message")
        self._d_out = scrolledtext.ScrolledText(p, height=8, state="disabled",
                                                bg=BG_INPUT, fg=SUCCESS, relief="flat",
                                                font=("Consolas", 10), bd=6, wrap="word")
        self._d_out.pack(fill="x", padx=20, pady=(0, 10))

    def _pick_encode(self):
        paths = filedialog.askopenfilenames(
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp"), ("All", "*.*")])
        if paths:
            self._encode_images = list(paths)
            self._e_lbl.config(text=f"{len(self._encode_images)} image(s) selected")

    def _pick_decode(self):
        paths = filedialog.askopenfilenames(
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp"), ("All", "*.*")])
        if paths:
            self._decode_images = list(paths)
            self._d_lbl.config(text=f"{len(self._decode_images)} image(s) selected")

    def _pick_outdir(self):
        d = filedialog.askdirectory()
        if d: self._e_outdir.set(d)

    def _encode(self):
        if not self._encode_images:
            self._status.error("Select cover images first."); return
        outdir = self._e_outdir.get()
        if not outdir:
            self._status.error("Select an output directory."); return
        pw = self._e_pw.get()
        msg = self._e_msg.get("1.0", "end-1c").strip()
        if not msg:
            self._status.error("Message cannot be empty."); return
        self._status.info("Batch encoding…")
        def run():
            try:
                out_paths = batch_encode.encode_batch(self._encode_images, outdir, msg, pw)
                self._e_result.config(state="normal"); self._e_result.delete("1.0", "end")
                self._e_result.insert("end", "\n".join(out_paths))
                self._e_result.config(state="disabled")
                self._status.success(f"Batch encoded {len(out_paths)} image(s).")
            except Exception as ex:
                self._status.error(str(ex))
        threading.Thread(target=run, daemon=True).start()

    def _decode(self):
        if not self._decode_images:
            self._status.error("Select stego images first."); return
        pw = self._d_pw.get()
        self._status.info("Batch decoding…")
        def run():
            try:
                msg = batch_encode.decode_batch(self._decode_images, pw)
                self._d_out.config(state="normal"); self._d_out.delete("1.0", "end")
                self._d_out.insert("end", msg); self._d_out.config(state="disabled")
                self._status.success("Message reconstructed.")
            except Exception as ex:
                self._status.error(str(ex))
        threading.Thread(target=run, daemon=True).start()


# ── Main Application ──────────────────────────────────────────────────────────

class SteganographyApp(tk.Tk):
    PAGES = [
        ("🖼  Image",       ImagePanel),
        ("📄  Text",        TextPanel),
        ("🎵  Audio",       AudioPanel),
        ("🎬  Video",       VideoPanel),
        ("🔍  Steganalysis", SteganalysisPanel),
        ("📦  Batch",       BatchPanel),
    ]

    def __init__(self):
        super().__init__()
        self.title("Steganography Tools")
        self.geometry("920x680")
        self.minsize(760, 560)
        self.configure(bg=BG_DARK)

        self._style_ttk()
        self._build_header()
        self._build_body()

    def _style_ttk(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=BG_CARD, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_PANEL, foreground=TEXT_MUTED,
                         font=("Segoe UI", 9), padding=[12, 6])
        style.map("TNotebook.Tab",
                   background=[("selected", BG_CARD)],
                   foreground=[("selected", ACCENT)])
        style.configure("TProgressbar", troughcolor=BG_INPUT, background=ACCENT,
                         thickness=4, borderwidth=0)

    def _build_header(self):
        hdr = tk.Frame(self, bg=BG_PANEL, height=56)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🛡  Steganography Tools", bg=BG_PANEL, fg=TEXT_PRIMARY,
                 font=("Segoe UI", 15, "bold")).pack(side="left", padx=20)
        tk.Label(hdr, text="Hide & Reveal Secret Messages", bg=BG_PANEL, fg=TEXT_MUTED,
                 font=("Segoe UI", 9)).pack(side="left", padx=(0, 20))
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    def _build_body(self):
        body = tk.Frame(self, bg=BG_DARK)
        body.pack(fill="both", expand=True)

        # Sidebar
        sidebar = tk.Frame(body, bg=BG_PANEL, width=SIDEBAR_W)
        sidebar.pack(fill="y", side="left")
        sidebar.pack_propagate(False)
        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", pady=(10, 4))

        # Content area
        self._content = tk.Frame(body, bg=BG_CARD)
        self._content.pack(fill="both", expand=True)

        # Status bar
        self._status = StatusBar(self)
        self._status.pack(fill="x", side="bottom")
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", side="bottom")

        # Build pages and sidebar buttons
        self._panels = {}
        self._sidebar_btns = {}
        self._active = None

        for (name, cls) in self.PAGES:
            panel = cls(self._content, self._status)
            panel.place(relx=0, rely=0, relwidth=1, relheight=1)
            self._panels[name] = panel

            btn = tk.Button(sidebar, text=name, bg=BG_PANEL, fg=TEXT_MUTED,
                             relief="flat", cursor="hand2", font=("Segoe UI", 10),
                             anchor="w", padx=16, pady=10, bd=0,
                             command=lambda n=name: self._show(n))
            btn.pack(fill="x")
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=BG_CARD) if b != self._active_btn else None)
            btn.bind("<Leave>", lambda e, b=btn, n=name: b.config(bg=BG_CARD if n == self._active else BG_PANEL))
            self._sidebar_btns[name] = btn

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", pady=6)

        # Show first page
        first = self.PAGES[0][0]
        self._active_btn = self._sidebar_btns[first]
        self._show(first)

    def _show(self, name: str):
        self._active = name
        for n, panel in self._panels.items():
            if n == name:
                panel.lift()
                self._sidebar_btns[n].config(bg=BG_CARD, fg=ACCENT,
                                              font=("Segoe UI", 10, "bold"))
                self._active_btn = self._sidebar_btns[n]
            else:
                self._sidebar_btns[n].config(bg=BG_PANEL, fg=TEXT_MUTED,
                                              font=("Segoe UI", 10))
        self._status.set("Ready")


if __name__ == "__main__":
    app = SteganographyApp()
    app.mainloop()
