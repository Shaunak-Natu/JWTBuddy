#!/usr/bin/env python3
"""
JWT PenTest Suite  //  security research tool
Features: Decode/Encode  |  Payload List Generator  |  Secret Cracker
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import time
import hmac
import hashlib
import base64
import json
import itertools
import string
import re
from datetime import datetime
from copy import deepcopy

# ── optional crypto ──────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, ec, utils
    from cryptography.hazmat.backends import default_backend
    import cryptography.hazmat.primitives.asymmetric.rsa as _rsa
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ═══════════════════════════════════════════════════════════════════════════════
#  PALETTE
# ═══════════════════════════════════════════════════════════════════════════════
BG       = "#0a0e14"
PANEL    = "#0d1521"
PANEL2   = "#111c2d"
BORDER   = "#1e2d45"
BORDER2  = "#253855"
ACCENT   = "#00d4ff"
ACCENT2  = "#00ff9f"
ACCENT3  = "#a78bfa"
WARNING  = "#ff6b35"
DIM      = "#2a3a50"
TEXT     = "#c8d8e8"
TEXT_DIM = "#4a6a8a"
SUCCESS  = "#00ff9f"
FAIL     = "#ff4444"
# colour-coded JWT parts
C_HEADER  = "#fb7185"   # red-pink  – header
C_PAYLOAD = "#a78bfa"   # violet    – payload
C_SIG     = "#34d399"   # teal      – signature

FONT_MONO  = ("Courier New", 9)
FONT_MONO2 = ("Courier New", 10)
FONT_HEAD  = ("Courier New", 11, "bold")
FONT_BIG   = ("Courier New", 16, "bold")
FONT_LABEL = ("Courier New", 8)

# ═══════════════════════════════════════════════════════════════════════════════
#  JWT CORE HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)

def parse_jwt(token: str):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Token must have exactly 3 dot-separated parts.")
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig     = b64url_decode(parts[2])
    return header, payload, parts[0], parts[1], sig

def encode_jwt(header: dict, payload: dict, secret_or_key: str, algorithm: str = None) -> str:
    alg = algorithm or header.get("alg", "HS256")
    header = dict(header)
    header["alg"] = alg
    h_enc = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_enc = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_enc}.{p_enc}".encode()
    sig = _sign(signing_input, secret_or_key, alg)
    return f"{h_enc}.{p_enc}.{b64url_encode(sig)}"

# ── HMAC algos ────────────────────────────────────────────────────────────────
HMAC_ALGOS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

def _sign(signing_input: bytes, key: str, alg: str) -> bytes:
    if alg in HMAC_ALGOS:
        return hmac.new(key.encode(), signing_input, HMAC_ALGOS[alg]).digest()
    if not CRYPTO_OK:
        raise RuntimeError("Install 'cryptography' for asymmetric algorithms.")
    pem = key.encode() if isinstance(key, str) else key
    private_key = serialization.load_pem_private_key(pem, password=None)
    if alg in ("RS256", "RS384", "RS512"):
        hash_map = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}
        return private_key.sign(signing_input, padding.PKCS1v15(), hash_map[alg])
    if alg in ("PS256", "PS384", "PS512"):
        hash_map = {"PS256": hashes.SHA256(), "PS384": hashes.SHA384(), "PS512": hashes.SHA512()}
        h = hash_map[alg]
        return private_key.sign(signing_input, padding.PSS(mgf=padding.MGF1(h), salt_length=padding.PSS.MAX_LENGTH), h)
    if alg in ("ES256", "ES384", "ES512"):
        hash_map = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}
        return private_key.sign(signing_input, ec.ECDSA(hash_map[alg]))
    raise ValueError(f"Unsupported algorithm: {alg}")

def _verify(signing_input: bytes, sig: bytes, key: str, alg: str) -> bool:
    try:
        if alg in HMAC_ALGOS:
            expected = hmac.new(key.encode(), signing_input, HMAC_ALGOS[alg]).digest()
            return hmac.compare_digest(expected, sig)
        if not CRYPTO_OK:
            return False
        pem = key.encode() if isinstance(key, str) else key
        # Try public key first, then private
        try:
            pub = serialization.load_pem_public_key(pem)
        except Exception:
            priv = serialization.load_pem_private_key(pem, password=None)
            pub  = priv.public_key()
        if alg in ("RS256", "RS384", "RS512"):
            hash_map = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}
            pub.verify(sig, signing_input, padding.PKCS1v15(), hash_map[alg])
        elif alg in ("PS256", "PS384", "PS512"):
            hash_map = {"PS256": hashes.SHA256(), "PS384": hashes.SHA384(), "PS512": hashes.SHA512()}
            h = hash_map[alg]
            pub.verify(sig, signing_input, padding.PSS(mgf=padding.MGF1(h), salt_length=padding.PSS.AUTO), h)
        elif alg in ("ES256", "ES384", "ES512"):
            hash_map = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}
            pub.verify(sig, signing_input, ec.ECDSA(hash_map[alg]))
        return True
    except Exception:
        return False

ALL_ALGORITHMS = [
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "none",
]

# ═══════════════════════════════════════════════════════════════════════════════
#  REUSABLE WIDGETS
# ═══════════════════════════════════════════════════════════════════════════════

def mk_btn(parent, text, cmd, style="normal", **kw):
    palettes = {
        "normal":  (DIM,     TEXT,    BORDER2),
        "primary": (ACCENT,  BG,      "#00aacc"),
        "success": (ACCENT2, BG,      "#00cc80"),
        "danger":  (WARNING, BG,      "#cc4400"),
        "ghost":   (PANEL,   ACCENT,  BORDER),
        "violet":  (ACCENT3, BG,      "#8b5cf6"),
    }
    bg, fg, ab = palettes.get(style, palettes["normal"])
    b = tk.Button(parent, text=text, command=cmd,
                  font=("Courier New", 9, "bold"), fg=fg, bg=bg,
                  activeforeground=ab, activebackground=BG,
                  relief="flat", bd=0, padx=10, pady=4, cursor="hand2", **kw)
    return b

def mk_label(parent, text, size=9, bold=False, color=None, **kw):
    font = ("Courier New", size, "bold") if bold else ("Courier New", size)
    return tk.Label(parent, text=text, font=font,
                    fg=color or TEXT, bg=parent.cget("bg"), **kw)

def section_header(parent, title, row=None, col=0, padx=12, pady=(10, 3)):
    f = tk.Frame(parent, bg=parent.cget("bg"))
    if row is not None:
        f.grid(row=row, column=col, sticky="ew", padx=padx, pady=pady)
    else:
        f.pack(fill="x", padx=padx, pady=pady)
    tk.Label(f, text=f"── {title} ", font=("Courier New", 8, "bold"),
             fg=ACCENT, bg=f.cget("bg")).pack(side="left")
    tk.Frame(f, bg=BORDER, height=1).pack(side="left", fill="x", expand=True, pady=5)
    return f

def scrolled_text(parent, height=6, **kw):
    st = scrolledtext.ScrolledText(
        parent, height=height, font=FONT_MONO, bg="#060d18", fg=TEXT,
        insertbackground=ACCENT, bd=0, relief="flat", wrap="word",
        selectbackground=BORDER2, selectforeground=ACCENT, **kw
    )
    return st

# ═══════════════════════════════════════════════════════════════════════════════
#  GLOBAL TOKEN CONTEXT BAR
# ═══════════════════════════════════════════════════════════════════════════════

class TokenBar(tk.Frame):
    """Persistent bar at top — token shared across all tabs."""
    def __init__(self, master, on_change=None):
        super().__init__(master, bg=PANEL2, pady=6)
        self._on_change = on_change
        self._build()

    def _build(self):
        self.grid_columnconfigure(1, weight=1)

        tk.Label(self, text="TOKEN:", font=("Courier New", 8, "bold"),
                 fg=ACCENT, bg=PANEL2).grid(row=0, column=0, padx=(12, 6))

        self._token_var = tk.StringVar()
        self._token_var.trace_add("write", self._on_token_write)

        entry = tk.Entry(self, textvariable=self._token_var,
                         font=("Courier New", 9), bg="#080f1c", fg=ACCENT,
                         insertbackground=ACCENT, bd=0, relief="flat",
                         highlightthickness=1, highlightbackground=BORDER,
                         highlightcolor=ACCENT)
        entry.grid(row=0, column=1, sticky="ew", padx=(0, 8), ipady=4)

        # badges
        badge_frame = tk.Frame(self, bg=PANEL2)
        badge_frame.grid(row=0, column=2, padx=(0, 8))

        self._alg_badge = tk.Label(badge_frame, text="ALG:—", font=("Courier New", 8, "bold"),
                                   fg=BG, bg=DIM, padx=6, pady=2)
        self._alg_badge.pack(side="left", padx=(0, 4))

        self._status_badge = tk.Label(badge_frame, text="NO TOKEN", font=("Courier New", 8, "bold"),
                                      fg=BG, bg=DIM, padx=6, pady=2)
        self._status_badge.pack(side="left", padx=(0, 4))

        self._exp_badge = tk.Label(badge_frame, text="", font=("Courier New", 8),
                                   fg=TEXT_DIM, bg=PANEL2)
        self._exp_badge.pack(side="left")

        mk_btn(self, "CLEAR", self._clear, style="ghost").grid(row=0, column=3, padx=(0, 12))

    def _on_token_write(self, *_):
        token = self._token_var.get().strip()
        if not token:
            self._alg_badge.config(text="ALG:—", bg=DIM, fg=BG)
            self._status_badge.config(text="NO TOKEN", bg=DIM, fg=BG)
            self._exp_badge.config(text="")
        else:
            try:
                header, payload, _, _, _ = parse_jwt(token)
                alg = header.get("alg", "?")
                self._alg_badge.config(text=f"ALG:{alg}", bg=ACCENT3, fg=BG)
                self._status_badge.config(text="VALID", bg=ACCENT2, fg=BG)
                exp = payload.get("exp")
                if exp:
                    import time as _t
                    remaining = int(exp) - int(_t.time())
                    if remaining < 0:
                        self._exp_badge.config(text=f"EXPIRED {abs(remaining)//3600}h ago", fg=FAIL)
                    else:
                        self._exp_badge.config(text=f"exp in {remaining//3600}h {(remaining%3600)//60}m", fg=ACCENT2)
                else:
                    self._exp_badge.config(text="no exp", fg=TEXT_DIM)
            except Exception:
                self._alg_badge.config(text="ALG:?", bg=DIM, fg=TEXT_DIM)
                self._status_badge.config(text="INVALID", bg=FAIL, fg=BG)
                self._exp_badge.config(text="")

        if self._on_change:
            self._on_change(self._token_var.get().strip())

    def get(self) -> str:
        return self._token_var.get().strip()

    def set(self, token: str):
        self._token_var.set(token)

    def _clear(self):
        self._token_var.set("")

# ═══════════════════════════════════════════════════════════════════════════════
#  TAB 1 — DECODE / ENCODE
# ═══════════════════════════════════════════════════════════════════════════════

class DecodeTab(tk.Frame):
    def __init__(self, master, token_bar: TokenBar):
        super().__init__(master, bg=BG)
        self._token_bar = token_bar
        self._inhibit_rebuild = False
        self._build()
        token_bar._on_change = self._on_global_token

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # ── LEFT: colourised token + verification ──────────────────────────
        left = tk.Frame(self, bg=BG)
        left.grid(row=0, column=0, rowspan=3, sticky="nsew", padx=(10, 5), pady=8)
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        section_header(left, "ENCODED TOKEN  (color-coded)", row=0)

        token_frame = tk.Frame(left, bg=BORDER, bd=1)
        token_frame.grid(row=1, column=0, sticky="nsew", padx=12)
        token_frame.grid_rowconfigure(0, weight=1)
        token_frame.grid_columnconfigure(0, weight=1)

        self._colored_text = tk.Text(
            token_frame, font=("Courier New", 10), bg="#060d18", fg=TEXT,
            insertbackground=ACCENT, bd=0, relief="flat", wrap="word",
            height=6, selectbackground=BORDER2
        )
        self._colored_text.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        sb = tk.Scrollbar(token_frame, command=self._colored_text.yview, bg=BORDER, troughcolor=BG)
        sb.grid(row=0, column=1, sticky="ns")
        self._colored_text.config(yscrollcommand=sb.set)
        self._colored_text.tag_config("header",  foreground=C_HEADER)
        self._colored_text.tag_config("dot",      foreground=TEXT_DIM)
        self._colored_text.tag_config("payload",  foreground=C_PAYLOAD)
        self._colored_text.tag_config("sig",      foreground=C_SIG)
        self._colored_text.bind("<KeyRelease>", self._on_encoded_edit)

        # colour legend
        legend = tk.Frame(left, bg=BG)
        legend.grid(row=2, column=0, sticky="w", padx=12, pady=(4, 0))
        for txt, col in [("■ Header", C_HEADER), ("■ Payload", C_PAYLOAD), ("■ Signature", C_SIG)]:
            tk.Label(legend, text=txt, font=("Courier New", 8),
                     fg=col, bg=BG).pack(side="left", padx=(0, 12))

        # verification bar
        section_header(left, "SIGNATURE VERIFICATION", row=3)
        vbar = tk.Frame(left, bg=BG)
        vbar.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 6))
        vbar.grid_columnconfigure(1, weight=1)

        tk.Label(vbar, text="SECRET / KEY:", font=FONT_LABEL,
                 fg=TEXT_DIM, bg=BG).grid(row=0, column=0, padx=(0, 6))
        self._verify_key_var = tk.StringVar()
        tk.Entry(vbar, textvariable=self._verify_key_var,
                 font=FONT_MONO, bg="#080f1c", fg=ACCENT2,
                 insertbackground=ACCENT2, bd=0, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT2).grid(row=0, column=1, sticky="ew", ipady=3)
        mk_btn(vbar, "VERIFY", self._do_verify, style="success").grid(row=0, column=2, padx=(6, 0))

        self._verify_result = tk.Label(left, text="", font=("Courier New", 9, "bold"),
                                       fg=TEXT_DIM, bg=BG)
        self._verify_result.grid(row=5, column=0, sticky="w", padx=12, pady=(0, 8))

        # ── RIGHT: decoded panels ──────────────────────────────────────────
        right = tk.Frame(self, bg=BG)
        right.grid(row=0, column=1, rowspan=3, sticky="nsew", padx=(5, 10), pady=8)
        right.grid_rowconfigure(1, weight=2)
        right.grid_rowconfigure(4, weight=3)
        right.grid_columnconfigure(0, weight=1)

        # header JSON
        section_header(right, "HEADER", row=0)
        self._header_text = scrolled_text(right, height=5)
        self._header_text.grid(row=1, column=0, sticky="nsew", padx=12)
        self._header_text.bind("<KeyRelease>", self._on_json_edit)

        # alg selector
        alg_row = tk.Frame(right, bg=BG)
        alg_row.grid(row=2, column=0, sticky="ew", padx=12, pady=(4, 0))
        tk.Label(alg_row, text="ALGORITHM:", font=FONT_LABEL, fg=TEXT_DIM, bg=BG).pack(side="left", padx=(0, 6))
        self._alg_var = tk.StringVar(value="HS256")
        alg_cb = ttk.Combobox(alg_row, textvariable=self._alg_var,
                               values=ALL_ALGORITHMS, width=10,
                               font=FONT_MONO, state="readonly")
        alg_cb.pack(side="left")
        alg_cb.bind("<<ComboboxSelected>>", self._on_alg_change)

        # payload JSON
        section_header(right, "PAYLOAD  (edit to re-encode)", row=3)
        self._payload_text = scrolled_text(right, height=8)
        self._payload_text.grid(row=4, column=0, sticky="nsew", padx=12)
        self._payload_text.bind("<KeyRelease>", self._on_json_edit)

        # sign key + actions
        section_header(right, "SIGN / RE-ENCODE", row=5)
        sign_frame = tk.Frame(right, bg=BG)
        sign_frame.grid(row=6, column=0, sticky="ew", padx=12, pady=(0, 4))
        sign_frame.grid_columnconfigure(1, weight=1)

        tk.Label(sign_frame, text="SECRET / PEM KEY:", font=FONT_LABEL,
                 fg=TEXT_DIM, bg=BG).grid(row=0, column=0, padx=(0, 6))
        self._sign_key_var = tk.StringVar()
        self._sign_key_entry = tk.Entry(sign_frame, textvariable=self._sign_key_var,
                                        font=FONT_MONO, bg="#080f1c", fg=ACCENT,
                                        insertbackground=ACCENT, bd=0, relief="flat",
                                        highlightthickness=1, highlightbackground=BORDER,
                                        highlightcolor=ACCENT)
        self._sign_key_entry.grid(row=0, column=1, sticky="ew", ipady=3)

        btn_row = tk.Frame(right, bg=BG)
        btn_row.grid(row=7, column=0, sticky="ew", padx=12, pady=(4, 8))
        mk_btn(btn_row, "▶ ENCODE & SIGN", self._do_encode, style="primary").pack(side="left", padx=(0, 6))
        mk_btn(btn_row, "⎘ COPY TOKEN",    self._copy_token, style="ghost").pack(side="left", padx=(0, 6))
        mk_btn(btn_row, "→ SEND TO GLOBAL", self._push_to_global, style="ghost").pack(side="left")

        self._encode_status = tk.Label(right, text="", font=("Courier New", 8),
                                       fg=TEXT_DIM, bg=BG)
        self._encode_status.grid(row=8, column=0, sticky="w", padx=12)

        # PEM multi-line area (shown only for asymmetric)
        self._pem_frame = tk.Frame(right, bg=BG)
        self._pem_frame.grid(row=9, column=0, sticky="ew", padx=12, pady=(0, 8))
        self._pem_frame.grid_columnconfigure(0, weight=1)
        tk.Label(self._pem_frame, text="PEM KEY (paste multi-line here for RS/ES/PS):",
                 font=FONT_LABEL, fg=TEXT_DIM, bg=BG).grid(row=0, column=0, sticky="w")
        self._pem_text = scrolled_text(self._pem_frame, height=5)
        self._pem_text.grid(row=1, column=0, sticky="ew")
        self._pem_frame.grid_remove()

        self._alg_var.trace_add("write", self._toggle_pem)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _toggle_pem(self, *_):
        alg = self._alg_var.get()
        if alg and alg[0] in ("R", "E", "P"):
            self._pem_frame.grid()
        else:
            self._pem_frame.grid_remove()

    def _get_key(self) -> str:
        alg = self._alg_var.get()
        if alg and alg[0] in ("R", "E", "P"):
            return self._pem_text.get("1.0", "end").strip()
        return self._sign_key_var.get()

    def _colorise_token(self, token: str):
        self._colored_text.config(state="normal")
        self._colored_text.delete("1.0", "end")
        parts = token.split(".")
        if len(parts) == 3:
            self._colored_text.insert("end", parts[0], "header")
            self._colored_text.insert("end", ".", "dot")
            self._colored_text.insert("end", parts[1], "payload")
            self._colored_text.insert("end", ".", "dot")
            self._colored_text.insert("end", parts[2], "sig")
        else:
            self._colored_text.insert("end", token, "header")

    def _set_json_box(self, widget, data: dict):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", json.dumps(data, indent=2))

    def _get_json_box(self, widget) -> dict:
        return json.loads(widget.get("1.0", "end").strip())

    # ── event handlers ────────────────────────────────────────────────────────

    def _on_global_token(self, token: str):
        if self._inhibit_rebuild or not token:
            return
        try:
            header, payload, _, _, _ = parse_jwt(token)
            self._inhibit_rebuild = True
            self._colorise_token(token)
            self._set_json_box(self._header_text, header)
            self._set_json_box(self._payload_text, payload)
            self._alg_var.set(header.get("alg", "HS256"))
            self._verify_result.config(text="")
            self._inhibit_rebuild = False
        except Exception:
            pass

    def _on_encoded_edit(self, _event=None):
        """User types directly into the coloured token box."""
        if self._inhibit_rebuild:
            return
        token = self._colored_text.get("1.0", "end").strip()
        try:
            header, payload, _, _, _ = parse_jwt(token)
            self._inhibit_rebuild = True
            self._token_bar.set(token)
            self._set_json_box(self._header_text, header)
            self._set_json_box(self._payload_text, payload)
            self._alg_var.set(header.get("alg", "HS256"))
            self._inhibit_rebuild = False
        except Exception:
            pass

    def _on_json_edit(self, _event=None):
        """User edits header/payload JSON — live re-encode if key present."""
        if self._inhibit_rebuild:
            return
        key = self._get_key()
        if not key:
            return
        self._do_encode(silent=True)

    def _on_alg_change(self, _event=None):
        try:
            header = self._get_json_box(self._header_text)
            header["alg"] = self._alg_var.get()
            self._set_json_box(self._header_text, header)
        except Exception:
            pass

    def _do_verify(self):
        token = self._token_bar.get()
        key   = self._verify_key_var.get().strip()
        if not token:
            self._verify_result.config(text="⚠ No token in global bar", fg=WARNING)
            return
        if not key:
            self._verify_result.config(text="⚠ Enter a secret or key", fg=WARNING)
            return
        try:
            header, _, h_enc, p_enc, sig = parse_jwt(token)
            alg = header.get("alg", "HS256")
            ok  = _verify(f"{h_enc}.{p_enc}".encode(), sig, key, alg)
            if ok:
                self._verify_result.config(text="✔  SIGNATURE VALID", fg=SUCCESS)
            else:
                self._verify_result.config(text="✘  INVALID SIGNATURE", fg=FAIL)
        except Exception as e:
            self._verify_result.config(text=f"Error: {e}", fg=WARNING)

    def _do_encode(self, silent=False):
        key = self._get_key()
        alg = self._alg_var.get()
        if alg == "none":
            key = ""
        elif not key and not silent:
            self._encode_status.config(text="⚠ Enter a secret/key first", fg=WARNING)
            return
        elif not key:
            return
        try:
            header  = self._get_json_box(self._header_text)
            payload = self._get_json_box(self._payload_text)
        except json.JSONDecodeError as e:
            if not silent:
                self._encode_status.config(text=f"JSON error: {e}", fg=FAIL)
            return
        try:
            if alg == "none":
                h_enc = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
                p_enc = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
                new_token = f"{h_enc}.{p_enc}."
            else:
                new_token = encode_jwt(header, payload, key, alg)
            self._inhibit_rebuild = True
            self._colorise_token(new_token)
            self._token_bar.set(new_token)
            self._inhibit_rebuild = False
            if not silent:
                self._encode_status.config(text=f"✔ Encoded ({alg})", fg=SUCCESS)
        except Exception as e:
            if not silent:
                self._encode_status.config(text=f"Error: {e}", fg=FAIL)

    def _copy_token(self):
        token = self._token_bar.get()
        if token:
            self.clipboard_clear()
            self.clipboard_append(token)
            self._encode_status.config(text="✔ Copied to clipboard", fg=SUCCESS)

    def _push_to_global(self):
        raw = self._colored_text.get("1.0", "end").strip()
        if raw:
            self._token_bar.set(raw)
            self._encode_status.config(text="✔ Pushed to global bar", fg=ACCENT2)

# ═══════════════════════════════════════════════════════════════════════════════
#  TAB 2 — PAYLOAD LIST GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class GeneratorTab(tk.Frame):
    def __init__(self, master, token_bar: TokenBar):
        super().__init__(master, bg=BG)
        self._token_bar = token_bar
        self._iter_rows: list[dict] = []   # list of {claim, type, values_widget, frame}
        self._generated_tokens: list[tuple] = []   # (label, token)
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ── LEFT: template config ──────────────────────────────────────────
        left = tk.Frame(self, bg=BG)
        left.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(10, 5), pady=8)
        left.grid_rowconfigure(3, weight=1)
        left.grid_columnconfigure(0, weight=1)

        section_header(left, "TEMPLATE TOKEN", row=0)

        # template token entry (linked to global)
        tf = tk.Frame(left, bg=BORDER, bd=1)
        tf.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 4))
        tf.grid_columnconfigure(0, weight=1)

        self._tmpl_token_text = scrolled_text(tf, height=3)
        self._tmpl_token_text.grid(row=0, column=0, sticky="ew", padx=2, pady=2)

        btn_r = tk.Frame(left, bg=BG)
        btn_r.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 4))
        mk_btn(btn_r, "← USE GLOBAL TOKEN", self._pull_global, style="ghost").pack(side="left", padx=(0, 6))
        mk_btn(btn_r, "PARSE TEMPLATE", self._parse_template, style="primary").pack(side="left")

        # payload preview
        section_header(left, "PAYLOAD CLAIMS  (click ⊕ to make iterable)", row=3)

        claims_outer = tk.Frame(left, bg=BORDER, bd=1)
        claims_outer.grid(row=4, column=0, sticky="nsew", padx=12, pady=(0, 4))
        claims_outer.grid_rowconfigure(0, weight=1)
        claims_outer.grid_columnconfigure(0, weight=1)
        left.grid_rowconfigure(4, weight=2)

        self._claims_canvas = tk.Canvas(claims_outer, bg=PANEL, bd=0, highlightthickness=0)
        self._claims_canvas.grid(row=0, column=0, sticky="nsew")
        csb = tk.Scrollbar(claims_outer, orient="vertical", command=self._claims_canvas.yview,
                           bg=BORDER, troughcolor=BG)
        csb.grid(row=0, column=1, sticky="ns")
        self._claims_canvas.config(yscrollcommand=csb.set)
        self._claims_inner = tk.Frame(self._claims_canvas, bg=PANEL)
        self._claims_canvas.create_window((0, 0), window=self._claims_inner, anchor="nw")
        self._claims_inner.bind("<Configure>",
            lambda e: self._claims_canvas.config(scrollregion=self._claims_canvas.bbox("all")))

        # sign key
        section_header(left, "SIGN KEY", row=5)
        sk_frame = tk.Frame(left, bg=BG)
        sk_frame.grid(row=6, column=0, sticky="ew", padx=12, pady=(0, 4))
        sk_frame.grid_columnconfigure(1, weight=1)
        tk.Label(sk_frame, text="SECRET / PEM:", font=FONT_LABEL, fg=TEXT_DIM, bg=BG).grid(row=0, column=0, padx=(0, 6))
        self._gen_key_var = tk.StringVar()
        tk.Entry(sk_frame, textvariable=self._gen_key_var,
                 font=FONT_MONO, bg="#080f1c", fg=ACCENT,
                 insertbackground=ACCENT, bd=0, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).grid(row=0, column=1, sticky="ew", ipady=3)

        # alg
        alg_row = tk.Frame(left, bg=BG)
        alg_row.grid(row=7, column=0, sticky="ew", padx=12, pady=(0, 4))
        tk.Label(alg_row, text="ALG:", font=FONT_LABEL, fg=TEXT_DIM, bg=BG).pack(side="left", padx=(0, 6))
        self._gen_alg_var = tk.StringVar(value="HS256")
        ttk.Combobox(alg_row, textvariable=self._gen_alg_var,
                     values=ALL_ALGORITHMS, width=10,
                     font=FONT_MONO, state="readonly").pack(side="left")

        # generate button
        ctrl = tk.Frame(left, bg=BG)
        ctrl.grid(row=8, column=0, sticky="ew", padx=12, pady=8)
        mk_btn(ctrl, "⚡ GENERATE TOKENS", self._generate, style="primary").pack(side="left", padx=(0, 6))
        self._gen_count_lbl = tk.Label(ctrl, text="", font=("Courier New", 9), fg=ACCENT2, bg=BG)
        self._gen_count_lbl.pack(side="left")

        # ── RIGHT: iterable configurator + output ─────────────────────────
        right = tk.Frame(self, bg=BG)
        right.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(5, 10), pady=8)
        right.grid_rowconfigure(1, weight=1)
        right.grid_rowconfigure(4, weight=2)
        right.grid_columnconfigure(0, weight=1)

        section_header(right, "ITERABLE CLAIMS CONFIGURATION", row=0)

        iter_outer = tk.Frame(right, bg=BORDER, bd=1)
        iter_outer.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 4))
        iter_outer.grid_rowconfigure(0, weight=1)
        iter_outer.grid_columnconfigure(0, weight=1)

        self._iter_canvas = tk.Canvas(iter_outer, bg=PANEL, bd=0, highlightthickness=0)
        self._iter_canvas.grid(row=0, column=0, sticky="nsew")
        isb = tk.Scrollbar(iter_outer, orient="vertical", command=self._iter_canvas.yview,
                           bg=BORDER, troughcolor=BG)
        isb.grid(row=0, column=1, sticky="ns")
        self._iter_canvas.config(yscrollcommand=isb.set)
        self._iter_inner = tk.Frame(self._iter_canvas, bg=PANEL)
        self._iter_canvas.create_window((0, 0), window=self._iter_inner, anchor="nw")
        self._iter_inner.bind("<Configure>",
            lambda e: self._iter_canvas.config(scrollregion=self._iter_canvas.bbox("all")))

        info = tk.Label(right,
            text="  ⊕ buttons appear in the claims panel after parsing. Click to add a claim here.",
            font=("Courier New", 8), fg=TEXT_DIM, bg=BG, anchor="w")
        info.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 4))

        # output
        section_header(right, "GENERATED TOKENS", row=3)

        self._output_text = scrolled_text(right, height=10)
        self._output_text.grid(row=4, column=0, sticky="nsew", padx=12, pady=(0, 4))

        out_ctrl = tk.Frame(right, bg=BG)
        out_ctrl.grid(row=5, column=0, sticky="ew", padx=12, pady=(0, 8))
        mk_btn(out_ctrl, "⎘ COPY ALL",     self._copy_output,   style="ghost").pack(side="left", padx=(0, 6))
        mk_btn(out_ctrl, "⬇ EXPORT .TXT",  self._export_output, style="ghost").pack(side="left", padx=(0, 6))
        mk_btn(out_ctrl, "CLEAR OUTPUT",   self._clear_output,  style="ghost").pack(side="left")
        self._out_status = tk.Label(out_ctrl, text="", font=("Courier New", 8), fg=ACCENT2, bg=BG)
        self._out_status.pack(side="right")

    # ── helpers ───────────────────────────────────────────────────────────────

    def _pull_global(self):
        token = self._token_bar.get()
        if token:
            self._tmpl_token_text.delete("1.0", "end")
            self._tmpl_token_text.insert("1.0", token)
            self._parse_template()

    def _parse_template(self):
        token = self._tmpl_token_text.get("1.0", "end").strip()
        if not token:
            return
        try:
            _, payload, _, _, _ = parse_jwt(token)
        except Exception as e:
            messagebox.showerror("Parse Error", str(e))
            return

        # clear claims panel
        for w in self._claims_inner.winfo_children():
            w.destroy()

        # render each claim with ⊕ toggle
        for i, (k, v) in enumerate(payload.items()):
            row = tk.Frame(self._claims_inner, bg=PANEL, pady=3)
            row.pack(fill="x", padx=6, pady=1)
            row.grid_columnconfigure(1, weight=1)

            add_btn = tk.Button(row, text="⊕", font=("Courier New", 10, "bold"),
                                fg=ACCENT2, bg=PANEL, bd=0, relief="flat",
                                cursor="hand2", padx=4)
            add_btn.grid(row=0, column=0, padx=(0, 6))

            tk.Label(row, text=f"{k}:", font=("Courier New", 9, "bold"),
                     fg=C_PAYLOAD, bg=PANEL, width=14, anchor="w").grid(row=0, column=1, sticky="w")
            tk.Label(row, text=str(v)[:50], font=FONT_MONO,
                     fg=TEXT, bg=PANEL, anchor="w").grid(row=0, column=2, sticky="w")

            claim_key = k
            add_btn.config(command=lambda ck=claim_key, cv=v: self._add_iter_claim(ck, cv))

        self._gen_count_lbl.config(text="")

    def _add_iter_claim(self, claim: str, default_val):
        # don't add duplicates
        for r in self._iter_rows:
            if r["claim"] == claim:
                return

        frame = tk.Frame(self._iter_inner, bg=PANEL2, pady=6, padx=8, relief="flat", bd=0)
        frame.pack(fill="x", padx=6, pady=3)
        frame.grid_columnconfigure(1, weight=1)

        # header row
        hdr = tk.Frame(frame, bg=PANEL2)
        hdr.grid(row=0, column=0, columnspan=3, sticky="ew")
        hdr.grid_columnconfigure(1, weight=1)

        tk.Label(hdr, text=claim, font=("Courier New", 10, "bold"),
                 fg=C_PAYLOAD, bg=PANEL2).grid(row=0, column=0, padx=(0, 8))

        type_var = tk.StringVar(value="range" if isinstance(default_val, (int, float)) else "list")
        ttk.Combobox(hdr, textvariable=type_var,
                     values=["range", "list"], width=8,
                     font=FONT_MONO, state="readonly").grid(row=0, column=1, sticky="w")

        remove_btn = tk.Button(hdr, text="✕", font=("Courier New", 9),
                               fg=FAIL, bg=PANEL2, bd=0, relief="flat", cursor="hand2", padx=4)
        remove_btn.grid(row=0, column=2, sticky="e")

        # value input area
        val_frame = tk.Frame(frame, bg=PANEL2)
        val_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(4, 0))
        val_frame.grid_columnconfigure(0, weight=1)

        # range inputs
        range_frame = tk.Frame(val_frame, bg=PANEL2)
        range_frame.grid(row=0, column=0, sticky="ew")
        tk.Label(range_frame, text="FROM:", font=FONT_LABEL, fg=TEXT_DIM, bg=PANEL2).pack(side="left")
        from_var = tk.StringVar(value="1")
        tk.Entry(range_frame, textvariable=from_var, width=8,
                 font=FONT_MONO, bg="#080f1c", fg=ACCENT, bd=0, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER,
                 insertbackground=ACCENT).pack(side="left", padx=(2, 8), ipady=2)
        tk.Label(range_frame, text="TO:", font=FONT_LABEL, fg=TEXT_DIM, bg=PANEL2).pack(side="left")
        to_var = tk.StringVar(value="10")
        tk.Entry(range_frame, textvariable=to_var, width=8,
                 font=FONT_MONO, bg="#080f1c", fg=ACCENT, bd=0, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER,
                 insertbackground=ACCENT).pack(side="left", padx=(2, 8), ipady=2)
        tk.Label(range_frame, text="STEP:", font=FONT_LABEL, fg=TEXT_DIM, bg=PANEL2).pack(side="left")
        step_var = tk.StringVar(value="1")
        tk.Entry(range_frame, textvariable=step_var, width=5,
                 font=FONT_MONO, bg="#080f1c", fg=ACCENT, bd=0, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER,
                 insertbackground=ACCENT).pack(side="left", padx=(2, 0), ipady=2)

        # list inputs
        list_frame = tk.Frame(val_frame, bg=PANEL2)
        list_frame.grid(row=1, column=0, sticky="ew")
        tk.Label(list_frame, text="VALUES (one per line):", font=FONT_LABEL, fg=TEXT_DIM, bg=PANEL2).pack(anchor="w")
        list_text = scrolled_text(list_frame, height=3)
        list_text.pack(fill="x")
        list_text.insert("1.0", str(default_val))

        def toggle_type(*_):
            t = type_var.get()
            if t == "range":
                range_frame.grid()
                list_frame.grid_remove()
            else:
                range_frame.grid_remove()
                list_frame.grid()

        type_var.trace_add("write", toggle_type)
        toggle_type()

        row_data = {
            "claim": claim,
            "type_var": type_var,
            "from_var": from_var,
            "to_var": to_var,
            "step_var": step_var,
            "list_text": list_text,
            "frame": frame,
        }
        self._iter_rows.append(row_data)

        def remove(rd=row_data):
            rd["frame"].destroy()
            self._iter_rows.remove(rd)

        remove_btn.config(command=remove)

    def _get_iter_values(self, row_data: dict) -> list:
        if row_data["type_var"].get() == "range":
            try:
                f = int(row_data["from_var"].get())
                t = int(row_data["to_var"].get())
                s = int(row_data["step_var"].get()) or 1
                return list(range(f, t + 1, s))
            except ValueError:
                return []
        else:
            raw = row_data["list_text"].get("1.0", "end").strip()
            return [line for line in raw.splitlines() if line]

    def _generate(self):
        token = self._tmpl_token_text.get("1.0", "end").strip()
        if not token:
            messagebox.showwarning("No Template", "Paste a template token first.")
            return
        if not self._iter_rows:
            messagebox.showwarning("No Iterables", "Mark at least one claim as iterable using the ⊕ buttons.")
            return

        key = self._gen_key_var.get().strip()
        alg = self._gen_alg_var.get()
        if alg != "none" and not key:
            messagebox.showwarning("No Key", "Enter a secret/key for signing.")
            return

        try:
            header, payload, _, _, _ = parse_jwt(token)
        except Exception as e:
            messagebox.showerror("Parse Error", str(e))
            return

        # build value lists
        claim_names  = [r["claim"] for r in self._iter_rows]
        claim_values = [self._get_iter_values(r) for r in self._iter_rows]

        if any(len(v) == 0 for v in claim_values):
            messagebox.showwarning("Empty Values", "One or more iterable claims has no values.")
            return

        combos = list(itertools.product(*claim_values))
        self._generated_tokens = []

        self._output_text.config(state="normal")
        self._output_text.delete("1.0", "end")

        for combo in combos:
            new_payload = deepcopy(payload)
            label_parts = []
            for claim, val in zip(claim_names, combo):
                # preserve original type (int stays int if it looks like one)
                orig = payload.get(claim)
                if isinstance(orig, int):
                    try:
                        val = int(val)
                    except (ValueError, TypeError):
                        pass
                elif isinstance(orig, float):
                    try:
                        val = float(val)
                    except (ValueError, TypeError):
                        pass
                new_payload[claim] = val
                label_parts.append(f"{claim}={val}")
            label = ", ".join(label_parts)

            try:
                if alg == "none":
                    h_enc = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
                    p_enc = b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
                    new_token = f"{h_enc}.{p_enc}."
                else:
                    new_token = encode_jwt(header, new_payload, key, alg)

                self._generated_tokens.append((label, new_token))
                self._output_text.insert("end", new_token + "\n", "token")
            except Exception as e:
                self._output_text.insert("end", f"# ERROR ({label}): {e}\n\n", "error")

        self._output_text.tag_config("label", foreground=TEXT_DIM)
        self._output_text.tag_config("token", foreground=ACCENT)
        self._output_text.tag_config("error", foreground=FAIL)
        self._output_text.config(state="disabled")

        total = len(self._generated_tokens)
        self._gen_count_lbl.config(text=f"✔ {total:,} tokens generated")
        self._out_status.config(text=f"{total} tokens")

    def _copy_output(self):
        if not self._generated_tokens:
            return
        lines = [tok for _, tok in self._generated_tokens]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self._out_status.config(text="✔ Copied!", fg=SUCCESS)

    def _export_output(self):
        if not self._generated_tokens:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Export tokens"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for label, tok in self._generated_tokens:
                f.write(tok + "\n")
        self._out_status.config(text=f"✔ Saved to {path.split('/')[-1]}", fg=SUCCESS)

    def _clear_output(self):
        self._output_text.config(state="normal")
        self._output_text.delete("1.0", "end")
        self._output_text.config(state="disabled")
        self._generated_tokens = []
        self._out_status.config(text="")
        self._gen_count_lbl.config(text="")

# ═══════════════════════════════════════════════════════════════════════════════
#  TAB 3 — SECRET CRACKER  (upgraded from v1)
# ═══════════════════════════════════════════════════════════════════════════════

class CrackerTab(tk.Frame):
    def __init__(self, master, token_bar: TokenBar):
        super().__init__(master, bg=BG)
        self._token_bar = token_bar
        self._crack_thread = None
        self._stop_event   = threading.Event()
        self._found_secret = None
        self._attempts     = 0
        self._start_time   = 0.0
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)

        # token pull
        section_header(self, "TARGET TOKEN", row=0)
        token_pull = tk.Frame(self, bg=BG)
        token_pull.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 4))
        token_pull.grid_columnconfigure(1, weight=1)
        tk.Label(token_pull, text="TOKEN:", font=FONT_LABEL, fg=TEXT_DIM, bg=BG).grid(row=0, column=0, padx=(0, 6))
        self._crack_token_var = tk.StringVar()
        tk.Entry(token_pull, textvariable=self._crack_token_var,
                 font=FONT_MONO, bg="#080f1c", fg=ACCENT,
                 insertbackground=ACCENT, bd=0, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).grid(row=0, column=1, sticky="ew", ipady=3)
        mk_btn(token_pull, "← GLOBAL", self._pull_global, style="ghost").grid(row=0, column=2, padx=(6, 0))

        # token info badges
        info_row = tk.Frame(self, bg=BG)
        info_row.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))
        self._cr_alg_var = tk.StringVar(value="—")
        self._cr_exp_var = tk.StringVar(value="—")
        self._cr_sub_var = tk.StringVar(value="—")
        for lbl, var in [("ALG", self._cr_alg_var), ("EXP", self._cr_exp_var), ("SUB/ISS", self._cr_sub_var)]:
            f = tk.Frame(info_row, bg=BORDER, padx=10, pady=4)
            f.pack(side="left", padx=(0, 6))
            tk.Label(f, text=lbl, font=("Courier New", 7, "bold"), fg=TEXT_DIM, bg=BORDER).pack()
            tk.Label(f, textvariable=var, font=("Courier New", 9, "bold"), fg=ACCENT2, bg=BORDER).pack()
        mk_btn(info_row, "PARSE", self._parse_crack_token, style="primary").pack(side="left", padx=(8, 0))

        # attack mode
        section_header(self, "ATTACK MODE", row=3)
        mode_frame = tk.Frame(self, bg=BG)
        mode_frame.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 6))
        self._mode_var = tk.StringVar(value="wordlist")
        self._mode_frames = {}

        modes = [("WORDLIST", "wordlist"), ("BRUTE FORCE", "bruteforce"), ("COMMON SECRETS", "common")]
        for txt, val in modes:
            tk.Radiobutton(
                mode_frame, text=txt, variable=self._mode_var, value=val,
                font=("Courier New", 9, "bold"), fg=TEXT, bg=BG,
                selectcolor=BORDER2, activebackground=BG, activeforeground=ACCENT,
                indicatoron=0, relief="flat", bd=0, command=self._update_mode_ui,
                padx=12, pady=4
            ).pack(side="left", padx=(0, 6))

        # wordlist panel
        wf = tk.Frame(self, bg=BG)
        wf.grid(row=5, column=0, sticky="ew", padx=12, pady=(0, 4))
        wf.grid_columnconfigure(1, weight=1)
        self._mode_frames["wordlist"] = wf
        tk.Label(wf, text="FILE:", font=FONT_LABEL, fg=TEXT_DIM, bg=BG).grid(row=0, column=0, padx=(0, 6))
        self._wl_path_var = tk.StringVar(value="No file selected")
        tk.Label(wf, textvariable=self._wl_path_var, font=FONT_MONO,
                 fg=TEXT, bg=BG, anchor="w").grid(row=0, column=1, sticky="ew")
        mk_btn(wf, "BROWSE", self._browse_wordlist, style="ghost").grid(row=0, column=2, padx=(6, 0))

        # brute force panel
        bf = tk.Frame(self, bg=BG)
        bf.grid(row=5, column=0, sticky="ew", padx=12, pady=(0, 4))
        bf.grid_columnconfigure(3, weight=1)
        self._mode_frames["bruteforce"] = bf
        bf.grid_remove()
        tk.Label(bf, text="CHARSET:", font=FONT_LABEL, fg=TEXT_DIM, bg=BG).grid(row=0, column=0, padx=(0, 6))
        self._charset_var = tk.StringVar(value="alphanumeric")
        ttk.Combobox(bf, textvariable=self._charset_var, width=16,
                     values=["alphanumeric", "lowercase", "uppercase", "digits", "printable"],
                     font=FONT_MONO, state="readonly").grid(row=0, column=1, padx=(0, 12))
        tk.Label(bf, text="MAX LEN:", font=FONT_LABEL, fg=TEXT_DIM, bg=BG).grid(row=0, column=2, padx=(0, 6))
        self._maxlen_var = tk.IntVar(value=4)
        tk.Spinbox(bf, from_=1, to=8, textvariable=self._maxlen_var, width=5,
                   font=FONT_MONO, bg="#080f1c", fg=ACCENT, bd=0,
                   buttonbackground=BORDER, insertbackground=ACCENT).grid(row=0, column=3)

        # common panel
        cf = tk.Frame(self, bg=BG)
        cf.grid(row=5, column=0, sticky="ew", padx=12, pady=(0, 4))
        self._mode_frames["common"] = cf
        cf.grid_remove()
        tk.Label(cf, text="Uses built-in list of 200+ common JWT secrets (secret, password, 123456, …)",
                 font=("Courier New", 9), fg=TEXT_DIM, bg=BG).pack(anchor="w")

        # controls + stats
        ctrl = tk.Frame(self, bg=BG)
        ctrl.grid(row=6, column=0, sticky="ew", padx=12, pady=8)
        self._start_btn = mk_btn(ctrl, "▶  START CRACK", self._start_crack, style="primary")
        self._start_btn.pack(side="left", padx=(0, 6))
        self._stop_btn = mk_btn(ctrl, "■  STOP", self._stop_crack, style="danger")
        self._stop_btn.pack(side="left", padx=(0, 6))
        self._stop_btn.config(state="disabled")
        mk_btn(ctrl, "⌫  CLEAR LOG", self._clear_log, style="ghost").pack(side="left")

        stats = tk.Frame(ctrl, bg=BG)
        stats.pack(side="right")
        self._rate_var    = tk.StringVar(value="0/s")
        self._elapsed_var = tk.StringVar(value="00:00")
        self._count_var   = tk.StringVar(value="0")
        for lbl, var in [("RATE", self._rate_var), ("TIME", self._elapsed_var), ("TESTED", self._count_var)]:
            sf = tk.Frame(stats, bg=BORDER, padx=8, pady=3)
            sf.pack(side="left", padx=(0, 4))
            tk.Label(sf, text=lbl, font=("Courier New", 7), fg=TEXT_DIM, bg=BORDER).pack()
            tk.Label(sf, textvariable=var, font=("Courier New", 10, "bold"), fg=ACCENT, bg=BORDER).pack()

        # log
        section_header(self, "OUTPUT", row=7)
        log_frame = tk.Frame(self, bg=BORDER, bd=1)
        log_frame.grid(row=8, column=0, sticky="nsew", padx=12, pady=(0, 12))
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(8, weight=1)

        self._log = scrolledtext.ScrolledText(
            log_frame, font=FONT_MONO, bg="#050d18", fg=TEXT,
            insertbackground=ACCENT, bd=0, relief="flat", wrap="word",
            state="disabled", selectbackground=BORDER2, selectforeground=ACCENT
        )
        self._log.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        for tag, fg in [("info", TEXT), ("dim", TEXT_DIM), ("accent", ACCENT),
                        ("accent2", ACCENT2), ("success", SUCCESS),
                        ("fail", FAIL), ("warn", WARNING)]:
            self._log.tag_config(tag, foreground=fg)
        self._log.tag_config("success", font=("Courier New", 10, "bold"))

    # ── helpers ───────────────────────────────────────────────────────────────

    def _pull_global(self):
        t = self._token_bar.get()
        if t:
            self._crack_token_var.set(t)
            self._parse_crack_token()

    def _parse_crack_token(self):
        token = self._crack_token_var.get().strip()
        if not token:
            self._log_write("No token.", "warn"); return
        try:
            header, payload, _, _, _ = parse_jwt(token)
            self._cr_alg_var.set(header.get("alg", "?"))
            self._cr_exp_var.set(str(payload.get("exp", "—")))
            self._cr_sub_var.set(str(payload.get("sub", payload.get("iss", "—")))[:20])
            self._log_write(f"Parsed OK — alg={header.get('alg')}  sub={payload.get('sub', '—')}", "accent2")
        except Exception as e:
            self._log_write(f"Parse error: {e}", "fail")

    def _update_mode_ui(self):
        mode = self._mode_var.get()
        for key, frame in self._mode_frames.items():
            frame.grid() if key == mode else frame.grid_remove()

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(
            title="Select wordlist", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self._wl_path_var.set(path)

    def _log_write(self, text, tag="info"):
        self._log.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.insert("end", f"[{ts}] ", "dim")
        self._log.insert("end", text + "\n", tag)
        self._log.see("end")
        self._log.config(state="disabled")

    def _clear_log(self):
        self._log.config(state="normal")
        self._log.delete("1.0", "end")
        self._log.config(state="disabled")

    # ── cracking ──────────────────────────────────────────────────────────────

    def _start_crack(self):
        token = self._crack_token_var.get().strip()
        if not token:
            self._log_write("No token.", "warn"); return
        try:
            header, _, h_enc, p_enc, sig = parse_jwt(token)
        except Exception as e:
            self._log_write(f"Token error: {e}", "fail"); return

        alg = header.get("alg", "HS256")
        if alg not in HMAC_ALGOS:
            self._log_write(f"Cracker only supports HMAC (HS256/384/512). Got: {alg}", "fail"); return

        signing_input = f"{h_enc}.{p_enc}".encode()
        mode = self._mode_var.get()

        if mode == "wordlist":
            path = self._wl_path_var.get()
            if path == "No file selected":
                self._log_write("Select a wordlist.", "warn"); return
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    words = [l.rstrip("\n") for l in f]
            except Exception as e:
                self._log_write(f"File error: {e}", "fail"); return
            gen, total = iter(words), len(words)

        elif mode == "bruteforce":
            cs_map = {
                "alphanumeric": string.ascii_letters + string.digits,
                "lowercase": string.ascii_lowercase,
                "uppercase": string.ascii_uppercase,
                "digits": string.digits,
                "printable": string.printable.strip(),
            }
            cs  = cs_map.get(self._charset_var.get(), string.ascii_letters + string.digits)
            ml  = self._maxlen_var.get()
            gen = ("".join(c) for l in range(1, ml + 1) for c in itertools.product(cs, repeat=l))
            total = sum(len(cs) ** l for l in range(1, ml + 1))
        else:
            gen, total = iter(COMMON_SECRETS), len(COMMON_SECRETS)

        self._stop_event.clear()
        self._found_secret = None
        self._attempts     = 0
        self._start_time   = time.time()
        self._start_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        self._log_write("─" * 54, "dim")
        self._log_write(f"START  mode={mode}  alg={alg}  candidates={total:,}", "accent")

        self._crack_thread = threading.Thread(
            target=self._worker, args=(signing_input, sig, alg, gen), daemon=True)
        self._crack_thread.start()
        self._ticker()

    def _worker(self, signing_input, sig, alg, gen):
        hfn  = HMAC_ALGOS[alg]
        batch, buf = 500, []
        for secret in gen:
            if self._stop_event.is_set():
                break
            buf.append(secret)
            if len(buf) >= batch:
                for s in buf:
                    self._attempts += 1
                    mac = hmac.new(s.encode(), signing_input, hfn).digest()
                    if hmac.compare_digest(mac, sig):
                        self._found_secret = s
                        self._stop_event.set()
                        break
                buf.clear()
                if self._found_secret:
                    break
        if not self._found_secret:
            for s in buf:
                self._attempts += 1
                mac = hmac.new(s.encode(), signing_input, hfn).digest()
                if hmac.compare_digest(mac, sig):
                    self._found_secret = s
                    break
        self.after(0, self._on_done)

    def _on_done(self):
        elapsed = time.time() - self._start_time
        self._start_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        if self._found_secret:
            self._log_write("─" * 54, "dim")
            self._log_write("SECRET FOUND!", "success")
            self._log_write(f'  ▶  "{self._found_secret}"', "success")
            self._log_write(f"  Attempts : {self._attempts:,}", "accent2")
            self._log_write(f"  Elapsed  : {elapsed:.2f}s", "accent2")
        else:
            self._log_write("─" * 54, "dim")
            self._log_write("Not found in candidate set.", "fail")
            self._log_write(f"  Attempts: {self._attempts:,}  |  Time: {elapsed:.2f}s", "dim")

    def _stop_crack(self):
        self._stop_event.set()
        self._log_write("Stop requested.", "warn")

    def _ticker(self):
        if self._crack_thread and self._crack_thread.is_alive():
            elapsed = time.time() - self._start_time
            rate    = self._attempts / elapsed if elapsed > 0 else 0
            m, s    = divmod(int(elapsed), 60)
            self._elapsed_var.set(f"{m:02d}:{s:02d}")
            self._rate_var.set(f"{rate:,.0f}/s")
            self._count_var.set(f"{self._attempts:,}")
            self.after(250, self._ticker)

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN APP
# ═══════════════════════════════════════════════════════════════════════════════

class JWTPentestSuite(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("JWT PENTEST SUITE  //  security research tool")
        self.configure(bg=BG)
        self.geometry("1100x820")
        self.minsize(900, 680)
        self.resizable(True, True)
        self._build_ui()
        self._animate_title()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # ── header ────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG, pady=8)
        hdr.grid(row=0, column=0, sticky="ew", padx=16)

        self._title_lbl = tk.Label(hdr, text="◈ JWT PENTEST SUITE",
                                   font=FONT_BIG, fg=ACCENT, bg=BG)
        self._title_lbl.pack(side="left")
        tk.Label(hdr, text="v2.0  //  decode · encode · generate · crack",
                 font=("Courier New", 8), fg=TEXT_DIM, bg=BG).pack(side="left", padx=14)

        if not CRYPTO_OK:
            tk.Label(hdr, text=" ⚠ cryptography not installed — asymmetric algos disabled ",
                     font=("Courier New", 8, "bold"), fg=WARNING, bg=BG).pack(side="left", padx=8)

        tk.Label(hdr, text=" SECURITY RESEARCH ONLY ",
                 font=("Courier New", 8, "bold"), fg=BG, bg=WARNING).pack(side="right")

        # ── global token bar ──────────────────────────────────────────────
        self._token_bar = TokenBar(self)
        self._token_bar.grid(row=1, column=0, sticky="ew", padx=0, pady=0)

        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.grid(row=2, column=0, sticky="ew")

        # ── tabs ──────────────────────────────────────────────────────────
        style = ttk.Style()
        style.theme_use("default")
        style.configure("JWT.TNotebook",           background=BG, borderwidth=0, tabmargins=0)
        style.configure("JWT.TNotebook.Tab",       background=DIM, foreground=TEXT_DIM,
                        font=("Courier New", 9, "bold"), padding=[16, 6], borderwidth=0)
        style.map("JWT.TNotebook.Tab",
                  background=[("selected", PANEL2), ("active", BORDER2)],
                  foreground=[("selected", ACCENT),  ("active", TEXT)])

        self._notebook = ttk.Notebook(self, style="JWT.TNotebook")
        self._notebook.grid(row=3, column=0, sticky="nsew", padx=0, pady=0)
        self.grid_rowconfigure(3, weight=1)

        self._decode_tab    = DecodeTab(self._notebook, self._token_bar)
        self._generator_tab = GeneratorTab(self._notebook, self._token_bar)
        self._cracker_tab   = CrackerTab(self._notebook, self._token_bar)

        self._notebook.add(self._decode_tab,    text="  ◉ DECODE / ENCODE  ")
        self._notebook.add(self._generator_tab, text="  ⚡ PAYLOAD GENERATOR  ")
        self._notebook.add(self._cracker_tab,   text="  ◈ SECRET CRACKER  ")

        # ── status bar ────────────────────────────────────────────────────
        bar = tk.Frame(self, bg="#050d18", height=22)
        bar.grid(row=4, column=0, sticky="ew")
        tk.Label(bar,
                 text="For authorised security testing only. Misuse of this tool may violate applicable laws.",
                 font=("Courier New", 7), fg=TEXT_DIM, bg="#050d18", padx=12).pack(side="left")
        alg_support = "HS/RS/ES/PS256·384·512" if CRYPTO_OK else "HS256·HS384·HS512 only"
        tk.Label(bar, text=f"alg: {alg_support}",
                 font=("Courier New", 7), fg=TEXT_DIM, bg="#050d18", padx=12).pack(side="right")

    def _animate_title(self):
        colours = [ACCENT, "#00b8e0", "#0099cc", "#00b8e0", ACCENT, ACCENT2, ACCENT]
        idx = [0]
        def tick():
            self._title_lbl.config(fg=colours[idx[0] % len(colours)])
            idx[0] += 1
            self.after(800, tick)
        tick()


# ═══════════════════════════════════════════════════════════════════════════════
#  COMMON SECRETS LIST
# ═══════════════════════════════════════════════════════════════════════════════

COMMON_SECRETS = [
    "secret", "password", "123456", "secret123", "qwerty", "abc123",
    "password123", "admin", "letmein", "welcome", "monkey", "dragon",
    "master", "hello", "shadow", "sunshine", "princess", "football",
    "jwt_secret", "jwtsecret", "jwt-secret", "jwttoken", "my_secret",
    "mysecret", "supersecret", "super_secret", "topsecret", "top_secret",
    "changeme", "change_me", "default", "test", "testing", "dev", "development",
    "prod", "production", "stage", "staging", "local", "localhost",
    "key", "apikey", "api_key", "api-key", "authkey", "auth_key",
    "token", "auth_token", "access_token", "refresh_token",
    "private", "private_key", "publickey",
    "12345", "123456789", "1234567890", "111111", "000000",
    "aaaaaa", "zzzzzz", "abcdef", "qazwsx", "asdfgh",
    "iloveyou", "sunshine", "princess", "baseball", "michael",
    "hunter", "batman", "trustno1", "696969", "superman", "harley",
    "your-256-bit-secret", "your-512-bit-secret", "your-384-bit-secret",
    "HS256", "HS384", "HS512", "RS256",
    "s3cr3t", "p4ssw0rd", "p@ssword", "p@ssw0rd", "passw0rd",
    "P@ssword", "P@ssw0rd", "Password1", "Password123",
    "root", "toor", "alpine", "raspberry", "ubnt",
    "django-insecure-secret", "flask_secret_key", "rails_secret",
    "node_secret", "express_secret",
    "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789abcdef", "deadbeef", "cafebabe",
    "aaaaaaaa", "12341234", "11111111", "00000000",
    "shhhhh", "shhhhhh", "keep_it_secret",
    "my-super-secret-key", "super-secret-key", "very-secret-key",
    "not-so-secret", "totally-secret",
    "", " ", "null", "none", "undefined", "false", "true",
    "guest", "user", "demo", "example", "sample",
    "app_secret", "app_key", "application_secret",
    "256bitkey123456789012345678901234",
    "sk-" + "a" * 48, "pk_test_" + "a" * 24,
]


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = JWTPentestSuite()
    app.mainloop()
