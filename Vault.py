# ============================================================
#   MASTER VAULT – PHOTO (single) + VIDEO IMPORT (Photos & Files)
#   AES-CTR + HMAC, single master password, threaded imports
# ============================================================

import ui, photos, dialogs, console, os, time, hashlib, hmac, secrets, zipfile, io, threading
import pyaes
from pathlib import Path

# ---------- Hidden Storage Setup ----------
DOCS = Path.home() / "Documents"
NAME_FILE = DOCS / ".vault_folder_name"

if NAME_FILE.exists():
    folder = NAME_FILE.read_text().strip()
    HIDDEN_DIR = DOCS / folder
else:
    rnd = "._" + secrets.token_hex(8)
    HIDDEN_DIR = DOCS / rnd
    try:
        HIDDEN_DIR.mkdir(exist_ok=True)
        NAME_FILE.write_text(rnd)
    except Exception:
        HIDDEN_DIR = DOCS / ".sys_hidden_vault"
        HIDDEN_DIR.mkdir(exist_ok=True)
        NAME_FILE.write_text(".sys_hidden_vault")

KEYFILE = HIDDEN_DIR / ".keyfile"        # salt(16) || verifier_main(32)
VAULT_FILE = HIDDEN_DIR / ".vault"       # salt(16) || tag(32) || iv(16) || ciphertext
BACKUP_KEYFILE = HIDDEN_DIR / ".keyfile.bak"
STAGE_DIR = HIDDEN_DIR / ".stage"
UNPACK_DIR = DOCS / "vault_unpacked"

PBKDF2_ITERS = 200_000
AUTO_DELETE = False
BURN_AFTER_READ = False

# Optional biometric
try:
    import local_auth
    HAS_BIOMETRIC = True
except:
    HAS_BIOMETRIC = False

# ---------- Utility ----------
def ensure_dirs():
    HIDDEN_DIR.mkdir(exist_ok=True)
    STAGE_DIR.mkdir(exist_ok=True)
    UNPACK_DIR.mkdir(exist_ok=True)

def notify(msg, style='success'):
    console.hud_alert(msg, style)

def password_prompt(title, msg):
    # stable password prompt
    return dialogs.password_alert(title, msg)

# ---------- Crypto ----------
def derive_keys(password: str, salt: bytes):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS, dklen=64)
    return dk[:32], dk[32:]  # enc_key, mac_key

def aes_ctr_encrypt(key: bytes, data: bytes):
    iv = secrets.token_bytes(16)
    ctr = pyaes.Counter(int.from_bytes(iv, 'big'))
    aes = pyaes.AESModeOfOperationCTR(key, counter=ctr)
    ct = aes.encrypt(data)
    return iv, ct

def aes_ctr_decrypt(key: bytes, iv: bytes, ct: bytes):
    ctr = pyaes.Counter(int.from_bytes(iv, 'big'))
    aes = pyaes.AESModeOfOperationCTR(key, counter=ctr)
    return aes.decrypt(ct)

# ---------- Keyfile ----------
def create_keyfile(master_pw: str):
    ensure_dirs()
    salt = secrets.token_bytes(16)
    _, mac = derive_keys(master_pw, salt)
    verifier = hmac.new(mac, b"vault-main", hashlib.sha256).digest()
    with open(KEYFILE, "wb") as f:
        f.write(salt + verifier)
    backup_keyfile(salt, verifier, master_pw)

def load_keys(password: str):
    if not KEYFILE.exists():
        raise FileNotFoundError("Keyfile missing")
    raw = KEYFILE.read_bytes()
    salt = raw[:16]
    verifier = raw[16:48]
    enc_key, mac_key = derive_keys(password, salt)
    check = hmac.new(mac_key, b"vault-main", hashlib.sha256).digest()
    if not hmac.compare_digest(check, verifier):
        raise ValueError("Wrong password")
    return enc_key, mac_key, salt

def backup_keyfile(salt, verifier, pw):
    enc_key, mac_key = derive_keys(pw, salt)
    iv, ct = aes_ctr_encrypt(enc_key, salt + verifier)
    tag = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    BACKUP_KEYFILE.write_bytes(salt + tag + iv + ct)

# ---------- Stage / Zip ----------
def stage_add_bytes(name, data):
    STAGE_DIR.mkdir(exist_ok=True)
    dst = STAGE_DIR / name
    if dst.exists():
        stem, ext = os.path.splitext(name)
        dst = STAGE_DIR / f"{stem}_{int(time.time())}{ext}"
    dst.write_bytes(data)
    return dst

def stage_add_file(src):
    STAGE_DIR.mkdir(exist_ok=True)
    srcp = Path(src)
    dst = STAGE_DIR / srcp.name
    if dst.exists():
        stem, ext = os.path.splitext(srcp.name)
        dst = STAGE_DIR / f"{stem}_{int(time.time())}{ext}"
    dst.write_bytes(srcp.read_bytes())
    return dst

def pack_stage_to_zip():
    ensure_dirs()
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in STAGE_DIR.glob("*"):
            # only files
            if f.is_file():
                zf.write(str(f), f.name)
    return bio.getvalue()

def unpack_zip(zip_bytes, target):
    target.mkdir(exist_ok=True)
    bio = io.BytesIO(zip_bytes)
    with zipfile.ZipFile(bio, "r") as z:
        z.extractall(str(target))

def clear_stage():
    for f in STAGE_DIR.glob("*"):
        try: f.unlink()
        except: pass

def list_stage():
    ensure_dirs()
    return sorted([p.name for p in STAGE_DIR.glob("*") if p.is_file()])

# ---------- Import helpers (threaded) ----------
def import_photo_from_photos(sender):
    # single-photo import using pick_image, process in background
    ui.delay(_pick_and_stage_photo, 0.05)

def _pick_and_stage_photo():
    try:
        img = photos.pick_image()  # single photo
    except Exception as e:
        notify("Picker failed: " + str(e), 'error')
        return
    if not img:
        notify("No photo selected", 'error'); return

    # process in background
    t = threading.Thread(target=_photo_worker, args=(img,))
    t.daemon = True
    t.start()

def _photo_worker(img):
    added = 0
    try:
        # many Pythonista versions let you save the image directly
        fname = f"photo_{int(time.time())}.jpg"
        try:
            img.save(fname)
            stage_add_file(fname)
            added += 1
            # optionally remove temp file
            if AUTO_DELETE:
                try: os.remove(fname)
                except: pass
        except Exception:
            # try png bytes
            try:
                data = img.to_png()
                stage_add_bytes(fname, data)
                added += 1
            except Exception:
                pass
    except Exception:
        pass

    def finish():
        notify(f"Staged {added} photo(s)")
        try: refresh_grid()
        except: pass

    ui.delay(finish, 0.01)

# ---------- Video import (Photos) ----------
def import_video_from_photos(sender):
    # pick a video asset (single)
    ui.delay(_pick_and_stage_video_asset, 0.05)

def _pick_and_stage_video_asset():
    # show activity while user picks
    try:
        assets = photos.pick_asset(multi=False)
    except Exception as e:
        notify("Picker failed: " + str(e), 'error'); return
    if not assets:
        notify("No asset selected", 'error'); return
    asset = assets if not isinstance(assets, (list,tuple)) else (assets[0] if assets else None)
    if asset is None:
        notify("No asset", 'error'); return

    # background process
    t = threading.Thread(target=_video_asset_worker, args=(asset,))
    t.daemon = True
    t.start()

def _video_asset_worker(asset):
    added = 0
    # Try several fallbacks to extract video bytes or a temporary file path:
    # 1) photos.get_video(asset)
    # 2) asset.get_video()
    # 3) photos.get_image_data(asset) maybe contains original bytes (rare)
    # If none works, we inform the user.
    try:
        video_path = None
        # attempt photos.get_video if available
        try:
            vp = photos.get_video(asset)
            # get_video often returns a file path or bytes depending on Pythonista version
            if isinstance(vp, str) and os.path.exists(vp):
                video_path = vp
            elif isinstance(vp, (bytes, bytearray)):
                fname = f"video_{int(time.time())}.mov"
                stage_add_bytes(fname, vp)
                added += 1
        except Exception:
            pass

        if video_path is None:
            # try asset.get_video()
            try:
                av = asset.get_video()
                if isinstance(av, str) and os.path.exists(av):
                    video_path = av
                elif isinstance(av, (bytes, bytearray)):
                    fname = f"video_{int(time.time())}.mov"
                    stage_add_bytes(fname, av)
                    added += 1
            except Exception:
                pass

        if video_path is None:
            # try direct raw data (less likely)
            try:
                raw = photos.get_image_data(asset)
                if raw:
                    # could be video bytes or image bytes; check signature
                    # mp4/quicktime typically start with bytes like b'\x00\x00\x00' or 'ftyp'
                    fname = f"video_{int(time.time())}.mov"
                    stage_add_bytes(fname, raw)
                    added += 1
            except Exception:
                pass

        if video_path:
            # copy the file into staging
            try:
                fname = os.path.basename(video_path)
                name_out = f"video_{int(time.time())}_{fname}"
                dst = STAGE_DIR / name_out
                # copy file bytes
                with open(video_path, "rb") as fr, open(dst, "wb") as fw:
                    fw.write(fr.read())
                added += 1
            except Exception:
                pass
    except Exception:
        pass

    def finish():
        notify(f"Staged {added} video(s)")
        try: refresh_grid()
        except: pass

    ui.delay(finish, 0.01)

# ---------- Video import (Files) ----------
def import_video_from_files(sender):
    # user picks a file from Pythonista Documents (list dialog)
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    if not files:
        notify("No files in Documents", 'error'); return
    sel = dialogs.list_dialog("Select video file to stage", files)
    if not sel:
        return
    # very simple check by extension
    if not sel.lower().endswith(('.mp4','.mov','.m4v','.avi','.mpg','.mpeg','.3gp')):
        if not dialogs.confirm("Selected file doesn't look like a video. Stage anyway?"):
            return
    try:
        stage_add_file(sel)
        notify("Staged file: " + sel)
        refresh_grid()
    except Exception as e:
        notify("Failed to stage: " + str(e), 'error')

# ---------- Lock / Unlock ----------
def action_lock(sender):
    if not KEYFILE.exists():
        notify("Initialize vault first", 'error'); return
    pw = password_prompt("Encrypt", "Enter master password")
    if not pw: return
    try:
        enc_key, mac_key, salt = load_keys(pw)
    except Exception:
        notify("Wrong password", 'error'); return
    zipb = pack_stage_to_zip()
    if not zipb:
        notify("Nothing staged", 'error'); return
    iv, ct = aes_ctr_encrypt(enc_key, zipb)
    tag = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    VAULT_FILE.write_bytes(salt + tag + iv + ct)
    clear_stage()
    notify("Vault locked")
    refresh_grid()

def action_unlock(sender):
    if not VAULT_FILE.exists():
        notify("No vault", 'error'); return
    pw = password_prompt("Decrypt", "Enter master password")
    if not pw: return
    try:
        enc_key, mac_key, salt = load_keys(pw)
    except Exception:
        notify("Wrong password", 'error'); return
    raw = VAULT_FILE.read_bytes()
    if len(raw) < 16 + 32 + 16:
        notify("Vault corrupted", 'error'); return
    tag = raw[16:48]
    iv = raw[48:64]
    ct = raw[64:]
    expected = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        notify("Integrity check failed", 'error'); return
    pt = aes_ctr_decrypt(enc_key, iv, ct)
    # clear unpack dir then extract
    for f in UNPACK_DIR.glob("*"):
        try: f.unlink()
        except: pass
    unpack_zip(pt, UNPACK_DIR)
    notify(f"Decrypted → {UNPACK_DIR}")
    if BURN_AFTER_READ:
        try: VAULT_FILE.unlink()
        except: pass

# ---------- UI: thumbnails ----------
THUMB_SIZE = 92
PADDING = 10
GRID_COLS = 3

def make_thumb(fn):
    v = ui.View(frame=(0,0,THUMB_SIZE,THUMB_SIZE+28))
    p = STAGE_DIR / fn
    try:
        img = ui.Image.named(str(p))
        if img:
            iv = ui.ImageView(frame=(0,0,THUMB_SIZE,THUMB_SIZE))
            iv.image = img
            iv.content_mode = ui.CONTENT_SCALE_ASPECT_FILL
            v.add_subview(iv)
    except:
        pass
    lab = ui.Label(frame=(0,THUMB_SIZE,THUMB_SIZE,28))
    lab.text = fn
    lab.font = ('<system>',10)
    lab.number_of_lines = 2
    v.add_subview(lab)
    def tapped(sender):
        if dialogs.confirm("Remove staged file?", fn):
            try: (STAGE_DIR / fn).unlink()
            except: pass
            refresh_grid()
    btn = ui.Button(frame=(0,0,THUMB_SIZE,THUMB_SIZE+28))
    btn.action = lambda s: tapped(s)
    btn.background_color = 'clear'
    v.add_subview(btn)
    return v

def refresh_grid():
    ensure_dirs()
    sv = ui_view['grid']
    for s in list(sv.subviews):
        sv.remove_subview(s)
    items = list_stage()
    x = PADDING; y = PADDING; col = 0
    for fn in items:
        w = make_thumb(fn)
        w.frame = (x, y, THUMB_SIZE, THUMB_SIZE+28)
        sv.add_subview(w)
        col += 1
        if col >= GRID_COLS:
            col = 0
            x = PADDING
            y += THUMB_SIZE + 28 + PADDING
        else:
            x += THUMB_SIZE + PADDING
    rows = (len(items) + GRID_COLS - 1)//GRID_COLS
    content_h = rows * (THUMB_SIZE + 28 + PADDING) + PADDING
    sv.content_size = (sv.width, max(sv.height, content_h))

# ---------- UI actions & helper controls ----------
def action_initialize(sender):
    pw = password_prompt("Create password", "Enter new master password")
    if not pw: notify("Cancelled", 'error'); return
    pw2 = password_prompt("Confirm password", "Re-enter master password")
    if pw2 != pw:
        notify("Passwords do not match", 'error'); return
    create_keyfile(pw)
    notify("Keyfile created")
    refresh_grid()

def action_add_file(sender):
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    if not files:
        notify("No files", 'error'); return
    sel = dialogs.list_dialog("Pick file", files)
    if not sel: return
    stage_add_file(sel)
    if AUTO_DELETE:
        try: os.remove(sel)
        except: pass
    refresh_grid()
    notify("Added")

def action_export_vault(sender):
    if VAULT_FILE.exists(): console.open_in(str(VAULT_FILE))
    else: notify("No vault", 'error')

def action_export_backup(sender):
    if BACKUP_KEYFILE.exists(): console.open_in(str(BACKUP_KEYFILE))
    else: notify("No backup", 'error')

def action_reset(sender):
    if dialogs.alert("Reset?", "Delete key + vault?", "OK","Cancel") != 1: return
    try:
        if KEYFILE.exists(): KEYFILE.unlink()
        if VAULT_FILE.exists(): VAULT_FILE.unlink()
        if BACKUP_KEYFILE.exists(): BACKUP_KEYFILE.unlink()
        clear_stage()
        notify("Reset complete")
        refresh_grid()
    except Exception as e:
        notify(str(e), 'error')

def action_wipe_unpacked(sender):
    for f in UNPACK_DIR.glob("*"):
        try: f.unlink()
        except: pass
    notify("Unpacked wiped")

# ---------- Build UI ----------
def build_ui():
    global ui_view
    ensure_dirs()
    ui_view = ui.View()
    ui_view.name = "Master Vault"
    ui_view.background_color = 'white'
    ui_view.frame = (0,0,420,900)

    y = 10
    def add_btn(title, action, w=396, h=44):
        nonlocal y
        b = ui.Button(title=title, frame=(12,y,w,h))
        b.action = action
        ui_view.add_subview(b)
        y += 52
        return b

    add_btn("Initialize Vault", action_initialize)
    add_btn("Import Photo (Photos)", import_photo_from_photos)
    add_btn("Import Video (Photos)", import_video_from_photos)
    add_btn("Import Video (Files)", import_video_from_files)
    add_btn("Add File (Documents)", action_add_file)

    lbl = ui.Label(frame=(12,y,396,22))
    lbl.text = "Staged Files (tap thumbnail to remove)"
    ui_view.add_subview(lbl); y += 28

    sv = ui.ScrollView(frame=(12,y,396,300))
    sv.name = "grid"
    sv.background_color = "#FAFAFA"
    ui_view.add_subview(sv); y += 312

    add_btn("Lock (Encrypt) -> Hidden Vault", action_lock)
    add_btn("Unlock Vault (Decrypt)", action_unlock)

    # toggles
    b1 = ui.Button(title="Auto-delete: OFF", frame=(12,y,196,40))
    def tog_autodel(sender):
        global AUTO_DELETE
    # we use separate function to avoid closure issues
    ui_view.add_subview(b1)
    def tog_autodel_impl(sender):
        global AUTO_DELETE
        AUTO_DELETE = not AUTO_DELETE
        sender.title = f"Auto-delete: {'ON' if AUTO_DELETE else 'OFF'}"
    b1.action = tog_autodel_impl

    b2 = ui.Button(title="Burn-after-read: OFF", frame=(212,y,196,40))
    def tog_burn_impl(sender):
        global BURN_AFTER_READ
        BURN_AFTER_READ = not BURN_AFTER_READ
        sender.title = f"Burn-after-read: {'ON' if BURN_AFTER_READ else 'OFF'}"
    b2.action = tog_burn_impl
    ui_view.add_subview(b2)
    y += 52

    add_btn("Export Vault", action_export_vault)
    add_btn("Export Backup Keyfile (share)", action_export_backup)
    add_btn("Wipe Unpacked", action_wipe_unpacked)
    add_btn("Reset (delete key & vault)", action_reset)

    info = ui.TextView(frame=(12,y,396,120))
    info.editable = False
    info.text = ("Notes:\n- Hidden folder: {0}\n- Use Import Photo (Photos) to pick one image at a time.\n- Use Import Video (Photos) to pick videos from Photos.\n- Use Import Video (Files) to stage video files from Documents.\n- After Lock, staged files are cleared.\n- Move backup keyfile to iCloud manually for safe storage.").format(HIDDEN_DIR.name)
    info.font = ('<system>',12)
    ui_view.add_subview(info)

    return ui_view

# ---------- Start ----------
if __name__ == "__main__":
    ui_view = build_ui()
    ui_view.present('fullscreen')
    refresh_grid()
