# main.py - KeyPassXC APK - Kivy version
import os, struct, json, secrets, string, math, time, threading
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.slider import Slider
from kivy.uix.scrollview import ScrollView
from kivy.core.clipboard import Clipboard
from kivy.clock import Clock
from kivy.uix.spinner import Spinner

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

VAULT_FILE = "vault.dat"
SALT_LEN = 16
IV_LEN = 16
LOCK_TIMEOUT = 60

# --- Crypto (same as C + Tkinter version) ---
def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_vault(entries, password):
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = derive_key(password, salt)
    plain = json.dumps(entries).encode()
    pad = 16 - (len(plain) % 16)
    plain += bytes([pad]*pad)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(plain) + enc.finalize()
    # Use app directory for Android storage
    path = App.get_running_app().user_data_dir + "/vault.dat"
    with open(path, "wb") as f:
        f.write(salt); f.write(iv); f.write(struct.pack("i", len(ct))); f.write(ct)
    # Also save local for testing
    with open(VAULT_FILE, "wb") as f:
        f.write(salt); f.write(iv); f.write(struct.pack("i", len(ct))); f.write(ct)

def decrypt_vault(password):
    path = App.get_running_app().user_data_dir + "/vault.dat"
    if not os.path.exists(path):
        path = VAULT_FILE
    if not os.path.exists(path): return []
    with open(path, "rb") as f:
        salt = f.read(SALT_LEN); iv = f.read(IV_LEN)
        clen = struct.unpack("i", f.read(4))[0]; ct = f.read(clen)
    key = derive_key(password, salt)
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        plain = dec.update(ct) + dec.finalize()
        pad = plain[-1]
        plain = plain[:-pad]
        return json.loads(plain.decode())
    except:
        return None

def gen_password(length=16):
    charset = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(charset) for _ in range(length))

def strength_bits(pw):
    charset = 0
    if any(c.islower() for c in pw): charset+=26
    if any(c.isupper() for c in pw): charset+=26
    if any(c.isdigit() for c in pw): charset+=10
    if any(not c.isalnum() for c in pw): charset+=10
    if charset==0: return 0
    return len(pw) * math.log2(charset)

class KeyPassApp(App):
    def build(self):
        self.title = "KeyPassXC"
        self.entries = []
        self.master = ""
        self.last_activity = time.time()
        self.selected_idx = -1
        self.show_passwords = False
        self.root_layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.show_login()
        # Auto-lock checker every 1 sec - Kivy Clock, not thread
        Clock.schedule_interval(self.check_lock, 1)
        return self.root_layout

    def touch(self, *args):
        self.last_activity = time.time()

    def check_lock(self, dt):
        if self.master and time.time() - self.last_activity > LOCK_TIMEOUT:
            self.master = ""
            self.show_popup("Locked", "Auto-locked after 60s idle")
            self.show_login()

    def clear(self):
        self.root_layout.clear_widgets()

    def show_popup(self, title, msg):
        popup = Popup(title=title, content=Label(text=msg), size_hint=(0.8, 0.4))
        popup.open()

    def show_login(self):
        self.clear()
        self.root_layout.add_widget(Label(text="🔐 KeyPassXC", font_size=32, bold=True, size_hint_y=0.3))
        self.root_layout.add_widget(Label(text="Secure Password Manager\nAES-256 • PBKDF2 • Auto-Lock 60s", halign="center", size_hint_y=0.2))
        self.pw_input = TextInput(hint_text="Master Password", password=True, multiline=False, font_size=20, size_hint_y=0.15)
        self.root_layout.add_widget(self.pw_input)
        btn = Button(text="Unlock Vault", background_color=(0, 0.83, 1, 1), font_size=20, size_hint_y=0.15)
        btn.bind(on_press=lambda x: self.unlock())
        self.root_layout.add_widget(btn)
        self.root_layout.add_widget(Label(text="First time? Just type a new master password.\nIt will create a new vault.", font_size=12, color=(0.6,0.6,0.6,1)))

    def unlock(self):
        pw = self.pw_input.text.strip()
        if not pw:
            self.show_popup("Error", "Enter master password")
            return
        res = decrypt_vault(pw)
        if res is None:
            self.show_popup("Error", "Wrong master password!")
            return
        self.master = pw
        self.entries = res
        self.touch()
        self.show_main()

    def show_main(self):
        self.clear()
        # Top bar
        top = BoxLayout(orientation='horizontal', size_hint_y=0.1, spacing=5)
        top.add_widget(Label(text=f"Vault: {len(self.entries)} entries", bold=True))
        lock_btn = Button(text="🔒 Lock", background_color=(0.9, 0.27, 0.37, 1))
        lock_btn.bind(on_press=lambda x: self.lock())
        save_btn = Button(text="💾 Save", background_color=(0, 0.83, 1, 1))
        save_btn.bind(on_press=lambda x: self.save())
        top.add_widget(save_btn); top.add_widget(lock_btn)
        self.root_layout.add_widget(top)

        # Generator - gen 16 / gen 32 with Slider
        gen_box = BoxLayout(orientation='vertical', size_hint_y=0.25, spacing=5)
        gen_box.add_widget(Label(text="Password Generator - Slide for Length", bold=True))
        slider_row = BoxLayout(orientation='horizontal', spacing=5)
        self.gen_slider = Slider(min=8, max=64, value=16, step=1)
        self.gen_slider.bind(value=self.on_slider)
        self.gen_len_label = Label(text="16 chars", size_hint_x=0.3)
        slider_row.add_widget(self.gen_slider); slider_row.add_widget(self.gen_len_label)
        gen_box.add_widget(slider_row)
        gen_row = BoxLayout(orientation='horizontal', spacing=5)
        self.gen_out = TextInput(hint_text="Generated password appears here", readonly=True, font_size=16)
        gen_btn = Button(text="Generate", background_color=(0, 0.83, 1, 1), size_hint_x=0.3)
        gen_btn.bind(on_press=lambda x: self.do_gen())
        copy_btn = Button(text="📋 Copy", size_hint_x=0.25)
        copy_btn.bind(on_press=lambda x: self.copy_gen())
        gen_row.add_widget(self.gen_out); gen_row.add_widget(gen_btn); gen_row.add_widget(copy_btn)
        gen_box.add_widget(gen_row)
        self.strength_label = Label(text="Strength: -", color=(0, 1, 0.5, 1))
        gen_box.add_widget(self.strength_label)
        self.root_layout.add_widget(gen_box)

        # Search + Category
        search_box = BoxLayout(orientation='horizontal', size_hint_y=0.1, spacing=5)
        self.search_input = TextInput(hint_text="🔍 Search...", multiline=False)
        self.search_input.bind(text=lambda inst, val: self.refresh_list())
        search_box.add_widget(self.search_input)
        cats = ["All"] + sorted(set(e.get("category","General") for e in self.entries))
        self.cat_spinner = Spinner(text="All", values=cats, size_hint_x=0.35)
        self.cat_spinner.bind(text=lambda inst, val: self.refresh_list())
        search_box.add_widget(self.cat_spinner)
        self.root_layout.add_widget(search_box)

        # List - Scrollable
        scroll = ScrollView(size_hint_y=0.45)
        self.list_layout = BoxLayout(orientation='vertical', size_hint_y=None, spacing=5)
        self.list_layout.bind(minimum_height=self.list_layout.setter('height'))
        scroll.add_widget(self.list_layout)
        self.root_layout.add_widget(scroll)

        # Bottom buttons
        btns = GridLayout(cols=4, size_hint_y=0.15, spacing=5)
        for txt, func, col in [
            ("➕ Add", self.add_popup, (0, 1, 0.5, 1)),
            ("✏️ Edit", self.edit_popup, (1, 0.8, 0, 1)),
            ("🗑️ Delete", self.delete_entry, (0.9, 0.27, 0.37, 1)),
            ("👁️ Show/Hide", self.toggle_show, (0, 0.83, 1, 1)),
        ]:
            b = Button(text=txt, background_color=col)
            b.bind(on_press=lambda x, f=func: f())
            btns.add_widget(b)
        self.root_layout.add_widget(btns)
        self.refresh_list()

    def on_slider(self, inst, val):
        self.gen_len_label.text = f"{int(val)} chars"

    def do_gen(self):
        length = int(self.gen_slider.value)
        pw = gen_password(length)
        self.gen_out.text = pw
        bits = strength_bits(pw)
        label = "WEAK" if bits<40 else "FAIR" if bits<60 else "GOOD" if bits<80 else "STRONG" if bits<100 else "VERY STRONG"
        self.strength_label.text = f"Strength: {bits:.0f} bits | {label} | ✅ Copied!"
        Clipboard.copy(pw)
        self.touch()

    def copy_gen(self):
        if self.gen_out.text:
            Clipboard.copy(self.gen_out.text)
            self.show_popup("Copied", "Password copied to clipboard!")

    def lock(self):
        self.master = ""
        self.show_login()

    def save(self):
        if not self.master: return
        encrypt_vault(self.entries, self.master)
        self.show_popup("Saved", f"Saved {len(self.entries)} entries")
        self.touch()

    def refresh_list(self):
        self.list_layout.clear_widgets()
        q = self.search_input.text.lower() if hasattr(self, 'search_input') else ""
        cat = self.cat_spinner.text if hasattr(self, 'cat_spinner') else "All"
        for i, e in enumerate(self.entries):
            if cat != "All" and e.get("category") != cat: continue
            if q and q not in (e["site"]+e["username"]).lower(): continue
            pw_display = e["password"] if self.show_passwords else "********"
            txt = f"[{e.get('category','General')}] {e['site']} | {e['username']} | {pw_display}"
            btn = Button(text=txt, size_hint_y=None, height=50, halign="left")
            # Capture index correctly
            btn.bind(on_press=lambda x, idx=i: self.select_entry(idx))
            self.list_layout.add_widget(btn)

    def select_entry(self, idx):
        self.selected_idx = idx
        self.touch()
        e = self.entries[idx]
        self.show_popup(e["site"], f"User: {e['username']}\nPass: {e['password']}\nCategory: {e.get('category')}")
        Clipboard.copy(e["password"])

    def toggle_show(self):
        self.show_passwords = not self.show_passwords
        self.refresh_list()

    def add_popup(self):
        content = BoxLayout(orientation='vertical', spacing=5, padding=10)
        site = TextInput(hint_text="Site (e.g. gmail)")
        user = TextInput(hint_text="Username")
        cat = TextInput(hint_text="Category (Social/Bank/School)")
        pw = TextInput(hint_text="Password - leave empty to use generator")
        content.add_widget(site); content.add_widget(user); content.add_widget(cat); content.add_widget(pw)
        def save_entry(inst):
            s = site.text.strip()
            if not s: return
            p = pw.text.strip() or self.gen_out.text or gen_password(16)
            # Support "gen 32" typed in popup too
            if p.startswith("gen"):
                try: l = int(p.split()[1])
                except: l = 16
                p = gen_password(l)
            self.entries.append({"site": s, "username": user.text.strip(), "password": p, "category": cat.text.strip() or "General"})
            self.save()
            popup.dismiss()
            self.show_main()
        save_btn = Button(text="Save Entry", background_color=(0, 1, 0.5, 1))
        save_btn.bind(on_press=save_entry)
        content.add_widget(save_btn)
        popup = Popup(title="Add Entry", content=content, size_hint=(0.9, 0.7))
        popup.open()
        self._popup = popup

    def edit_popup(self):
        if self.selected_idx < 0 or self.selected_idx >= len(self.entries):
            self.show_popup("Select", "Tap an entry first to select it, then Edit")
            return
        e = self.entries[self.selected_idx]
        content = BoxLayout(orientation='vertical', spacing=5, padding=10)
        pw = TextInput(hint_text=f"New password for {e['site']} (gen 24 for random)")
        content.add_widget(Label(text=f"Editing {e['site']}"))
        content.add_widget(pw)
        def do_edit(inst):
            p = pw.text.strip()
            if p.startswith("gen"):
                try: l = int(p.split()[1])
                except: l = 16
                p = gen_password(l)
            if p: e["password"] = p
            self.save()
            popup.dismiss()
            self.show_main()
        b = Button(text="Update", background_color=(1, 0.8, 0, 1))
        b.bind(on_press=do_edit)
        content.add_widget(b)
        popup = Popup(title="Edit", content=content, size_hint=(0.9, 0.5))
        popup.open()

    def delete_entry(self):
        if self.selected_idx < 0:
            self.show_popup("Select", "Tap an entry first, then Delete")
            return
        del self.entries[self.selected_idx]
        self.selected_idx = -1
        self.save()
        self.show_main()

if __name__ == "__main__":
    KeyPassApp().run()
