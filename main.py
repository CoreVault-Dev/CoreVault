"""
CoreVault Application Presentation Layer
Version: 1.1.0 (Production Ready)
Author: Security Engineering Team
"""

import os
import gc
import sys
import customtkinter as ctk
from tkinter import filedialog
import vault_engine 

# ==============================================================================
# WINDOWS OS INTEGRATION (ANTI-GROUPING PATCH)
# ==============================================================================
# By default, Windows groups compiled Python apps under the generic Python/Tkinter icon.
# Using ctypes to register a custom AppUserModelID forces the OS to recognize this
# executable as a standalone application, unlocking the custom taskbar icon.
if sys.platform == "win32":
    import ctypes
    myappid = "corevault.cryptographic.security.v1.1.8" 
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

# ==============================================================================
# RESOURCE PATH RESOLUTION (PYINSTALLER COMPATIBILITY)
# ==============================================================================
def get_resource_path(relative_path):
    """
    Resolves the absolute path to external assets (like app.ico).
    When running as a standalone EXE, PyInstaller unpacks data to a temporary
    directory stored in sys._MEIPASS. This function handles both dev and prod states.
    """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# ==============================================================================
# MAIN APPLICATION INTERFACE
# ==============================================================================
class CoreVaultGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Geometry & Behavioral Policies
        self.title("CoreVault v1.1.0")
        self.geometry("490x670") 
        self.resizable(False, False)
        self.configure(fg_color="#141414")

        # ----------------------------------------------------------------------
        # SQUARE LOCK ICON INITIATION Pipeline
        # ----------------------------------------------------------------------
        # Resolving the absolute asset pipeline path for your white lock icon.
        # This replaces the default fallback blue/cyan icon with your custom design.
        icon_path = get_resource_path("app.ico")
        if os.path.exists(icon_path):
            # Sets the icon for the Window Title Bar and Explorer window
            self.iconbitmap(icon_path)
            # Safe-guard enforcement callback to fix asynchronous rendering lag 
            # common in CustomTkinter window initialization loops.
            self.after(200, lambda: self.iconbitmap(icon_path))
        
        # Runtime State Variables
        self.target_file_path = ""
        self.local_hwid = vault_engine.get_immutable_hwid()
        self.wallet_address = "0xC7D36738Bb71F97afA3Cd0ce78514A114fBB8dc5"

        # ----------------------------------------------------------------------
        # UI FRAME 1: SECURITY TELEMETRY HEADER
        # ----------------------------------------------------------------------
        self.header_frame = ctk.CTkFrame(self, fg_color="#1f1f1f", corner_radius=8, border_width=1, border_color="#2d2d2d")
        self.header_frame.pack(pady=(20, 10), padx=25, fill="x")

        self.title_label = ctk.CTkLabel(self.header_frame, text="COREVAULT SYSTEM", font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"), text_color="#ffffff")
        self.title_label.pack(pady=(12, 2))
        
        self.hwid_label = ctk.CTkLabel(self.header_frame, text=f"HARDWARE NODE: {self.local_hwid[:26].upper()}", font=ctk.CTkFont(family="Consolas", size=11), text_color="#777777")
        self.hwid_label.pack(pady=(0, 12))

        # ----------------------------------------------------------------------
        # UI FRAME 2: OBJECT STREAM SELECTOR
        # ----------------------------------------------------------------------
        self.file_frame = ctk.CTkFrame(self, fg_color="#1f1f1f", corner_radius=8, border_width=1, border_color="#2d2d2d")
        self.file_frame.pack(pady=10, padx=25, fill="x")

        self.file_btn = ctk.CTkButton(self.file_frame, text="CHOOSE TARGET FILE", command=self.select_file, fg_color="#1c4475", hover_color="#245999", font=ctk.CTkFont(weight="bold"))
        self.file_btn.pack(pady=(15, 5), padx=20, fill="x")
        
        self.file_status_label = ctk.CTkLabel(self.file_frame, text="STATUS: NO OBJECT QUEUED", font=ctk.CTkFont(size=12, weight="bold"), text_color="#b88428")
        self.file_status_label.pack(pady=(0, 15))

        # ----------------------------------------------------------------------
        # UI FRAME 3: POLICY MATRICES & VARIABLE CONTROLS
        # ----------------------------------------------------------------------
        self.input_frame = ctk.CTkFrame(self, fg_color="#1f1f1f", corner_radius=8, border_width=1, border_color="#2d2d2d")
        self.input_frame.pack(pady=10, padx=25, fill="x")

        self.pass_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Enter Cryptographic Passphrase...", height=38, show="*")
        self.pass_entry.pack(pady=15, padx=20, fill="x")

        self.grid_frame = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        self.grid_frame.pack(pady=(0, 15), padx=20, fill="x")

        # Security Matrix Component: Max Retries
        self.r_label = ctk.CTkLabel(self.grid_frame, text="Max Retries:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff")
        self.r_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.retries_entry = ctk.CTkEntry(self.grid_frame, width=90, height=28)
        self.retries_entry.insert(0, "5")
        self.retries_entry.grid(row=0, column=1, padx=5, pady=5)

        # Security Matrix Component: Breach Policy
        self.p_label = ctk.CTkLabel(self.grid_frame, text="Breach Policy:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff")
        self.p_label.grid(row=0, column=2, padx=(15, 5), pady=5, sticky="w")
        self.penalty_menu = ctk.CTkOptionMenu(self.grid_frame, values=["Temporary Lockout", "Destroy File Forever"], width=155, height=28, fg_color="#2b2b2b", button_color="#1f1f1f", button_hover_color="#3d3d3d")
        self.penalty_menu.set("Temporary Lockout")
        self.penalty_menu.grid(row=0, column=3, padx=5, pady=5)

        # Security Matrix Component: Cooldown Operational Parameters
        self.t_label = ctk.CTkLabel(self.grid_frame, text="Lockout (Min):", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff")
        self.t_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.time_entry = ctk.CTkEntry(self.grid_frame, width=90, height=28)
        self.time_entry.insert(0, "15")
        self.time_entry.grid(row=1, column=1, padx=5, pady=5)

        # ----------------------------------------------------------------------
        # UI FRAME 4: ACTION INVOCATION PIPELINE
        # ----------------------------------------------------------------------
        self.action_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.action_frame.pack(pady=(10, 5), padx=25, fill="x")

        self.lock_btn = ctk.CTkButton(self.action_frame, text="🔒 LOCK FILE", command=lambda: self.process_vault('lock'), fg_color="#822222", hover_color="#a12b2b", height=42, font=ctk.CTkFont(weight="bold"))
        self.lock_btn.pack(side="left", expand=True, fill="x", padx=(0, 6))

        self.unlock_btn = ctk.CTkButton(self.action_frame, text="🔓 UNLOCK FILE", command=lambda: self.process_vault('unlock'), fg_color="#228249", hover_color="#2ba15b", height=42, font=ctk.CTkFont(weight="bold"))
        self.unlock_btn.pack(side="right", expand=True, fill="x", padx=(6, 0))

        # Real-time Telemetry Terminal Status Display Label
        self.status_msg_label = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=13, weight="bold"), wraplength=440)
        self.status_msg_label.pack(pady=(5, 5), padx=25)

        # ----------------------------------------------------------------------
        # UI FRAME 5: DEVELOPER CONTRIBUTIONS PIPELINE (DONATION FOOTER)
        # ----------------------------------------------------------------------
        self.support_frame = ctk.CTkFrame(self, fg_color="#1f1f1f", corner_radius=8, border_width=1, border_color="#2d2d2d")
        self.support_frame.pack(pady=(5, 10), padx=25, fill="x", side="bottom")

        self.support_title = ctk.CTkLabel(self.support_frame, text="💝 Support via MetaMask (Network: BNB Smart Chain)", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff")
        self.support_title.pack(pady=(8, 2))

        self.wallet_align_frame = ctk.CTkFrame(self.support_frame, fg_color="transparent")
        self.wallet_align_frame.pack(pady=(0, 10))

        self.wallet_label = ctk.CTkLabel(self.wallet_align_frame, text=self.wallet_address, font=ctk.CTkFont(family="Consolas", size=10), text_color="#888888")
        self.wallet_label.pack(side="left", padx=(0, 10))

        self.copy_btn = ctk.CTkButton(self.wallet_align_frame, text="COPY", width=50, height=22, fg_color="#2d2d2d", hover_color="#3d3d3d", font=ctk.CTkFont(size=10, weight="bold"), command=self.copy_address_to_clipboard)
        self.copy_btn.pack(side="left")

    def copy_address_to_clipboard(self):
        """ Copies the hardcoded Web3 Wallet public hash into the operating system clipboard """
        self.clipboard_clear()
        self.clipboard_append(self.wallet_address)
        self.copy_btn.configure(text="COPIED!", fg_color="#2ecc71", text_color="#000000")
        self.after(2000, lambda: self.copy_btn.configure(text="COPY", fg_color="#2d2d2d", text_color="#ffffff"))

    def select_file(self):
        """ Invokes OS local file explorer dialog to register target file path """
        self.target_file_path = filedialog.askopenfilename()
        if self.target_file_path:
            filename = os.path.basename(self.target_file_path)
            self.file_status_label.configure(text=f"QUEUED: {filename.upper()}", text_color="#2bba5c")
            self.status_msg_label.configure(text="") 

    def process_vault(self, mode):
        """ Extracts variables and pipelines payload stream to the engine core """
        self.status_msg_label.configure(text="")
        if not self.target_file_path:
            self.status_msg_label.configure(text="[!] BUFFER EMPTY: Select a valid file stream destination.", text_color="#e74c3c")
            return
        passphrase = self.pass_entry.get()
        if not passphrase:
            self.status_msg_label.configure(text="[!] PARAMETER ERROR: Symmetric cryptographic keys cannot have a null length.", text_color="#e74c3c")
            return

        try:
            max_retries = int(self.retries_entry.get())
            cooldown_minutes = int(self.time_entry.get())
        except ValueError:
            self.status_msg_label.configure(text="[!] INPUT ERROR: Retries and Lockout Time must be numbers.", text_color="#e74c3c")
            return

        # Map UI policy layout options to Engine structural constants
        penalty_type = 1 if "Destroy" in self.penalty_menu.get() else 2
        
        # Execute underlying engine process
        success, message = vault_engine.execute_tamper_proof_vault(
            file_path=self.target_file_path, passphrase=passphrase, hw_token=self.local_hwid,
            mode=mode, max_retries=max_retries, penalty_type=penalty_type, cooldown_minutes=cooldown_minutes
        )

        # Handle process feedback state
        if success:
            self.status_msg_label.configure(text=f"[✔] SUCCESS: {message}", text_color="#2ecc71")
            self.file_status_label.configure(text="STATUS: NO OBJECT QUEUED", text_color="#b88428")
            self.target_file_path = ""
            self.pass_entry.delete(0, 'end')
        else:
            self.status_msg_label.configure(text=f"[✖] ABORTED: {message}", text_color="#e74c3c")
        
        # Explicitly trigger cyclic garbage collector to wipe transient key traces from volatile memory
        gc.collect()

if __name__ == "__main__":
    app = CoreVaultGUI()
    app.mainloop()