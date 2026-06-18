"""
CoreVault Application Presentation Layer
Version: 1.0.0 (Enterprise Production Build)
Description: Provides UI/UX controls for managing local sandboxes and software validation.
"""

import os
import gc
import customtkinter as ctk
from tkinter import filedialog, messagebox
import vault_engine  # Dynamic link to core crypt-engine module

class CoreVaultGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CoreVault v1.0 [Enterprise Ready]")
        self.geometry("480x620")
        self.resizable(False, False)
        self.configure(fg_color="#141414")
        
        self.target_file_path = ""
        self.local_hwid = vault_engine.get_immutable_hwid()
        self.is_licensed = False 

        # --- Frame 1: Security Telemetry Header ---
        self.header_frame = ctk.CTkFrame(self, fg_color="#1f1f1f", corner_radius=8, border_width=1, border_color="#2d2d2d")
        self.header_frame.pack(pady=(20, 10), padx=25, fill="x")

        self.title_label = ctk.CTkLabel(self.header_frame, text="COREVAULT SYSTEM", font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"), text_color="#ffffff")
        self.title_label.pack(pady=(12, 2))
        
        self.hwid_label = ctk.CTkLabel(self.header_frame, text=f"HARDWARE NODE: {self.local_hwid[:26].upper()}", font=ctk.CTkFont(family="Consolas", size=11), text_color="#555555")
        self.hwid_label.pack(pady=(0, 12))

        # --- Frame 2: Commercial Monetization Verification ---
        self.license_frame = ctk.CTkFrame(self, fg_color="#1f1f1f", corner_radius=8, border_width=1, border_color="#c47a1a")
        self.license_frame.pack(pady=5, padx=25, fill="x")
        
        self.license_entry = ctk.CTkEntry(self.license_frame, placeholder_text="Enter BuyMeACoffee Master License...", height=30, show="*")
        self.license_entry.pack(side="left", padx=(15, 5), text_color="#ffffff", pady=10, expand=True, fill="x")
        
        self.license_btn = ctk.CTkButton(self.license_frame, text="Verify", width=70, height=30, fg_color="#c47a1a", hover_color="#9e6213", command=self.verify_corporate_license)
        self.license_btn.pack(side="right", padx=(5, 15), pady=10)

        # --- Frame 3: Object Stream Selector ---
        self.file_frame = ctk.CTkFrame(self, fg_color="#1f1f1f", corner_radius=8, border_width=1, border_color="#2d2d2d")
        self.file_frame.pack(pady=10, padx=25, fill="x")

        self.file_btn = ctk.CTkButton(self.file_frame, text="CHOOSE TARGET FILE", command=self.select_file, fg_color="#1c4475", hover_color="#245999", font=ctk.CTkFont(weight="bold"))
        self.file_btn.pack(pady=(15, 5), padx=20, fill="x")
        
        self.file_status_label = ctk.CTkLabel(self.file_frame, text="STATUS: NO OBJECT QUEUED", font=ctk.CTkFont(size=12, weight="bold"), text_color="#b88428")
        self.file_status_label.pack(pady=(0, 15))

        # --- Frame 4: Policy Matrices & Variable Controls ---
        self.input_frame = ctk.CTkFrame(self, fg_color="#1f1f1f", corner_radius=8, border_width=1, border_color="#2d2d2d")
        self.input_frame.pack(pady=10, padx=25, fill="x")

        self.pass_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Enter Cryptographic Passphrase...", height=38, show="*")
        self.pass_entry.pack(pady=15, padx=20, fill="x")

        self.grid_frame = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        self.grid_frame.pack(pady=(0, 15), padx=20, fill="x")

        self.r_label = ctk.CTkLabel(self.grid_frame, text="Max Retries:", font=ctk.CTkFont(size=12, weight="bold"))
        self.r_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.retries_spin = ctk.CTkComboBox(self.grid_frame, values=["3", "5", "10"], width=70, height=28)
        self.retries_spin.set("5")
        self.retries_spin.grid(row=0, column=1, padx=5, pady=5)

        self.p_label = ctk.CTkLabel(self.grid_frame, text="Breach Policy:", font=ctk.CTkFont(size=12, weight="bold"))
        self.p_label.grid(row=0, column=2, padx=(15, 5), pady=5, sticky="w")
        self.penalty_box = ctk.CTkComboBox(self.grid_frame, values=["Self-Destruct Headers", "Time Lockout (15m)"], width=160, height=28)
        self.penalty_box.set("Time Lockout (15m)")
        self.penalty_box.grid(row=0, column=3, padx=5, pady=5)

        # --- Frame 5: Action Invocation Pipeline ---
        self.action_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.action_frame.pack(pady=15, padx=25, fill="x")

        self.lock_btn = ctk.CTkButton(self.action_frame, text="🔒 LOCK FILE", command=lambda: self.process_vault('lock'), fg_color="#822222", hover_color="#a12b2b", height=42, font=ctk.CTkFont(weight="bold"))
        self.lock_btn.pack(side="left", expand=True, fill="x", padx=(0, 6))

        self.unlock_btn = ctk.CTkButton(self.action_frame, text="🔓 UNLOCK FILE", command=lambda: self.process_vault('unlock'), fg_color="#228249", hover_color="#2ba15b", height=42, font=ctk.CTkFont(weight="bold"))
        self.unlock_btn.pack(side="right", expand=True, fill="x", padx=(6, 0))

    def verify_corporate_license(self):
        key = self.license_entry.get()
        if vault_engine.verify_static_corporate_license(key):
            self.is_licensed = True
            self.license_frame.configure(border_color="#2bba5c")
            self.license_entry.configure(state="disabled")
            self.license_btn.configure(state="disabled", text="Active")
            messagebox.showinfo("License Authorized", "Enterprise Commercial Node Activated.")
        else:
            messagebox.showerror("Validation Failure", "The provided enterprise license key is invalid.")

    def select_file(self):
        self.target_file_path = filedialog.askopenfilename()
        if self.target_file_path:
            filename = os.path.basename(self.target_file_path)
            self.file_status_label.configure(text=f"QUEUED: {filename.upper()}", text_color="#2bba5c")

    def process_vault(self, mode):
        if not self.is_licensed:
            answer = messagebox.askyesno("EULA Requirement", "Are you utilizing this utility strictly for individual, non-commercial private purposes?\n\n(Hospitals, Commercial entities, and Corporate environments must deploy an Enterprise Token).")
            if not answer:
                messagebox.showerror("Execution Terminated", "Deployment blocked. Please input a valid commercial token.")
                return

        if not self.target_file_path:
            messagebox.showerror("Error", "No valid binary object currently loaded in buffer queue.")
            return
        passphrase = self.pass_entry.get()
        if not passphrase:
            messagebox.showerror("Error", "Symmetric passphrases cannot contain a null length.")
            return

        max_retries = int(self.retries_spin.get())
        penalty_type = 1 if "Self-Destruct" in self.penalty_box.get() else 2
        
        success, message = vault_engine.execute_tamper_proof_vault(
            file_path=self.target_file_path, passphrase=passphrase, hw_token=self.local_hwid,
            mode=mode, max_retries=max_retries, penalty_type=penalty_type, cooldown_minutes=15
        )

        if success:
            messagebox.showinfo("Operation Complete", message)
            self.file_status_label.configure(text="STATUS: NO OBJECT QUEUED", text_color="#b88428")
            self.target_file_path = ""
            self.pass_entry.delete(0, 'end')
        else:
            messagebox.showerror("Operation Aborted", message)
            
        gc.collect()

if __name__ == "__main__":
    app = CoreVaultGUI()
    app.mainloop()