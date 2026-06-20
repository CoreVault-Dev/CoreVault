# CoreVault v1.1.0 🛡️

CoreVault is a lightweight, high-security cryptographic file-locking application engineered for robust local data protection. Built on top of a secure Python backend and a modern CustomTkinter presentation layer, it features hardware-enforced accessibility and dynamic anti-tampering logic.

---

## Key Technical Specifications

* **Hardware Node Authentication:** Uses cryptographic system calls to bind the encryption pipeline to an unalterable Hardware ID (HWID), mitigating remote unauthorized access.
* **Dynamic Security Grid Matrix:** Fully customizable breach thresholds featuring automated temporary security lockouts or irreversible file destruction mechanisms.
* **Standalone OS Shell Integration:** Integrated using low-level Windows `ctypes` processes to support standalone Taskbar, Task Manager, and Title Bar icon branding.
* **Secure Memory Optimization:** Deploys systematic Garbage Collection calls immediately following payload delivery to wipe symmetric cryptographic keys from volatile memory.

---

## Project Architecture

Ensure your local development directory maintains the following infrastructure layout:

```text
📁 CoreVault
├── 📄 main.py          # Production presentation layer & UI logic
├── 📄 vault_engine.py  # Underlying core security & encryption logic
├── 🖼️ app.ico          # Official application square icon asset
└── 📄 README.md        # Technical repository manual
Deployment & Production Build
To compile the application source code into a standalone executable (.exe) featuring native asset wrapping, deploy the following PyInstaller routine inside your administrative PowerShell terminal:

PowerShell
python -m PyInstaller --noconsole --onefile --name "CoreVault" --icon="app.ico" --add-data "app.ico;." --collect-all customtkinter main.py
Binary Distribution
To download the pre-compiled, production-ready version of CoreVault without setting up a Python environment, please navigate to the official GitHub Releases tab of this repository.