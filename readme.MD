# 🛡️ LatticeGuard SBOM

**Quantum-Safe Software Supply Chain Security Platform**

LatticeGuard SBOM is an advanced dependency security tool that generates Software Bills of Materials (SBOMs), scans them for malicious threats via a 5-signal risk engine, and cryptographically deals them using **hybrid classical and post-quantum cryptography** (Ed25519 + NIST FIPS 204 ML-DSA-65).

---

## 🚀 Key Features

*   **🔍 Name Verification:** Prevents typosquatting by cross-referencing dependencies against the top 8,000 known legitimate PyPI packages.
*   **📊 5-Signal Risk Engine:** Evaluates package safety using release history, maintainer anomalies, and structural integrity.
*   **🔬 Static Source Scan:** Dissects package source code (`.tar.gz` / `.whl`) to find malicious heuristic patterns (e.g., unauthorized data exfiltration using `os.environ` + `requests.post`).
*   **✍️ Hybrid Quantum-Safe Signing:** Cryptographically seals the standard CycloneDX SBOM JSON using a hybrid approach—classical **Ed25519** combined with the post-quantum **ML-DSA-65** algorithm.
*   **✅ Verification Engine:** Mathematically proves the integrity of your SBOM. If a single byte is altered in transit, the quantum signature breaks, throwing a critical alert.

---

## 🛠️ Technology Stack

**Frontend:**
*   React 19 + Vite
*   Tailwind CSS 4.0 + Framer Motion (Glassmorphism UI)
*   Wouter (Client-side routing)
*   Lucide React (Icons)

**Backend:**
*   Python 3.12
*   FastAPI + Uvicorn
*   `liboqs-python` (Open Quantum Safe library for ML-DSA-65)
*   Cryptography (Ed25519 hashing and signing)

---

## ⚙️ Prerequisites

Before you begin, ensure you have the following installed on your machine:
*   [Node.js](https://nodejs.org/) (v24.13.0 or higher)
*   [Python](https://www.python.org/) (v3.12.x)
*   [pnpm](https://pnpm.io/) (v10.26.1) -> Install via: `npm install -g pnpm@10.26.1`

---

## 🏃‍♂️ How to Run the Project Locally

You will need to run the Backend and the Frontend in two separate terminals.

### 1. Start the Backend (Quantum Engine)
Open your first terminal and run:
```bash
cd backend
pip install -r requirements.txt  # (or install manually: fastapi uvicorn[standard] liboqs-python cryptography)
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
*Note: Make sure your Python environment has `liboqs-python` installed properly for the ML-DSA-65 signatures to work.*

### 2. Start the Frontend (Web App)
Open a **second** terminal, ensure you are in the project root directory, and run:
```powershell
# Install dependencies (First time only)
pnpm install

# Start the Vite development server
$env:PORT="5173"; $env:BASE_PATH="/"; pnpm --filter @workspace/latticeguard-sbom dev
```

### 3. Open the App
Navigate to [http://localhost:5173](http://localhost:5173) in your web browser.

---

## 🔒 The Quantum Threat (Why ML-DSA-65?)
Classical cryptographic signatures (RSA, ECDSA) rely on mathematical problems like integer factorization, which can be easily broken in polynomial time by Shor's Algorithm running on a Cryptographically Relevant Quantum Computer (CRQC).

LatticeGuard uses **Module-Learning With Errors (M-LWE)** over high-dimensional lattices. Because we introduce random algebraic "noise" into the matrix, the resulting Shortest Vector Problem (SVP) remains exponentially difficult. By layering ML-DSA-65 over traditional signatures, LatticeGuard protects your supply chain from both present-day classical attacks and future "Harvest Now, Decrypt Later" quantum adversaries.

---

## 🤝 Team
Built by **Team INFIFNITE** for the QC² Hackathon 2025.
