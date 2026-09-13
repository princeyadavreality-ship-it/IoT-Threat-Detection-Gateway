# Contributing to IoT Threat Detection & Hardening Gateway

First off, thank you for considering contributing to the **IoT Threat Detection & Hardening Gateway**! Open-source contributions from security researchers, network engineers, and web developers help make this security tool stronger for everyone.

---

## 🛠️ Development Setup

### 1. Fork & Clone
Fork the repository on GitHub, then clone your fork locally:
```bash
git clone https://github.com/<your-username>/iot-threat-detection-gateway.git
cd iot-threat-detection-gateway
```

### 2. Frontend Development (React + TypeScript + Vite)
```bash
npm install
npm run dev
```
Test your changes and verify TypeScript compiles without errors:
```bash
npm run lint
npm run build
```

### 3. Backend Development (Python Gateway Engine)
```bash
cd iot_gateway
python -m venv venv
source venv/bin/activate  # Or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
python main.py
```

---

## 🌿 Branching Strategy & Git Workflow

1. Create a descriptive feature branch from `main`:
   ```bash
   git checkout -b feature/mitre-rule-expansion
   # or
   git checkout -b fix/packet-buffer-overflow
   ```

2. Make focused, atomic commits with clear messages:
   ```bash
   git commit -m "feat(detection): add SYN flood sliding-window threshold"
   ```

3. Ensure all tests and linters pass before pushing:
   ```bash
   npm run lint
   npm run build
   ```

4. Push your branch to GitHub and open a Pull Request.

---

## 📋 Pull Request Guidelines

When submitting a pull request:
- Provide a clear summary of what changes were made and why.
- Reference any relevant GitHub issues (e.g., `Fixes #12`).
- Include screenshots or terminal logs if introducing UI modifications or CLI features.
- Keep PRs concise and focused on a single topic.

---

## 🧑‍💻 Code Style & Standards

- **TypeScript / React**:
  - Follow standard ESLint / TypeScript strict mode conventions.
  - Use Tailwind CSS utility classes; avoid custom inline CSS.
  - Ensure theme accessibility with both dark and light modes.
- **Python**:
  - Adhere to PEP 8 style standards.
  - Maintain type hints (`typing.List`, `typing.Optional`, dataclasses).
  - Ensure zero external dependencies outside `requirements.txt`.

---

## 💬 Questions or Suggestions?

Feel free to open an **Issue** or **Discussion** on GitHub to discuss new heuristics, hardware compatibility, or UI enhancements!
