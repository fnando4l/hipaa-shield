# HIPAA Shield

**Scan documents for PHI violations before they become compliance incidents.**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-hipaa--shield.netlify.app-blue?style=flat-square)](https://hipaa-shield.netlify.app)
[![MIT License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react)](https://react.dev)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3-38BDF8?style=flat-square&logo=tailwind-css)](https://tailwindcss.com)

---

## Live Demo

**[https://hipaa-shield.netlify.app](https://hipaa-shield.netlify.app)**

Paste text or upload a file to instantly detect and redact Protected Health Information across 9 PHI pattern types. No data ever leaves your browser.

---

## Features

- **Text & File Input** — Paste text directly or upload `.txt` / `.csv` files with drag-and-drop support
- **9 PHI Pattern Types** across three severity levels:
  - 🔴 **Critical** — Social Security Numbers, Medical Record Numbers (MRN), Health Plan / Insurance IDs
  - 🟠 **High** — Patient full names, Dates of birth
  - 🟡 **Medium** — Phone numbers, Email addresses, IP addresses, Account numbers
- **Annotated Document View** — Violations highlighted inline with color-coded severity badges
- **Risk Score Gauge** — 0–100 composite score weighted by severity and violation count
- **One-Click Redaction** — Replace all detected PHI with `[REDACTED]` placeholders
- **JSON Report Export** — Download a structured violation report for audit trails
- **Clipboard Copy** — Copy redacted output ready for safe sharing
- **Sample Data** — Built-in demo document to explore the scanner immediately

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | React 19 |
| Build Tool | Vite 8 |
| Styling | Tailwind CSS 3 |
| PHI Detection | Custom regex engine (client-side) |
| Deployment | Netlify |

> **Privacy by design** — all processing runs entirely in the browser. No document content is transmitted to any server.

---

## Getting Started

### Prerequisites

- Node.js 18+
- npm 9+

### Installation

```bash
git clone https://github.com/yourusername/hipaa-shield.git
cd hipaa-shield
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Build for Production

```bash
npm run build
npm run preview
```

---

## Project Structure

```
hipaa-shield/
├── public/                 # Static assets
├── src/
│   ├── assets/             # Images and icons
│   ├── App.jsx             # Core scanner logic and UI
│   ├── App.css             # Component styles
│   ├── main.jsx            # React entry point
│   └── index.css           # Global styles / Tailwind base
├── index.html
├── vite.config.js
├── tailwind.config.js
└── package.json
```

All PHI detection patterns, risk scoring, and redaction logic live in `App.jsx`. The scanner runs a multi-pass regex sweep over the input text, categorizes each match by severity, computes a weighted risk score, and renders an annotated view with violation highlights.

---

## PHI Detection Patterns

| Category | Severity | Pattern |
|---|---|---|
| Social Security Number | Critical | `XXX-XX-XXXX` |
| Medical Record Number | Critical | `MRN` / `MR#` prefix |
| Health Plan Number | Critical | Insurance ID formats |
| Patient Name | High | Name entity patterns |
| Date of Birth | High | DOB / birthdate formats |
| Phone Number | Medium | US phone formats |
| Email Address | Medium | Standard email |
| IP Address | Medium | IPv4 |
| Account Number | Medium | Numeric account IDs |

---

## Disclaimer

HIPAA Shield is a development and review tool. It is not a substitute for legal compliance review, a certified HIPAA compliance solution, or legal counsel. Always consult a qualified compliance officer for regulatory requirements.

---

## License

MIT © 2025
