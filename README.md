# HIPAA Shield

A client-side PHI (Protected Health Information) violation scanner built with React. Paste or upload documents and instantly detect HIPAA-sensitive data — no data ever leaves your browser.

## Features

- **Text input & file upload** — paste content directly or upload `.txt` / `.csv` files (drag-and-drop supported)
- **9 PHI detection patterns:**
  - 🔴 **Critical** — Social Security Numbers, Medical Record Numbers (MRN), Health Plan Numbers
  - 🟠 **High** — Patient Names, Dates of Birth
  - 🟡 **Medium** — Phone Numbers, Email Addresses, IP Addresses, Account Numbers
- **Annotated document view** — color-coded highlights show exactly where each violation appears
- **Risk score** — animated gauge (0–100) based on violation severity and count
- **Redact All** — replace every flagged item with `[REDACTED]` in one click
- **Export JSON report** — machine-readable report with positions, categories, and severity
- **Copy redacted text** — clipboard-ready sanitized output
- **Sample data** — built-in demo content to explore all features

## Tech Stack

- [React](https://react.dev) + [Vite](https://vite.dev)
- [Tailwind CSS v3](https://tailwindcss.com)
- 100% client-side — no backend, no data transmission

## Getting Started

```bash
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

## Build & Deploy

```bash
npm run build   # outputs to dist/
```

The `dist/` folder is a static site — deploy to Netlify, Vercel, GitHub Pages, or any static host.

**Live demo:** [https://hipaa-shield.netlify.app](https://hipaa-shield.netlify.app)

## Disclaimer

HIPAA Shield is a development and review tool. It is not a substitute for legal compliance review, a certified HIPAA compliance solution, or legal counsel. Always consult a qualified compliance officer for regulatory requirements.

## License

MIT
