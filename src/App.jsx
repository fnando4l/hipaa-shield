import { useState, useCallback, useRef } from 'react'

// ─── HIPAA Scanning Engine ───────────────────────────────────────────────────

const PATTERNS = [
  {
    id: 'ssn',
    label: 'Social Security Number',
    category: 'SSN',
    severity: 'critical',
    regex: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g,
    description: 'Social Security Numbers are critical PHI identifiers.',
  },
  {
    id: 'mrn',
    label: 'Medical Record Number',
    category: 'MRN',
    severity: 'critical',
    regex: /\b(?:MRN|mrn|M\.R\.N\.?|Medical\s+Record(?:\s+Number)?)[:\s#]*([A-Z0-9]{5,12})\b/gi,
    description: 'Medical Record Numbers directly identify patient records.',
  },
  {
    id: 'health_plan',
    label: 'Health Plan Number',
    category: 'Health Plan',
    severity: 'critical',
    regex: /\b(?:Health\s+Plan|Insurance\s+ID|Member\s+ID|Policy\s+(?:No|Number|#))[:\s#]*([A-Z0-9]{6,15})\b/gi,
    description: 'Health plan beneficiary numbers.',
  },
  {
    id: 'dob',
    label: 'Date of Birth',
    category: 'Date of Birth',
    severity: 'high',
    regex: /\b(?:DOB|D\.O\.B\.?|Date\s+of\s+Birth|Born)[:\s]*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\w+ \d{1,2},? \d{4})\b/gi,
    description: 'Dates of birth can uniquely identify individuals.',
  },
  {
    id: 'name',
    label: 'Patient Name',
    category: 'Patient Name',
    severity: 'high',
    regex: /\b(?:Patient|Pt\.?|Name|Full\s+Name)[:\s]+([A-Z][a-z]+ (?:[A-Z]\.? )?[A-Z][a-z]+)\b/g,
    description: 'Patient names are direct PHI identifiers.',
  },
  {
    id: 'phone',
    label: 'Phone Number',
    category: 'Phone',
    severity: 'medium',
    regex: /\b(?:\+1[-\s]?)?\(?\d{3}\)?[-\s.]\d{3}[-\s.]\d{4}\b/g,
    description: 'Phone numbers can be used to contact or identify individuals.',
  },
  {
    id: 'email',
    label: 'Email Address',
    category: 'Email',
    severity: 'medium',
    regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    description: 'Email addresses are personal contact identifiers.',
  },
  {
    id: 'ip',
    label: 'IP Address',
    category: 'IP Address',
    severity: 'medium',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    description: 'IP addresses can geographically locate individuals.',
  },
  {
    id: 'account',
    label: 'Account / ID Number',
    category: 'Account Number',
    severity: 'medium',
    regex: /\b(?:Account|Acct\.?|Account\s+(?:No|Number|#)|ID\s*#?)[:\s]*(\d{5,})\b/gi,
    description: '5+ digit account or ID numbers may identify individuals.',
  },
]

const SEVERITY_CONFIG = {
  critical: {
    color: 'text-red-400',
    bg: 'bg-red-500/10',
    border: 'border-red-500/40',
    badge: 'bg-red-500/20 text-red-300 border border-red-500/40',
    dot: 'bg-red-500',
    label: 'CRITICAL',
    highlightClass: 'highlight-critical',
    score: 25,
  },
  high: {
    color: 'text-orange-400',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/40',
    badge: 'bg-orange-500/20 text-orange-300 border border-orange-500/40',
    dot: 'bg-orange-500',
    label: 'HIGH',
    highlightClass: 'highlight-high',
    score: 15,
  },
  medium: {
    color: 'text-yellow-400',
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/40',
    badge: 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40',
    dot: 'bg-yellow-500',
    label: 'MEDIUM',
    highlightClass: 'highlight-medium',
    score: 8,
  },
}

function scanText(text) {
  const findings = []

  for (const pattern of PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags)
    let match
    while ((match = regex.exec(text)) !== null) {
      const value = match[1] ?? match[0]
      const start = match.index
      const end = match.index + match[0].length
      findings.push({
        id: `${pattern.id}-${start}`,
        patternId: pattern.id,
        label: pattern.label,
        category: pattern.category,
        severity: pattern.severity,
        value,
        matchedText: match[0],
        start,
        end,
        description: pattern.description,
      })
    }
  }

  // Sort by position
  findings.sort((a, b) => a.start - b.start)

  // Remove overlapping findings (keep higher severity)
  const deduped = []
  let lastEnd = -1
  for (const f of findings) {
    if (f.start >= lastEnd) {
      deduped.push(f)
      lastEnd = f.end
    }
  }

  return deduped
}

function computeRiskScore(findings) {
  if (findings.length === 0) return 0
  const raw = findings.reduce((acc, f) => acc + SEVERITY_CONFIG[f.severity].score, 0)
  return Math.min(100, raw)
}

function buildHighlightedHTML(text, findings) {
  if (findings.length === 0) return escapeHtml(text)
  let result = ''
  let cursor = 0
  for (const f of findings) {
    if (f.start > cursor) {
      result += escapeHtml(text.slice(cursor, f.start))
    }
    const cfg = SEVERITY_CONFIG[f.severity]
    result += `<mark class="${cfg.highlightClass}" title="${f.label}: ${f.value}">${escapeHtml(text.slice(f.start, f.end))}</mark>`
    cursor = f.end
  }
  if (cursor < text.length) result += escapeHtml(text.slice(cursor))
  return result
}

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

function redactText(text, findings) {
  if (findings.length === 0) return text
  let result = ''
  let cursor = 0
  for (const f of findings) {
    if (f.start > cursor) result += text.slice(cursor, f.start)
    result += '[REDACTED]'
    cursor = f.end
  }
  if (cursor < text.length) result += text.slice(cursor)
  return result
}

// ─── Sample Data ─────────────────────────────────────────────────────────────

const SAMPLE_TEXT = `Patient Intake Form — Confidential

Patient Name: John Michael Smith
DOB: 03/15/1978
SSN: 482-91-7723
MRN: MRN #A4892031
Policy Number: HBP-7741293

Contact Information:
Phone: (555) 243-8812
Email: john.smith@email.com
IP Address: 192.168.1.105

Account #: 00839274

Clinical Notes (Dr. Rivera):
Patient Name: Sarah Elizabeth Johnson (spouse, emergency contact)
DOB: 07/22/1980
SSN: 301-55-8821

Patient presents with chest pain since 02/10/2024. Prior cardiac history noted.
Referred to cardiology. Follow-up MRN: MRN #C1192847.

Health Plan Member ID: HP-220847312
Insurance ID: INS009273846`

// ─── Components ──────────────────────────────────────────────────────────────

function ShieldIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  )
}

function AlertIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  )
}

function CheckIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  )
}

function UploadIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 16 12 12 8 16" />
      <line x1="12" y1="12" x2="12" y2="21" />
      <path d="M20.39 18.39A5 5 0 0018 9h-1.26A8 8 0 103 16.3" />
    </svg>
  )
}

function RiskGauge({ score }) {
  const color = score >= 70 ? '#ef4444' : score >= 40 ? '#f97316' : score >= 15 ? '#eab308' : '#22c55e'
  const label = score >= 70 ? 'CRITICAL RISK' : score >= 40 ? 'HIGH RISK' : score >= 15 ? 'MODERATE RISK' : 'LOW RISK'
  const circumference = 2 * Math.PI * 40
  const strokeDashoffset = circumference - (score / 100) * circumference

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-28 h-28">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 96 96">
          <circle cx="48" cy="48" r="40" fill="none" stroke="#1e293b" strokeWidth="10" />
          <circle
            cx="48" cy="48" r="40"
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.8s ease, stroke 0.4s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold" style={{ color }}>{score}</span>
          <span className="text-xs text-slate-400">/ 100</span>
        </div>
      </div>
      <span className="text-xs font-semibold tracking-wider" style={{ color }}>{label}</span>
    </div>
  )
}

function StatCard({ label, value, color, bg }) {
  return (
    <div className={`rounded-xl border p-4 flex flex-col gap-1 ${bg}`} style={{ borderColor: color + '40' }}>
      <span className="text-2xl font-bold" style={{ color }}>{value}</span>
      <span className="text-xs text-slate-400 uppercase tracking-wide">{label}</span>
    </div>
  )
}

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [inputText, setInputText] = useState('')
  const [findings, setFindings] = useState(null)
  const [scannedText, setScannedText] = useState('')
  const [activeTab, setActiveTab] = useState('input')
  const [isDragging, setIsDragging] = useState(false)
  const [fileName, setFileName] = useState('')
  const [copied, setCopied] = useState(false)
  const fileInputRef = useRef(null)

  const handleScan = useCallback(() => {
    if (!inputText.trim()) return
    const results = scanText(inputText)
    setFindings(results)
    setScannedText(inputText)
    setActiveTab('results')
  }, [inputText])

  const handleRedact = useCallback(() => {
    if (!findings || !scannedText) return
    const redacted = redactText(scannedText, findings)
    setInputText(redacted)
    setFindings(null)
    setScannedText('')
    setActiveTab('input')
  }, [findings, scannedText])

  const handleLoadSample = () => {
    setInputText(SAMPLE_TEXT)
    setFindings(null)
    setFileName('')
    setActiveTab('input')
  }

  const handleFileUpload = (file) => {
    if (!file) return
    if (!file.name.match(/\.(txt|csv)$/i)) {
      alert('Please upload a .txt or .csv file.')
      return
    }
    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = (e) => {
      setInputText(e.target.result)
      setFindings(null)
      setActiveTab('input')
    }
    reader.readAsText(file)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setIsDragging(false)
    const file = e.dataTransfer.files[0]
    handleFileUpload(file)
  }

  const handleExportJSON = () => {
    if (!findings) return
    const report = {
      generated: new Date().toISOString(),
      tool: 'HIPAA Shield',
      totalViolations: findings.length,
      riskScore: computeRiskScore(findings),
      summary: PATTERNS.reduce((acc, p) => {
        const count = findings.filter(f => f.patternId === p.id).length
        if (count > 0) acc[p.category] = count
        return acc
      }, {}),
      findings: findings.map(({ id, label, category, severity, value, matchedText, start, end, description }) => ({
        id, label, category, severity, value, matchedText, position: { start, end }, description,
      })),
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `hipaa-shield-report-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleCopyRedacted = () => {
    if (!findings || !scannedText) return
    const redacted = redactText(scannedText, findings)
    navigator.clipboard.writeText(redacted).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const score = findings ? computeRiskScore(findings) : 0
  const criticalCount = findings ? findings.filter(f => f.severity === 'critical').length : 0
  const highCount = findings ? findings.filter(f => f.severity === 'high').length : 0
  const mediumCount = findings ? findings.filter(f => f.severity === 'medium').length : 0

  const categoryCounts = findings
    ? PATTERNS.reduce((acc, p) => {
        const count = findings.filter(f => f.patternId === p.id).length
        if (count > 0) acc[p.category] = { count, severity: p.severity }
        return acc
      }, {})
    : {}

  const highlightedHTML = findings && scannedText ? buildHighlightedHTML(scannedText, findings) : ''

  return (
    <div className="min-h-screen bg-[#030712] text-slate-100 flex flex-col">
      {/* Header */}
      <header className="border-b border-slate-800/60 bg-[#050b18]/80 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
              <ShieldIcon className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-white">HIPAA Shield</h1>
              <p className="text-xs text-slate-500 leading-none">PHI Violation Scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="hidden sm:inline-flex items-center gap-1.5 text-xs text-slate-500 bg-slate-800/60 rounded-full px-3 py-1 border border-slate-700/50">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></span>
              Client-Side Processing — No Data Leaves Your Browser
            </span>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 py-6 flex flex-col gap-6">

        {/* Tabs */}
        <div className="flex gap-1 bg-slate-900/60 rounded-xl p-1 border border-slate-800/60 w-fit">
          {[
            { id: 'input', label: 'Input' },
            { id: 'results', label: findings ? `Results (${findings.length})` : 'Results' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab.id
                  ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── INPUT TAB ── */}
        {activeTab === 'input' && (
          <div className="grid lg:grid-cols-3 gap-6">
            {/* Left: text area */}
            <div className="lg:col-span-2 flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Document / Text Input</h2>
                <button
                  onClick={handleLoadSample}
                  className="text-xs text-blue-400 hover:text-blue-300 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 px-3 py-1.5 rounded-lg transition-all"
                >
                  Load Sample Data
                </button>
              </div>

              {/* Drop zone */}
              <div
                onDragOver={(e) => { e.preventDefault(); setIsDragging(true) }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={handleDrop}
                className={`relative rounded-xl border-2 border-dashed transition-all ${
                  isDragging ? 'border-blue-500 bg-blue-500/5' : 'border-slate-700/60 hover:border-slate-600'
                }`}
              >
                <textarea
                  value={inputText}
                  onChange={e => setInputText(e.target.value)}
                  placeholder="Paste document content, clinical notes, emails, or any text containing potential PHI here…"
                  className="w-full h-72 bg-transparent rounded-xl px-4 py-3 text-sm text-slate-200 placeholder-slate-600 resize-none focus:outline-none focus:ring-2 focus:ring-blue-500/40 font-mono"
                  spellCheck={false}
                />
                {isDragging && (
                  <div className="absolute inset-0 rounded-xl flex items-center justify-center bg-blue-500/10 pointer-events-none">
                    <div className="text-blue-400 text-sm font-medium">Drop file here</div>
                  </div>
                )}
              </div>

              <div className="flex items-center gap-3 flex-wrap">
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="flex items-center gap-2 text-sm text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2 rounded-lg transition-all"
                >
                  <UploadIcon className="w-4 h-4" />
                  Upload .txt / .csv
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".txt,.csv"
                  className="hidden"
                  onChange={e => handleFileUpload(e.target.files[0])}
                />
                {fileName && (
                  <span className="text-xs text-slate-500 bg-slate-800/60 px-3 py-1.5 rounded-lg border border-slate-700/50">
                    {fileName}
                  </span>
                )}
                {inputText && (
                  <span className="text-xs text-slate-600 ml-auto">
                    {inputText.length.toLocaleString()} characters
                  </span>
                )}
              </div>

              <button
                onClick={handleScan}
                disabled={!inputText.trim()}
                className="w-full py-3 rounded-xl font-semibold text-sm tracking-wide transition-all bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-900/30 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                <ShieldIcon className="w-5 h-5" />
                Scan for HIPAA Violations
              </button>
            </div>

            {/* Right: pattern reference */}
            <div className="flex flex-col gap-4">
              <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Detection Patterns</h2>
              <div className="flex flex-col gap-2">
                {PATTERNS.map(p => {
                  const cfg = SEVERITY_CONFIG[p.severity]
                  return (
                    <div key={p.id} className={`rounded-lg border p-3 ${cfg.bg} ${cfg.border}`}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-slate-200">{p.label}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${cfg.badge}`}>{cfg.label}</span>
                      </div>
                      <p className="text-xs text-slate-500">{p.description}</p>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}

        {/* ── RESULTS TAB ── */}
        {activeTab === 'results' && findings && (
          <div className="flex flex-col gap-6">
            {/* Stats row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-5 gap-4">
              <div className="col-span-2 sm:col-span-1 flex justify-center sm:justify-start">
                <RiskGauge score={score} />
              </div>
              <StatCard label="Total Violations" value={findings.length} color="#60a5fa" bg="bg-blue-500/5" />
              <StatCard label="Critical" value={criticalCount} color="#ef4444" bg="bg-red-500/5" />
              <StatCard label="High" value={highCount} color="#f97316" bg="bg-orange-500/5" />
              <StatCard label="Medium" value={mediumCount} color="#eab308" bg="bg-yellow-500/5" />
            </div>

            {/* Action buttons */}
            <div className="flex flex-wrap gap-3">
              <button
                onClick={handleExportJSON}
                className="flex items-center gap-2 text-sm bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 px-4 py-2 rounded-lg transition-all"
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Export JSON Report
              </button>
              <button
                onClick={handleCopyRedacted}
                className="flex items-center gap-2 text-sm bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 px-4 py-2 rounded-lg transition-all"
              >
                {copied
                  ? <><CheckIcon className="w-4 h-4 text-green-400" /><span className="text-green-400">Copied!</span></>
                  : <><svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>Copy Redacted Text</>
                }
              </button>
              <button
                onClick={handleRedact}
                className="flex items-center gap-2 text-sm bg-red-600/20 hover:bg-red-600/30 border border-red-500/40 text-red-300 px-4 py-2 rounded-lg transition-all"
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M17 3a2.828 2.828 0 114 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
                Redact All & Edit
              </button>
              <button
                onClick={() => setActiveTab('input')}
                className="flex items-center gap-2 text-sm bg-slate-800/60 hover:bg-slate-700 border border-slate-700/50 text-slate-400 px-4 py-2 rounded-lg transition-all ml-auto"
              >
                ← New Scan
              </button>
            </div>

            {/* No findings */}
            {findings.length === 0 && (
              <div className="rounded-xl border border-green-500/30 bg-green-500/5 p-8 flex flex-col items-center gap-3 text-center">
                <CheckIcon className="w-12 h-12 text-green-400" />
                <h3 className="text-lg font-semibold text-green-300">No HIPAA Violations Detected</h3>
                <p className="text-sm text-slate-400">The scanned text does not contain any identifiable PHI patterns.</p>
              </div>
            )}

            {/* Findings grid */}
            {findings.length > 0 && (
              <div className="grid lg:grid-cols-5 gap-6">
                {/* Highlighted text */}
                <div className="lg:col-span-3 flex flex-col gap-3">
                  <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Annotated Document</h2>
                  <div
                    className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 text-sm font-mono text-slate-300 leading-relaxed whitespace-pre-wrap overflow-auto max-h-[32rem]"
                    dangerouslySetInnerHTML={{ __html: highlightedHTML }}
                  />
                  <div className="flex gap-4 flex-wrap text-xs text-slate-500">
                    {['critical', 'high', 'medium'].map(s => (
                      <span key={s} className="flex items-center gap-1.5">
                        <span className={`w-3 h-0.5 inline-block rounded ${SEVERITY_CONFIG[s].dot}`}></span>
                        {SEVERITY_CONFIG[s].label}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Findings list */}
                <div className="lg:col-span-2 flex flex-col gap-3">
                  <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                    Findings ({findings.length})
                  </h2>
                  <div className="flex flex-col gap-2 overflow-auto max-h-[32rem] pr-1">
                    {/* Category breakdown */}
                    {Object.entries(categoryCounts).map(([cat, { count, severity }]) => {
                      const cfg = SEVERITY_CONFIG[severity]
                      return (
                        <div key={cat} className={`rounded-lg border p-3 ${cfg.bg} ${cfg.border}`}>
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium text-slate-200">{cat}</span>
                            <div className="flex items-center gap-2">
                              <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${cfg.badge}`}>{cfg.label}</span>
                              <span className={`text-sm font-bold ${cfg.color}`}>{count}</span>
                            </div>
                          </div>
                        </div>
                      )
                    })}

                    <div className="border-t border-slate-800 pt-3 mt-1">
                      <h3 className="text-xs text-slate-500 uppercase tracking-wide mb-2">Individual Matches</h3>
                      {findings.map(f => {
                        const cfg = SEVERITY_CONFIG[f.severity]
                        return (
                          <div key={f.id} className={`rounded-lg border p-2.5 mb-2 ${cfg.bg} ${cfg.border}`}>
                            <div className="flex items-start justify-between gap-2">
                              <div className="flex-1 min-w-0">
                                <span className="text-xs font-semibold text-slate-300">{f.label}</span>
                                <p className="text-xs font-mono text-slate-400 truncate mt-0.5">"{f.matchedText}"</p>
                              </div>
                              <span className={`text-xs px-1.5 py-0.5 rounded font-semibold shrink-0 ${cfg.badge}`}>{cfg.label}</span>
                            </div>
                            <p className="text-xs text-slate-600 mt-1">pos {f.start}–{f.end}</p>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Results tab but no scan yet */}
        {activeTab === 'results' && !findings && (
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-12 flex flex-col items-center gap-4 text-center">
            <AlertIcon className="w-12 h-12 text-slate-600" />
            <h3 className="text-lg font-semibold text-slate-400">No Scan Results</h3>
            <p className="text-sm text-slate-600">Run a scan from the Input tab to see results here.</p>
            <button onClick={() => setActiveTab('input')} className="text-sm text-blue-400 hover:text-blue-300 underline underline-offset-2">
              Go to Input
            </button>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/60 py-4 px-6 text-center text-xs text-slate-600">
        HIPAA Shield — All processing is client-side. No PHI is transmitted or stored. For compliance review only — not a substitute for legal counsel.
      </footer>
    </div>
  )
}
