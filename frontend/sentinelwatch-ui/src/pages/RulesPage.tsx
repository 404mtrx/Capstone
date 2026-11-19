import { useState } from 'react'
import { Search, ShieldCheck } from 'lucide-react'
import './RulesPage.css'

// Snapshot verified against detection/rules.py and detection/engine.py.
// Update this catalog when engine code changes; it is not runtime configuration.
const catalog = [
  {
    "id": "RULE-001",
    "name": "Failed Login Detected",
    "severity": "Medium",
    "description": "Event type is failed_login."
  },
  {
    "id": "RULE-002",
    "name": "Multiple Failed Logins",
    "severity": "High",
    "description": "At least 3 failed logins from the same source IP within 5 minutes."
  },
  {
    "id": "RULE-003",
    "name": "Successful Login After Multiple Failures",
    "severity": "Critical",
    "description": "Successful authentication from the same IP after at least 3 failures within 10 minutes."
  },
  {
    "id": "RULE-004",
    "name": "Password Spraying Detected",
    "severity": "High",
    "description": "Failed logins against at least 3 distinct usernames from one IP within 5 minutes."
  },
  {
    "id": "RULE-005",
    "name": "Port Scan Detected",
    "severity": "High",
    "description": "At least 5 distinct destination ports for one source and destination IP pair within 5 minutes."
  },
  {
    "id": "RULE-006",
    "name": "Repeated Blocked Connections",
    "severity": "High",
    "description": "At least 5 blocked events from one source IP within 5 minutes."
  },
  {
    "id": "RULE-007",
    "name": "High Severity Event",
    "severity": "High / Critical",
    "description": "An event whose severity is high or critical; the alert preserves that severity."
  },
  {
    "id": "RULE-008",
    "name": "Account Lockout Detected",
    "severity": "High",
    "description": "Event type is account_lockout."
  },
  {
    "id": "RULE-009",
    "name": "Privilege Change Detected",
    "severity": "High",
    "description": "Event type is privilege_change."
  },
  {
    "id": "RULE-010",
    "name": "Suspicious Remote Login Detected",
    "severity": "High / Critical",
    "description": "Event type remote_login, action success, and severity high or critical."
  }
]

export default function RulesPage() {
  const [search, setSearch] = useState('')
  const filtered = catalog.filter(rule => `${rule.name} ${rule.description} ${rule.severity}`.toLowerCase().includes(search.trim().toLowerCase()))
  return <section className="rules-page">
    <div className="rules-heading"><div><h2>Implemented Detection Rules</h2><p>Read-only catalog verified against the supplied detection engine source.</p></div><ShieldCheck size={28} /></div>
    <div className="rules-summary"><div className="rules-summary-card"><span>Implemented rules</span><strong>{catalog.length}</strong></div><div className="rules-summary-card"><span>Configuration</span><strong>Code</strong></div></div>
    <p className="rules-note">These 10 rules are registered in the supplied engine. This catalog does not report whether the engine is running. Rule creation and configuration require backend development; no browser-only toggles are provided.</p>
    <div className="rules-toolbar"><div className="rules-search"><Search size={19}/><input type="search" aria-label="Search implemented rules" placeholder="Search rules…" value={search} onChange={event => setSearch(event.target.value)}/></div><span>{filtered.length} rules</span></div>
    <div className="rules-table-wrapper"><table className="rules-table"><thead><tr><th>Rule</th><th>Alert severity</th></tr></thead><tbody>{filtered.map(rule => <tr key={rule.id}><td><div className="rule-info"><ShieldCheck size={21}/><div><strong>{rule.name}</strong><p>{rule.description}</p><small>{rule.id}</small></div></div></td><td>{rule.severity}</td></tr>)}</tbody></table>{filtered.length === 0 && <p className="rules-empty">No matching rules.</p>}</div>
  </section>
}
