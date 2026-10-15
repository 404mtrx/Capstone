
import { useState, type FormEvent } from 'react'
import { ShieldCheck, Search, Plus, X } from 'lucide-react'
import './RulesPage.css'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

type Rule = {
  id: string
  name: string
  description: string
  severity: Severity
  enabled: boolean
}

const initialRules: Rule[] = [
  {
    id: 'RULE-001',
    name: 'Brute Force Login Detection',
    description: 'Detects 5 failed login attempts within 5 minutes.',
    severity: 'Critical',
    enabled: true,
  },
  {
    id: 'RULE-002',
    name: 'Suspicious Administrator Login',
    description: 'Flags unusual administrator login activity.',
    severity: 'High',
    enabled: true,
  },
  {
    id: 'RULE-003',
    name: 'Multiple Failed SSH Logins',
    description: 'Detects repeated SSH authentication failures.',
    severity: 'High',
    enabled: true,
  },
  {
    id: 'RULE-004',
    name: 'Unusual Network Connection',
    description: 'Flags potentially suspicious network activity.',
    severity: 'Medium',
    enabled: false,
  },
  {
    id: 'RULE-005',
    name: 'System Configuration Change',
    description: 'Detects changes to monitored system settings.',
    severity: 'Low',
    enabled: true,
  },
]

function RulesPage() {
  const [rules, setRules] = useState<Rule[]>(initialRules)
  const [search, setSearch] = useState('')
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)

  const [newName, setNewName] = useState('')
  const [newDescription, setNewDescription] = useState('')
  const [newSeverity, setNewSeverity] = useState<Severity>('Medium')

  const selectedRule = rules.find(rule => rule.id === selectedRuleId)
  const enabledCount = rules.filter(rule => rule.enabled).length

  const filteredRules = rules.filter(rule =>
    `${rule.name} ${rule.description} ${rule.severity}`
      .toLowerCase()
      .includes(search.trim().toLowerCase())
  )

  function toggleRule(id: string) {
    setRules(previous =>
      previous.map(rule =>
        rule.id === id
          ? { ...rule, enabled: !rule.enabled }
          : rule
      )
    )
  }

  function addRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (!newName.trim() || !newDescription.trim()) return

    const newRule: Rule = {
      id: `RULE-${Date.now()}`,
      name: newName.trim(),
      description: newDescription.trim(),
      severity: newSeverity,
      enabled: false,
    }

    setRules(previous => [...previous, newRule])
    setNewName('')
    setNewDescription('')
    setNewSeverity('Medium')
    setShowForm(false)
  }

  return (
    <section className="rules-page">
      <div className="rules-heading">
        <div>
          <h2>Detection Rules</h2>
          <p>Manage rules used to identify suspicious security activity.</p>
        </div>

        <button
          type="button"
          className="rules-add-button"
          onClick={() => setShowForm(true)}
        >
          <Plus size={18} />
          Add Rule
        </button>
      </div>

      <div className="rules-summary">
        <div className="rules-summary-card">
          <span>Total Rules</span>
          <strong>{rules.length}</strong>
        </div>

        <div className="rules-summary-card">
          <span>Enabled Rules</span>
          <strong className="rules-green">{enabledCount}</strong>
        </div>

        <div className="rules-summary-card">
          <span>Disabled Rules</span>
          <strong className="rules-orange">
            {rules.length - enabledCount}
          </strong>
        </div>
      </div>

      <div className="rules-toolbar">
        <div className="rules-search">
          <Search size={19} />
          <input
            type="search"
            aria-label="Search detection rules"
            placeholder="Search detection rules..."
            value={search}
            onChange={event => setSearch(event.target.value)}
          />
        </div>
        <span className="rules-result-count">
          {filteredRules.length} rules
        </span>
      </div>

      <div className="rules-table-wrapper">
        <table className="rules-table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Enabled</th>
            </tr>
          </thead>

          <tbody>
            {filteredRules.map(rule => (
              <tr key={rule.id}>
                <td>
                  <div className="rule-info">
                    <ShieldCheck size={21} />
                    <div>
                      <button
                        type="button"
                        className="rule-name-button"
                        onClick={() => setSelectedRuleId(rule.id)}
                      >
                        {rule.name}
                      </button>
                      <p>{rule.description}</p>
                    </div>
                  </div>
                </td>

                <td>
                  <span
                    className={`rule-severity ${rule.severity.toLowerCase()}`}
                  >
                    {rule.severity}
                  </span>
                </td>

                <td>
                  <span
                    className={
                      rule.enabled ? 'rules-green' : 'rules-muted'
                    }
                  >
                    {rule.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>

                <td>
                  <label className="rule-switch">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={() => toggleRule(rule.id)}
                      aria-label={`Enable ${rule.name}`}
                    />
                    <span className="rule-slider" />
                  </label>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredRules.length === 0 && (
          <p className="rules-empty">No matching rules found.</p>
        )}
      </div>

      <p className="rules-note">
        Demo Mode: Rule changes are temporary and do not affect
        backend detection behavior.
      </p>

      {selectedRule && (
        <div
          className="rules-modal-backdrop"
          onClick={() => setSelectedRuleId(null)}
        >
          <div
            className="rules-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="rule-details-title"
            onClick={event => event.stopPropagation()}
          >
            <div className="rules-modal-header">
              <div>
                <span className="rules-modal-eyebrow">SECURITY DETECTION</span>
                <h3 id="rule-details-title">Rule Details</h3>
              </div>
              <button
                type="button"
                aria-label="Close rule details"
                onClick={() => setSelectedRuleId(null)}
              >
                <X size={20} />
              </button>
            </div>

            <div className="rule-details">
              <div className="rule-detail-item">
                <span>Rule ID</span>
                <strong>{selectedRule.id}</strong>
              </div>
              <div className="rule-detail-item">
                <span>Rule Name</span>
                <strong>{selectedRule.name}</strong>
              </div>
              <div className="rule-detail-item">
                <span>Description</span>
                <p>{selectedRule.description}</p>
              </div>
              <div className="rule-detail-item">
                <span>Severity</span>
                <div>
                  <span
                    className={`rule-severity ${selectedRule.severity.toLowerCase()}`}
                  >
                    {selectedRule.severity}
                  </span>
                </div>
              </div>
              <div className="rule-detail-item">
                <span>Status</span>
                <strong
                  className={
                    selectedRule.enabled ? 'rules-green' : 'rules-muted'
                  }
                >
                  {selectedRule.enabled ? 'Enabled' : 'Disabled'}
                </strong>
              </div>
            </div>

            <button
              type="button"
              className="rules-save-button"
              onClick={() => setSelectedRuleId(null)}
            >
              Close Details
            </button>
          </div>
        </div>
      )}

      {showForm && (
        <div
          className="rules-modal-backdrop"
          onClick={() => setShowForm(false)}
        >
          <div
            className="rules-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="add-rule-title"
            onClick={event => event.stopPropagation()}
          >
            <div className="rules-modal-header">
              <div>
                <span className="rules-modal-eyebrow">DEMO CONFIGURATION</span>
                <h3 id="add-rule-title">Add Detection Rule</h3>
              </div>
              <button
                type="button"
                aria-label="Close add rule form"
                onClick={() => setShowForm(false)}
              >
                <X size={20} />
              </button>
            </div>

            <form className="rules-form" onSubmit={addRule}>
              <label htmlFor="rule-name">Rule Name</label>
              <input
                id="rule-name"
                value={newName}
                onChange={event => setNewName(event.target.value)}
                placeholder="Example: Suspicious Login"
                required
              />

              <label htmlFor="rule-description">Description</label>
              <textarea
                id="rule-description"
                value={newDescription}
                onChange={event => setNewDescription(event.target.value)}
                placeholder="Describe what this rule should detect"
                rows={3}
                required
              />

              <label htmlFor="rule-severity">Severity</label>
              <select
                id="rule-severity"
                value={newSeverity}
                onChange={event =>
                  setNewSeverity(event.target.value as Severity)
                }
              >
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>

              <button type="submit" className="rules-save-button">
                Save Demo Rule
              </button>
            </form>
          </div>
        </div>
      )}
    </section>
  )
}

export default RulesPage
