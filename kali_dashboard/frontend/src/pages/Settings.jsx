import React, { useState } from 'react';
import { Shield, Lock, FileText, Bell, Database, Save, AlertTriangle, CheckCircle } from 'lucide-react';

function Settings() {
  const [activeTab, setActiveTab] = useState('authorization');
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="settings-page">
      <div className="page-header">
        <h1>Dashboard Settings</h1>
        <p className="subtitle">Configure safety controls, authorization, and preferences</p>
      </div>

      <div className="settings-layout">
        <aside className="settings-nav">
          <button 
            className={`settings-tab ${activeTab === 'authorization' ? 'active' : ''}`}
            onClick={() => setActiveTab('authorization')}
          >
            <Lock size={20} />
            Authorization
          </button>
          <button 
            className={`settings-tab ${activeTab === 'safety' ? 'active' : ''}`}
            onClick={() => setActiveTab('safety')}
          >
            <Shield size={20} />
            Safety Controls
          </button>
          <button 
            className={`settings-tab ${activeTab === 'reports' ? 'active' : ''}`}
            onClick={() => setActiveTab('reports')}
          >
            <FileText size={20} />
            Reports
          </button>
          <button 
            className={`settings-tab ${activeTab === 'notifications' ? 'active' : ''}`}
            onClick={() => setActiveTab('notifications')}
          >
            <Bell size={20} />
            Notifications
          </button>
          <button 
            className={`settings-tab ${activeTab === 'database' ? 'active' : ''}`}
            onClick={() => setActiveTab('database')}
          >
            <Database size={20} />
            Metasploit DB
          </button>
        </aside>

        <main className="settings-content">
          {activeTab === 'authorization' && <AuthorizationSettings onSave={handleSave} />}
          {activeTab === 'safety' && <SafetySettings onSave={handleSave} />}
          {activeTab === 'reports' && <ReportSettings onSave={handleSave} />}
          {activeTab === 'notifications' && <NotificationSettings onSave={handleSave} />}
          {activeTab === 'database' && <DatabaseSettings onSave={handleSave} />}

          {saved && (
            <div className="save-notification">
              <CheckCircle size={20} />
              Settings saved successfully!
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function AuthorizationSettings({ onSave }) {
  const [level, setLevel] = useState('BASIC');

  const levels = [
    {
      value: 'NONE',
      label: 'No Authorization',
      color: '#6b7280',
      description: 'No tools can be executed. Safe for viewing only.',
      tools: 0,
    },
    {
      value: 'BASIC',
      label: 'Basic Operations',
      color: '#3b82f6',
      description: 'Reconnaissance and scanning tools only. Non-intrusive.',
      tools: 18,
    },
    {
      value: 'ADVANCED',
      label: 'Advanced Operations',
      color: '#f59e0b',
      description: 'Exploitation and password attacks. May cause disruptions.',
      tools: 28,
    },
    {
      value: 'CRITICAL',
      label: 'Critical Operations',
      color: '#ef4444',
      description: 'Full access including Metasploit and post-exploitation.',
      tools: 52,
    },
  ];

  return (
    <div className="settings-section">
      <h2>Authorization Level</h2>
      <p className="section-desc">
        Control which tools can be executed based on authorization level
      </p>

      <div className="auth-levels-grid">
        {levels.map((lvl) => (
          <div
            key={lvl.value}
            className={`auth-level-card ${level === lvl.value ? 'selected' : ''}`}
            onClick={() => setLevel(lvl.value)}
            style={{ '--accent': lvl.color }}
          >
            <div className="auth-level-header">
              <h3>{lvl.label}</h3>
              <span className="tools-count">{lvl.tools} tools</span>
            </div>
            <p>{lvl.description}</p>
            <div className="auth-level-bar">
              <div 
                className="auth-level-fill"
                style={{ 
                  width: `${(lvl.tools / 52) * 100}%`,
                  background: lvl.color
                }}
              ></div>
            </div>
          </div>
        ))}
      </div>

      <div className="settings-actions">
        <button className="btn primary" onClick={onSave}>
          <Save size={18} />
          Save Authorization Level
        </button>
      </div>
    </div>
  );
}

function SafetySettings({ onSave }) {
  const [whitelist, setWhitelist] = useState('192.0.2.0/24\n10.0.0.0/8');
  const [blacklist, setBlacklist] = useState('8.8.8.8\n1.1.1.1');
  const [safeMode, setSafeMode] = useState(true);
  const [dryRun, setDryRun] = useState(false);
  const [auditLog, setAuditLog] = useState(true);

  return (
    <div className="settings-section">
      <h2>Safety Controls</h2>
      <p className="section-desc">
        Configure target restrictions and safety measures
      </p>

      <div className="safety-grid">
        <div className="safety-card">
          <h3>IP Whitelist</h3>
          <p className="card-desc">Only these targets can be scanned (one per line)</p>
          <textarea
            value={whitelist}
            onChange={(e) => setWhitelist(e.target.value)}
            placeholder="192.0.2.0/24&#10;198.51.100.100"
            rows={6}
          />
          <div className="whitelist-info">
            <AlertTriangle size={16} />
            <span>If set, ONLY whitelisted IPs can be targeted</span>
          </div>
        </div>

        <div className="safety-card">
          <h3>IP Blacklist</h3>
          <p className="card-desc">These targets are always blocked (one per line)</p>
          <textarea
            value={blacklist}
            onChange={(e) => setBlacklist(e.target.value)}
            placeholder="8.8.8.8&#10;1.1.1.1"
            rows={6}
          />
          <div className="blacklist-info">
            <Shield size={16} />
            <span>Blacklisted IPs cannot be scanned under any circumstances</span>
          </div>
        </div>

        <div className="safety-card full-width">
          <h3>Safety Modes</h3>
          <div className="toggle-group">
            <div className="toggle-item">
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={safeMode}
                  onChange={(e) => setSafeMode(e.target.checked)}
                />
                <span className="toggle-slider"></span>
                <div className="toggle-info">
                  <span className="toggle-name">Safe Mode</span>
                  <span className="toggle-desc">Read-only operations, no system changes</span>
                </div>
              </label>
            </div>

            <div className="toggle-item">
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={dryRun}
                  onChange={(e) => setDryRun(e.target.checked)}
                />
                <span className="toggle-slider"></span>
                <div className="toggle-info">
                  <span className="toggle-name">Dry-Run Mode</span>
                  <span className="toggle-desc">Log commands without executing them</span>
                </div>
              </label>
            </div>

            <div className="toggle-item">
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={auditLog}
                  onChange={(e) => setAuditLog(e.target.checked)}
                />
                <span className="toggle-slider"></span>
                <div className="toggle-info">
                  <span className="toggle-name">Audit Logging</span>
                  <span className="toggle-desc">Log all executions to JSONL file</span>
                </div>
              </label>
            </div>
          </div>
        </div>
      </div>

      <div className="settings-actions">
        <button className="btn primary" onClick={onSave}>
          <Save size={18} />
          Save Safety Configuration
        </button>
      </div>
    </div>
  );
}

function ReportSettings({ onSave }) {
  const [format, setFormat] = useState('markdown');
  const [includeScreenshots, setIncludeScreenshots] = useState(true);
  const [autoGenerate, setAutoGenerate] = useState(false);
  const [emailReports, setEmailReports] = useState(false);
  const [emailRecipients, setEmailRecipients] = useState('');

  return (
    <div className="settings-section">
      <h2>Report Configuration</h2>
      <p className="section-desc">
        Customize report generation and delivery
      </p>

      <div className="report-settings-grid">
        <div className="setting-group">
          <label>Default Format</label>
          <select value={format} onChange={(e) => setFormat(e.target.value)}>
            <option value="markdown">Markdown (.md)</option>
            <option value="pdf">PDF (.pdf)</option>
            <option value="html">HTML (.html)</option>
            <option value="json">JSON (.json)</option>
          </select>
        </div>

        <div className="setting-group">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={includeScreenshots}
              onChange={(e) => setIncludeScreenshots(e.target.checked)}
            />
            Include Screenshots
          </label>
        </div>

        <div className="setting-group">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={autoGenerate}
              onChange={(e) => setAutoGenerate(e.target.checked)}
            />
            Auto-generate reports on completion
          </label>
        </div>

        <div className="setting-group">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={emailReports}
              onChange={(e) => setEmailReports(e.target.checked)}
            />
            Email reports automatically
          </label>
        </div>

        {emailReports && (
          <div className="setting-group full-width">
            <label>Email Recipients</label>
            <input
              type="email"
              value={emailRecipients}
              onChange={(e) => setEmailRecipients(e.target.value)}
              placeholder="security@example.com, manager@example.com"
            />
          </div>
        )}
      </div>

      <div className="settings-actions">
        <button className="btn primary" onClick={onSave}>
          <Save size={18} />
          Save Report Settings
        </button>
      </div>
    </div>
  );
}

function NotificationSettings({ onSave }) {
  const [engagementComplete, setEngagementComplete] = useState(true);
  const [criticalFindings, setCriticalFindings] = useState(true);
  const [toolFailures, setToolFailures] = useState(false);

  return (
    <div className="settings-section">
      <h2>Notifications</h2>
      <p className="section-desc">
        Configure when and how you receive notifications
      </p>

      <div className="notification-toggles">
        <div className="notification-item">
          <div className="notification-info">
            <h3>Engagement Complete</h3>
            <p>Notify when a playbook execution finishes</p>
          </div>
          <label className="toggle-switch">
            <input
              type="checkbox"
              checked={engagementComplete}
              onChange={(e) => setEngagementComplete(e.target.checked)}
            />
            <span className="toggle-slider"></span>
          </label>
        </div>

        <div className="notification-item">
          <div className="notification-info">
            <h3>Critical Findings</h3>
            <p>Immediate alert for critical severity findings</p>
          </div>
          <label className="toggle-switch">
            <input
              type="checkbox"
              checked={criticalFindings}
              onChange={(e) => setCriticalFindings(e.target.checked)}
            />
            <span className="toggle-slider"></span>
          </label>
        </div>

        <div className="notification-item">
          <div className="notification-info">
            <h3>Tool Failures</h3>
            <p>Alert when a tool execution fails</p>
          </div>
          <label className="toggle-switch">
            <input
              type="checkbox"
              checked={toolFailures}
              onChange={(e) => setToolFailures(e.target.checked)}
            />
            <span className="toggle-slider"></span>
          </label>
        </div>
      </div>

      <div className="settings-actions">
        <button className="btn primary" onClick={onSave}>
          <Save size={18} />
          Save Notification Settings
        </button>
      </div>
    </div>
  );
}

function DatabaseSettings({ onSave }) {
  const [msfHost, setMsfHost] = useState('127.0.0.1');
  const [msfPort, setMsfPort] = useState('55553');
  const [msfPassword, setMsfPassword] = useState('');
  const [connected, setConnected] = useState(false);

  const handleTestConnection = () => {
    // Simulate connection test
    setTimeout(() => setConnected(true), 1000);
  };

  return (
    <div className="settings-section">
      <h2>Metasploit Database</h2>
      <p className="section-desc">
        Configure connection to Metasploit RPC for database integration
      </p>

      <div className="db-connection-card">
        <div className="connection-status">
          <div className={`status-dot ${connected ? 'connected' : 'disconnected'}`}></div>
          <span>{connected ? 'Connected' : 'Disconnected'}</span>
        </div>

        <div className="db-settings-grid">
          <div className="setting-group">
            <label>Host</label>
            <input
              type="text"
              value={msfHost}
              onChange={(e) => setMsfHost(e.target.value)}
              placeholder="127.0.0.1"
            />
          </div>

          <div className="setting-group">
            <label>Port</label>
            <input
              type="number"
              value={msfPort}
              onChange={(e) => setMsfPort(e.target.value)}
              placeholder="55553"
            />
          </div>

          <div className="setting-group full-width">
            <label>Password</label>
            <input
              type="password"
              value={msfPassword}
              onChange={(e) => setMsfPassword(e.target.value)}
              placeholder="Enter Metasploit password"
            />
          </div>
        </div>

        <div className="db-actions">
          <button className="btn" onClick={handleTestConnection}>
            Test Connection
          </button>
          <button className="btn primary" onClick={onSave}>
            <Save size={18} />
            Save Configuration
          </button>
        </div>

        {connected && (
          <div className="db-stats">
            <h4>Database Statistics</h4>
            <div className="stats-row">
              <div className="stat">
                <span className="label">Hosts</span>
                <span className="value">247</span>
              </div>
              <div className="stat">
                <span className="label">Services</span>
                <span className="value">1,832</span>
              </div>
              <div className="stat">
                <span className="label">Vulnerabilities</span>
                <span className="value">89</span>
              </div>
              <div className="stat">
                <span className="label">Credentials</span>
                <span className="value">34</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Settings;
