import React, { useState } from 'react';
import { Plus, Search, Filter, Download, Eye, Play, Trash2 } from 'lucide-react';

function Engagements() {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');

  const engagements = [
    {
      id: 'eng-2026041801',
      name: 'Q2 2026 External Pentest',
      type: 'penetration_test',
      status: 'in_progress',
      progress: 67,
      start_date: '2026-04-15',
      targets: ['203.0.113.0/24', 'example.com'],
      findings: 23,
      critical: 3,
      high: 8,
      medium: 9,
      low: 3,
    },
    {
      id: 'eng-2026041802',
      name: 'Web Application Audit',
      type: 'web_audit',
      status: 'completed',
      progress: 100,
      start_date: '2026-04-10',
      targets: ['app.example.com'],
      findings: 15,
      critical: 1,
      high: 4,
      medium: 7,
      low: 3,
    },
    {
      id: 'eng-2026041803',
      name: 'Internal Network Recon',
      type: 'reconnaissance',
      status: 'planning',
      progress: 12,
      start_date: '2026-04-18',
      targets: ['198.51.100.0/8'],
      findings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
  ];

  const filtered = engagements.filter(eng => {
    const matchesSearch = eng.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = filterStatus === 'all' || eng.status === filterStatus;
    return matchesSearch && matchesFilter;
  });

  return (
    <div className="engagements-page">
      <div className="page-header">
        <h1>Security Engagements</h1>
        <button className="btn primary">
          <Plus size={20} />
          New Engagement
        </button>
      </div>

      <div className="filters-bar">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search engagements..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        
        <div className="filter-group">
          <Filter size={18} />
          <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
            <option value="all">All Status</option>
            <option value="planning">Planning</option>
            <option value="in_progress">In Progress</option>
            <option value="completed">Completed</option>
          </select>
        </div>
      </div>

      <div className="engagements-grid">
        {filtered.map((eng) => (
          <EngagementCard key={eng.id} engagement={eng} />
        ))}
      </div>
    </div>
  );
}

function EngagementCard({ engagement }) {
  const severityColors = {
    critical: '#ef4444',
    high: '#f59e0b',
    medium: '#3b82f6',
    low: '#10b981',
  };

  return (
    <div className="engagement-card">
      <div className="card-header">
        <div className="engagement-info">
          <h3>{engagement.name}</h3>
          <span className={`badge ${engagement.status}`}>
            {engagement.status.replace('_', ' ')}
          </span>
        </div>
        <div className="card-actions">
          <button className="icon-btn" title="View">
            <Eye size={18} />
          </button>
          <button className="icon-btn" title="Execute Playbook">
            <Play size={18} />
          </button>
          <button className="icon-btn" title="Download Report">
            <Download size={18} />
          </button>
          <button className="icon-btn danger" title="Delete">
            <Trash2 size={18} />
          </button>
        </div>
      </div>

      <div className="engagement-meta">
        <div className="meta-item">
          <span className="label">Type</span>
          <span className="value">{engagement.type.replace('_', ' ')}</span>
        </div>
        <div className="meta-item">
          <span className="label">Started</span>
          <span className="value">{engagement.start_date}</span>
        </div>
        <div className="meta-item">
          <span className="label">Targets</span>
          <span className="value">{engagement.targets.length}</span>
        </div>
      </div>

      <div className="progress-section">
        <div className="progress-header">
          <span>Progress</span>
          <span>{engagement.progress}%</span>
        </div>
        <div className="progress-bar-large">
          <div 
            className="progress-fill-large" 
            style={{ 
              width: `${engagement.progress}%`,
              background: engagement.progress === 100 
                ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)'
                : 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)'
            }}
          ></div>
        </div>
      </div>

      <div className="findings-summary">
        <h4>Findings by Severity</h4>
        <div className="severity-bars">
          {Object.entries(severityColors).map(([severity, color]) => (
            <div key={severity} className="severity-item">
              <div className="severity-label">
                <span 
                  className="severity-dot" 
                  style={{ background: color }}
                ></span>
                <span className="severity-name">{severity}</span>
              </div>
              <div className="severity-count">{engagement[severity]}</div>
            </div>
          ))}
        </div>
        <div className="total-findings">
          Total: <strong>{engagement.findings}</strong> findings
        </div>
      </div>

      <div className="engagement-targets">
        <h4>Targets</h4>
        <div className="target-list">
          {engagement.targets.map((target, idx) => (
            <span key={idx} className="target-tag">{target}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

export default Engagements;
