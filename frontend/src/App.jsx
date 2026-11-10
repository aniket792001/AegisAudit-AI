/**
 * AegisAudit AI - Production-Grade Pure React Single Page Application (SPA).
 * Built with React 18, React Hooks, and Modern Enterprise GRC Architecture.
 */

const { useState, useEffect, useMemo, useCallback, useRef } = React;

const API_BASE = window.location.origin;

// Initial High-Impact Demo Report (Guarantees zero-blank state on initial launch)
const INITIAL_DEMO_REPORT = {
  audit_id: "AUDIT-ISO27001-DEMO",
  standard_name: "ISO/IEC 27001:2022 ISMS Framework",
  policy_name: "Enterprise_Cloud_Security_Policy.pdf",
  timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
  summary: {
    overall_compliance_percentage: 78.5,
    total_clauses_audited: 6,
    compliant_count: 3,
    partially_compliant_count: 1,
    non_compliant_count: 2,
    risk_breakdown: { Critical: 1, High: 1, Medium: 1, Low: 3 },
    executive_overview: "Overall enterprise compliance posture is established at 78.5% audit readiness. While cryptographic key management and centralized SIEM telemetry meet strict regulatory thresholds, critical non-compliance was flagged in automated de-provisioning workflows (ISO-A.9.2.1) and Multi-Factor Authentication enforcement for production infrastructure access (ISO-A.8.5)."
  },
  findings: [
    {
      clause_id: "ISO-A.9.2.1",
      clause_title: "User Registration & Deprovisioning Lifecycle",
      requirement_summary: "A formalized user registration and de-registration process must be strictly implemented to govern assignment and immediate revocation of access rights upon personnel departure.",
      status: "Non-Compliant",
      risk_level: "Critical",
      is_verified: false,
      auditor_notes: "Identity audit revealed 4 active accounts belonging to departed contractors.",
      remediation_owner: "SecOps / IAM Lead",
      remediation_status: "Open",
      citations: [{ document_name: "Enterprise_Cloud_Security_Policy.pdf", page_number: 14 }],
      evidence_found: "Policy Section 4.1 specifies that access requests are submitted via service desk tickets, but lacks an automated SLA or SCIM webhook for de-provisioning departed employees within 24 hours.",
      gap_analysis: "No automated integration exists between Workday HR events and Okta SSO directory. Deprovisioning relies on manual ticketing with no SLA enforcement.",
      remediation_recommendation: "Deploy automated SCIM identity synchronization between HR Core and Okta/Azure AD with an automated 2-hour hard deactivation SLA for offboarded identities."
    },
    {
      clause_id: "ISO-A.8.5",
      clause_title: "Secure Authentication Procedures & Multi-Factor Enforcement",
      requirement_summary: "Secure authentication methods and MFA must be enforced for all administrative access, cloud control planes, and remote workstation connections.",
      status: "Non-Compliant",
      risk_level: "High",
      is_verified: false,
      auditor_notes: "Legacy bastion jump host allowed SMS-based MFA.",
      remediation_owner: "Cloud Infrastructure Team",
      remediation_status: "In Progress",
      citations: [{ document_name: "Enterprise_Cloud_Security_Policy.pdf", page_number: 18 }],
      evidence_found: "Policy Section 6 mandates MFA for external VPN access, but exempts internal developer jump boxes and allows deprecated SMS verification tokens.",
      gap_analysis: "Absence of FIDO2/WebAuthn hardware key requirements and presence of SMS MFA creates significant exposure to SIM-swapping and adversary-in-the-middle phishing attacks.",
      remediation_recommendation: "Mandate Phishing-Resistant FIDO2/WebAuthn security keys for all AWS Console, production Kubernetes clusters, and bastion access. Deprecate SMS."
    },
    {
      clause_id: "ISO-A.10.1.1",
      clause_title: "Cryptographic Controls & AES-256 Key Management",
      requirement_summary: "A formalized policy on the use of cryptographic controls and automated key management for protection of data-at-rest and data-in-transit must be enforced.",
      status: "Compliant",
      risk_level: "Low",
      is_verified: true,
      auditor_notes: "AWS KMS automated 365-day rotation validated via Terraform state.",
      remediation_owner: "DevSecOps Lead",
      remediation_status: "Resolved",
      citations: [{ document_name: "Enterprise_Cloud_Security_Policy.pdf", page_number: 22 }],
      evidence_found: "Policy Chapter 7 mandates AES-256 encryption across all AWS S3 buckets, RDS Aurora databases, and EBS storage volumes, with TLS 1.3 enforced for public endpoints.",
      gap_analysis: "Controls satisfy standard requirements completely. Cryptographic protocols align with NIST SP 800-57 recommendations.",
      remediation_recommendation: "Maintain continuous automated compliance monitoring via AWS Config rules and CloudTrail cryptographic drift alarms."
    },
    {
      clause_id: "GDPR-Art.32",
      clause_title: "Security of Processing & Data Protection Controls",
      requirement_summary: "The controller and processor shall implement technical and organizational measures to ensure a level of security appropriate to the risk, including pseudonymization and testing.",
      status: "Partially Compliant",
      risk_level: "Medium",
      is_verified: false,
      auditor_notes: "Pseudonymization exists in non-prod, but periodic tabletop breach drills are undocumented.",
      remediation_owner: "Compliance Officer",
      remediation_status: "Under Review",
      citations: [{ document_name: "Enterprise_Cloud_Security_Policy.pdf", page_number: 29 }],
      evidence_found: "Policy mandates masking of PII in non-production environments, but lacks a formalized calendar for bi-annual simulated data breach exercises.",
      gap_analysis: "Annual penetration testing is performed, but GDPR Article 32(1)(d) requirement for a process of regularly testing and evaluating effectiveness is partially documented.",
      remediation_recommendation: "Schedule bi-annual simulated breach tabletop exercises with legal, SecOps, and engineering leads, documenting RTO and regulatory notification timelines."
    },
    {
      clause_id: "ISO-A.12.4.1",
      clause_title: "Event Logging & SIEM Immutable Audit Trails",
      requirement_summary: "Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.",
      status: "Compliant",
      risk_level: "Low",
      is_verified: true,
      auditor_notes: "Splunk WORM S3 Object Lock retention verified.",
      remediation_owner: "SecOps Lead",
      remediation_status: "Resolved",
      citations: [{ document_name: "Enterprise_Cloud_Security_Policy.pdf", page_number: 35 }],
      evidence_found: "Centralized Splunk Cloud SIEM aggregates Linux journald, Windows Event logs, and AWS CloudTrail with 365-day immutable WORM compliance retention.",
      gap_analysis: "Fully meets ISO and SOC 2 requirements. Tamper-evident hash chaining is active on all ingested streams.",
      remediation_recommendation: "Conduct quarterly log pipeline synthetic test alerts to ensure SIEM ingestion latency remains below 120 seconds."
    },
    {
      clause_id: "NIST-DE.CM-01",
      clause_title: "Continuous Automated Vulnerability Scanning",
      requirement_summary: "Networks, computing infrastructure, and physical environments are continuously monitored to identify potential cybersecurity events and vulnerabilities.",
      status: "Compliant",
      risk_level: "Low",
      is_verified: true,
      auditor_notes: "Wiz and Snyk CI/CD pipeline blocking gates active.",
      remediation_owner: "Application Security",
      remediation_status: "Resolved",
      citations: [{ document_name: "Enterprise_Cloud_Security_Policy.pdf", page_number: 41 }],
      evidence_found: "Daily automated vulnerability scans across cloud assets via Wiz and pull-request container image scanning via Snyk with zero critical CVE bypasses allowed.",
      gap_analysis: "Meets NIST CSF 2.0 Detect subcategory requirements.",
      remediation_recommendation: "Review zero-day disclosure procedures to guarantee 24-hour SLA for vendor out-of-band security patches."
    }
  ]
};

function App() {
  // --- Navigation & Core State ---
  const [activeTab, setActiveTab] = useState('dashboard'); // dashboard | studio | matrix | standards | diff | exports
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    return localStorage.getItem('aegis_sidebar_collapsed') === 'true';
  });
  const [theme, setTheme] = useState(localStorage.getItem('aegis_theme') || 'dark');
  const [token, setToken] = useState(localStorage.getItem('aegis_token') || '');
  const [user, setUser] = useState({
    full_name: 'Lead Compliance Auditor',
    email: 'admin@aegisaudit.com',
    role: 'admin'
  });

  const toggleSidebar = useCallback(() => {
    setSidebarCollapsed(prev => {
      const next = !prev;
      localStorage.setItem('aegis_sidebar_collapsed', String(next));
      return next;
    });
  }, []);

  // --- Reports & Matrix State ---
  const [report, setReport] = useState(INITIAL_DEMO_REPORT);
  const [selectedFinding, setSelectedFinding] = useState(INITIAL_DEMO_REPORT.findings[0]);
  const [pastAudits, setPastAudits] = useState([]);
  const [matrixFilter, setMatrixFilter] = useState('ALL'); // ALL | GAP | PARTIAL | COMPLIANT | VERIFIED
  const [matrixSearch, setMatrixSearch] = useState('');

  // --- Standards & Documents ---
  const [standardsCatalog, setStandardsCatalog] = useState([]);
  const [availableDocs, setAvailableDocs] = useState([]);

  // --- Audit Studio Form & SSE Execution ---
  const [studioStandardKey, setStudioStandardKey] = useState('iso_27001_2022');
  const [studioCustomStandard, setStudioCustomStandard] = useState('');
  const [selectedPolicies, setSelectedPolicies] = useState(['sample.pdf']);
  const [studioMaxClauses, setStudioMaxClauses] = useState(10);
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditProgress, setAuditProgress] = useState(0);
  const [activeStepTitle, setActiveStepTitle] = useState('Idle');
  const [agentLogs, setAgentLogs] = useState([]);
  const [activeAgent, setActiveAgent] = useState('Orchestrator');

  // --- Compare & Diff State ---
  const [diffBaselineId, setDiffBaselineId] = useState('');
  const [diffTargetId, setDiffTargetId] = useState('');
  const [diffResult, setDiffResult] = useState(null);
  const [isDiffLoading, setIsDiffLoading] = useState(false);

  // --- Auditor Review Form State (For Right-hand Inspector) ---
  const [editStatus, setEditStatus] = useState('');
  const [editVerified, setEditVerified] = useState(false);
  const [editNotes, setEditNotes] = useState('');
  const [editOwner, setEditOwner] = useState('');
  const [editRemediationStatus, setEditRemediationStatus] = useState('Open');
  const [isSavingReview, setIsSavingReview] = useState(false);

  // --- Auth Modal & Toast ---
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authMode, setAuthMode] = useState('login');
  const [authEmail, setAuthEmail] = useState('admin@aegisaudit.com');
  const [authPass, setAuthPass] = useState('AdminPass123!');
  const [authName, setAuthName] = useState('Lead Auditor');
  const [authRole, setAuthRole] = useState('admin');
  const [toast, setToast] = useState(null);

  // Sync theme attribute with document root
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('aegis_theme', theme);
  }, [theme]);

  // Global Keyboard Shortcuts (Ctrl+B sidebar, Escape modal, / search)
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
        e.preventDefault();
        toggleSidebar();
      }
      if (e.key === 'Escape') {
        setShowAuthModal(false);
      }
      if (e.key === '/' && activeTab === 'matrix') {
        const tag = document.activeElement?.tagName;
        if (tag !== 'INPUT' && tag !== 'TEXTAREA') {
          e.preventDefault();
          const searchEl = document.querySelector('.search-input');
          if (searchEl) searchEl.focus();
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [toggleSidebar, activeTab]);

  // Show Toast Helper
  const showToast = (text, type = 'success') => {
    setToast({ text, type });
    setTimeout(() => setToast(null), 4000);
  };

  // Sync finding changes to edit form state
  useEffect(() => {
    if (selectedFinding) {
      setEditStatus(selectedFinding.status || 'Compliant');
      setEditVerified(!!selectedFinding.is_verified);
      setEditNotes(selectedFinding.auditor_notes || '');
      setEditOwner(selectedFinding.remediation_owner || 'SecOps Lead');
      setEditRemediationStatus(selectedFinding.remediation_status || 'Open');
    }
  }, [selectedFinding]);

  // --- Initial Data Load & Seamless Onboarding ---
  useEffect(() => {
    // Auto-login default admin if no token in session
    if (!token) {
      fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'admin@aegisaudit.com', password: 'AdminPass123!' })
      })
        .then(res => res.ok ? res.json() : null)
        .then(data => {
          if (data?.access_token) {
            setToken(data.access_token);
            setUser(data.user);
            localStorage.setItem('aegis_token', data.access_token);
          }
        })
        .catch(() => { });
    } else {
      fetch(`${API_BASE}/api/auth/me`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })
        .then(res => res.ok ? res.json() : null)
        .then(u => {
          if (u) setUser(u);
        })
        .catch(() => { });
    }

    // Load history, standards catalog & documents
    loadAuditHistory();

    fetch(`${API_BASE}/api/audit/standards/catalog`)
      .then(res => res.ok ? res.json() : [])
      .then(catalog => {
        setStandardsCatalog(catalog);
      })
      .catch(() => { });

    fetch(`${API_BASE}/api/documents/list`, {
      headers: token ? { 'Authorization': `Bearer ${token}` } : {}
    })
      .then(res => res.ok ? res.json() : [])
      .then(docs => {
        setAvailableDocs(docs);
        if (docs.length > 0 && selectedPolicies.length === 0) {
          setSelectedPolicies([docs[0].filename]);
        }
      })
      .catch(() => { });
  }, [token]);

  const loadAuditHistory = () => {
    fetch(`${API_BASE}/api/audit/history`, {
      headers: token ? { 'Authorization': `Bearer ${token}` } : {}
    })
      .then(res => res.ok ? res.json() : [])
      .then(list => {
        setPastAudits(list);
        if (list.length > 0) {
          if (!report || report.audit_id === 'AUDIT-ISO27001-DEMO') {
            loadReport(list[0].audit_id, false);
          }
          if (list.length >= 2) {
            setDiffBaselineId(list[1].audit_id);
            setDiffTargetId(list[0].audit_id);
          }
        }
      })
      .catch(() => { });
  };

  const loadReport = (auditId, notify = true) => {
    fetch(`${API_BASE}/api/audit/${auditId}`, {
      headers: token ? { 'Authorization': `Bearer ${token}` } : {}
    })
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data) {
          setReport(data);
          if (data.findings && data.findings.length > 0) {
            setSelectedFinding(data.findings[0]);
          }
          if (notify) {
            showToast(`Loaded audit report ${auditId}`, 'info');
          }
        }
      })
      .catch(err => console.error(err));
  };

  // --- Auth Handlers ---
  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: authEmail, password: authPass })
      });
      if (res.ok) {
        const data = await res.json();
        setToken(data.access_token);
        localStorage.setItem('aegis_token', data.access_token);
        setUser(data.user);
        setShowAuthModal(false);
        showToast(`Signed in as ${data.user.full_name}`);
        loadAuditHistory();
      } else {
        const err = await res.json();
        showToast(err.detail || 'Authentication failed', 'error');
      }
    } catch (err) {
      showToast('Network error during login', 'error');
    }
  };

  const handleRegister = async (e) => {
    if (e) e.preventDefault();
    try {
      const res = await fetch(`${API_BASE}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: authEmail,
          password: authPass,
          full_name: authName,
          role: authRole
        })
      });
      if (res.ok) {
        const data = await res.json();
        setToken(data.access_token);
        localStorage.setItem('aegis_token', data.access_token);
        setUser(data.user);
        setShowAuthModal(false);
        showToast(`Account created for ${data.user.full_name}`);
        loadAuditHistory();
      } else {
        const err = await res.json();
        showToast(err.detail || 'Registration failed', 'error');
      }
    } catch (err) {
      showToast('Network error during registration', 'error');
    }
  };

  const handleLogout = () => {
    setToken('');
    localStorage.removeItem('aegis_token');
    setUser({ full_name: 'Guest Viewer', email: '', role: 'viewer' });
    showToast('Signed out of session', 'info');
  };

  // --- Document Upload Handler ---
  const handleFileUpload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      showToast(`Uploading ${file.name}...`, 'info');
      const res = await fetch(`${API_BASE}/api/documents/upload`, {
        method: 'POST',
        headers: token ? { 'Authorization': `Bearer ${token}` } : {},
        body: formData
      });
      if (res.ok) {
        const doc = await res.json();
        showToast(`File ${doc.filename} uploaded successfully!`);
        // Refresh docs list
        const refreshed = await fetch(`${API_BASE}/api/documents/list`, {
          headers: token ? { 'Authorization': `Bearer ${token}` } : {}
        });
        if (refreshed.ok) {
          const docs = await refreshed.json();
          setAvailableDocs(docs);
          setSelectedPolicies(prev => [...new Set([...prev, doc.filename])]);
        }
      } else {
        const err = await res.json();
        showToast(err.detail || 'Upload failed', 'error');
      }
    } catch (err) {
      showToast('Failed to upload document', 'error');
    }
  };

  // --- Launch Audit in Background & Stream via SSE ---
  const launchAutonomousAudit = async () => {
    if (selectedPolicies.length === 0) {
      showToast('Please select at least one company policy document', 'error');
      return;
    }

    setIsAuditing(true);
    setAuditProgress(5);
    setActiveStepTitle('Orchestrator: Queuing audit job...');
    setAgentLogs([{
      timestamp: new Date().toLocaleTimeString(),
      agent_name: 'Orchestrator',
      message: 'Dispatching audit job to parallel execution pool...',
      progress_pct: 5
    }]);

    try {
      const payload = {
        standard_key: studioStandardKey || null,
        standard_filename: studioCustomStandard || 'sample.pdf',
        policy_filenames: selectedPolicies,
        max_clauses: studioMaxClauses
      };

      const res = await fetch(`${API_BASE}/api/audit/jobs/submit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to submit audit job');
      }

      const jobData = await res.json();
      showToast(`Audit job ${jobData.job_id} launched! Streaming telemetry...`, 'info');

      // Connect to SSE stream
      const eventSource = new EventSource(`${API_BASE}/api/audit/jobs/${jobData.job_id}/stream`);

      eventSource.onmessage = (e) => {
        try {
          const log = JSON.parse(e.data);
          setAgentLogs(prev => [...prev, log]);
          if (log.progress_pct) setAuditProgress(log.progress_pct);
          if (log.agent_name) setActiveAgent(log.agent_name);
          if (log.message) setActiveStepTitle(log.message);
        } catch (err) { }
      };

      eventSource.addEventListener('end', () => {
        eventSource.close();
        setIsAuditing(false);
        setAuditProgress(100);
        setActiveStepTitle('Audit Completed Successfully.');
        showToast('Autonomous Audit Finished! Finalizing report...', 'success');

        // Fetch completed report
        fetch(`${API_BASE}/api/audit/jobs/${jobData.job_id}/status`, {
          headers: token ? { 'Authorization': `Bearer ${token}` } : {}
        })
          .then(r => r.json())
          .then(doneJob => {
            if (doneJob.result) {
              setReport(doneJob.result);
              if (doneJob.result.findings?.length > 0) {
                setSelectedFinding(doneJob.result.findings[0]);
              }
              loadAuditHistory();
              // Switch to findings matrix after a short delay
              setTimeout(() => setActiveTab('matrix'), 1000);
            }
          });
      });

      eventSource.onerror = () => {
        eventSource.close();
        setIsAuditing(false);
      };

    } catch (err) {
      setIsAuditing(false);
      showToast(`Error launching audit: ${err.message}`, 'error');
    }
  };

  // --- Auditor Review Save Handler ---
  const saveAuditorReview = async () => {
    if (!selectedFinding || !report) return;
    setIsSavingReview(true);

    try {
      const payload = {
        clause_id: selectedFinding.clause_id,
        status: editStatus,
        is_verified: editVerified,
        auditor_notes: editNotes,
        remediation_owner: editOwner,
        remediation_status: editRemediationStatus
      };

      const res = await fetch(`${API_BASE}/api/audit/${report.audit_id}/review`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to save review');
      }

      const updatedReport = await res.json();
      setReport(updatedReport);
      // Update selected finding
      const updatedFinding = updatedReport.findings.find(f => f.clause_id === selectedFinding.clause_id);
      if (updatedFinding) {
        setSelectedFinding(updatedFinding);
      }
      showToast(`Auditor review for ${selectedFinding.clause_id} saved successfully!`);
      loadAuditHistory(); // Refresh history with new compliance percentage
    } catch (err) {
      showToast(`Review save failed: ${err.message}`, 'error');
    } finally {
      setIsSavingReview(false);
    }
  };

  // --- Compare / Diff Handler ---
  const runDiffComparison = async () => {
    if (!diffBaselineId || !diffTargetId) {
      showToast('Please select both baseline and target audits to compare', 'error');
      return;
    }
    setIsDiffLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/audit/compare`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        },
        body: JSON.stringify({
          audit_id_1: diffBaselineId,
          audit_id_2: diffTargetId
        })
      });
      if (res.ok) {
        const diffData = await res.json();
        setDiffResult(diffData);
        showToast('Compliance diff generated successfully!');
      } else {
        const err = await res.json();
        showToast(err.detail || 'Diff comparison failed', 'error');
      }
    } catch (err) {
      showToast('Failed to compare audits', 'error');
    } finally {
      setIsDiffLoading(false);
    }
  };

  // --- Direct File Download Helper ---
  const triggerDownload = (format) => {
    if (!report) return;
    const url = `${API_BASE}/api/audit/${report.audit_id}/export/${format}`;
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `AegisAudit_${report.audit_id}.${format}`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast(`Downloading official ${format.toUpperCase()} export...`, 'info');
  };

  // Filtered Findings Calculation
  const filteredFindings = useMemo(() => {
    if (!report?.findings) return [];
    return report.findings.filter(f => {
      // Status filter
      if (matrixFilter === 'GAP' && f.status !== 'Non-Compliant') return false;
      if (matrixFilter === 'PARTIAL' && f.status !== 'Partially Compliant') return false;
      if (matrixFilter === 'COMPLIANT' && f.status !== 'Compliant') return false;
      if (matrixFilter === 'VERIFIED' && !f.is_verified) return false;

      // Search query
      if (matrixSearch) {
        const q = matrixSearch.toLowerCase();
        const cid = (f.clause_id || '').toLowerCase();
        const title = (f.clause_title || '').toLowerCase();
        const req = (f.requirement_summary || '').toLowerCase();
        const ev = (f.evidence_found || '').toLowerCase();
        return cid.includes(q) || title.includes(q) || req.includes(q) || ev.includes(q);
      }
      return true;
    });
  }, [report, matrixFilter, matrixSearch]);

  const compliancePct = report?.summary?.overall_compliance_percentage || 0;
  const compliantCount = report?.summary?.compliant_count || 0;
  const partialCount = report?.summary?.partially_compliant_count || 0;
  const gapCount = report?.summary?.non_compliant_count || 0;

  return (
    <div className="app-shell">
      {/* Toast Notification */}
      {toast && (
        <div className="toast-container">
          <div className="toast-msg">
            <span>{toast.type === 'error' ? '⚠️' : toast.type === 'info' ? 'ℹ️' : '✅'}</span>
            <span>{toast.text}</span>
          </div>
        </div>
      )}

      {/* LEFT ENTERPRISE SIDEBAR NAVIGATION */}
      <aside className={`sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
        {/* Brand & Logo Header */}
        <div className="sidebar-header">
          <div className="sidebar-brand" onClick={() => setActiveTab('dashboard')} title="AegisAudit AI Home">
            <div className="sidebar-brand-icon">🛡️</div>
            <div className="sidebar-brand-text">
              <span className="sidebar-brand-title">AegisAudit AI</span>
              <span className="sidebar-brand-sub">Autonomous GRC</span>
            </div>
          </div>
          <button
            className="sidebar-collapse-btn"
            onClick={toggleSidebar}
            title={sidebarCollapsed ? "Expand Sidebar (Ctrl+B)" : "Collapse Sidebar (Ctrl+B)"}
          >
            {sidebarCollapsed ? '»' : '«'}
          </button>
        </div>

        {/* Active Audit Session Switcher Box */}
        <div className="sidebar-audit-box">
          <div className="sidebar-section-label">Active Audit Session</div>
          {pastAudits.length > 0 ? (
            <select
              className="sidebar-audit-select"
              value={report?.audit_id || ''}
              onChange={(e) => loadReport(e.target.value)}
              title="Switch Active Audit Run"
            >
              {pastAudits.map(a => (
                <option key={a.audit_id} value={a.audit_id}>
                  {a.audit_id} ({a.compliance_pct}%)
                </option>
              ))}
            </select>
          ) : (
            <div style={{ fontSize: '0.78rem', color: 'var(--accent-cyan-light)', fontFamily: 'var(--font-mono)', padding: '4px 0' }}>
              {report?.audit_id || 'AUDIT-ISO27001-DEMO'}
            </div>
          )}
        </div>

        {/* Vertical Navigation Menu */}
        <nav className="sidebar-nav">
          <div className="sidebar-nav-heading">Platform</div>

          <button
            className={`sidebar-nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <div className="sidebar-nav-item-left">
              <span className="sidebar-nav-icon">📊</span>
              <span>Executive Dashboard</span>
            </div>
            <span className="sidebar-nav-badge">{compliancePct}%</span>
          </button>

          <button
            className={`sidebar-nav-item ${activeTab === 'studio' ? 'active' : ''}`}
            onClick={() => setActiveTab('studio')}
          >
            <div className="sidebar-nav-item-left">
              <span className="sidebar-nav-icon">⚡</span>
              <span>Audit Studio</span>
            </div>
            {isAuditing && <span className="agent-pulse" style={{ background: '#34D399', width: '8px', height: '8px' }}></span>}
          </button>

          <button
            className={`sidebar-nav-item ${activeTab === 'matrix' ? 'active' : ''}`}
            onClick={() => setActiveTab('matrix')}
          >
            <div className="sidebar-nav-item-left">
              <span className="sidebar-nav-icon">📋</span>
              <span>Findings Matrix</span>
            </div>
            <span className="sidebar-nav-badge">{report?.findings?.length || 0}</span>
          </button>

          <div className="sidebar-nav-heading">Intelligence</div>

          <button
            className={`sidebar-nav-item ${activeTab === 'standards' ? 'active' : ''}`}
            onClick={() => setActiveTab('standards')}
          >
            <div className="sidebar-nav-item-left">
              <span className="sidebar-nav-icon">📚</span>
              <span>Standards Catalog</span>
            </div>
            <span className="sidebar-nav-badge">{standardsCatalog.length || 4}</span>
          </button>

          <button
            className={`sidebar-nav-item ${activeTab === 'diff' ? 'active' : ''}`}
            onClick={() => setActiveTab('diff')}
          >
            <div className="sidebar-nav-item-left">
              <span className="sidebar-nav-icon">🔀</span>
              <span>Diff & Benchmark</span>
            </div>
          </button>

          <button
            className={`sidebar-nav-item ${activeTab === 'exports' ? 'active' : ''}`}
            onClick={() => setActiveTab('exports')}
          >
            <div className="sidebar-nav-item-left">
              <span className="sidebar-nav-icon">📥</span>
              <span>Export Center</span>
            </div>
            <span className="sidebar-nav-badge">PDF/XLS</span>
          </button>
        </nav>

        {/* Quick Launch CTA */}
        <div className="sidebar-action-box">
          <button
            className="btn btn-primary"
            style={{ width: '100%', justifyContent: 'center', padding: '10px 14px', fontSize: '0.85rem' }}
            onClick={() => setActiveTab('studio')}
            disabled={user?.role === 'viewer'}
            title="Launch New Audit"
          >
            <span className="btn-icon">⚡</span>
            <span>Launch Audit</span>
          </button>
        </div>

        {/* Sidebar Footer: User Card & Theme Switcher */}
        <div className="sidebar-footer">
          {user?.email ? (
            <div className="user-profile-card">
              <div style={{ display: 'flex', alignItems: 'center', minWidth: 0, overflow: 'hidden' }}>
                <div className="user-avatar">
                  {user.full_name ? user.full_name.charAt(0).toUpperCase() : 'U'}
                </div>
                <div className="user-info">
                  <span className="user-name" title={user.full_name}>{user.full_name}</span>
                  <span className="user-role-badge">{user.role}</span>
                </div>
              </div>
              <button
                className="btn btn-ghost"
                onClick={handleLogout}
                title="Sign Out"
                style={{ padding: '4px 8px', fontSize: '0.85rem', color: 'var(--text-dim)' }}
              >
                🚪
              </button>
            </div>
          ) : (
            <button
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center' }}
              onClick={() => setShowAuthModal(true)}
            >
              🔐 Sign In to Workspace
            </button>
          )}

          <button
            className="btn btn-secondary theme-toggle-btn"
            style={{ width: '100%', justifyContent: 'center', fontSize: '0.80rem', padding: '8px 12px' }}
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          >
            <span className="theme-icon">{theme === 'dark' ? '☀️' : '🌙'}</span>
            <span>{theme === 'dark' ? ' Light Mode' : ' Dark Mode'}</span>
          </button>
        </div>
      </aside>

      {/* RIGHT MAIN VIEWPORT */}
      <div className="main-viewport">
        {/* Dynamic Context Topbar */}
        <header className="viewport-topbar">
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <button
              className="topbar-collapse-btn"
              onClick={toggleSidebar}
              title={sidebarCollapsed ? "Expand Sidebar (Ctrl+B)" : "Collapse Sidebar (Ctrl+B)"}
            >
              {sidebarCollapsed ? '☰' : '⇤'}
            </button>
            <div className="viewport-title-area">
              <h1 className="viewport-title">
                {activeTab === 'dashboard' && '📊 Executive Compliance Dashboard'}
                {activeTab === 'studio' && '⚡ Autonomous Audit Studio'}
                {activeTab === 'matrix' && '📋 Regulatory Compliance Matrix'}
                {activeTab === 'standards' && '📚 Regulatory Standards & Benchmarks'}
                {activeTab === 'diff' && '🔀 Compliance Diff & Benchmarking'}
                {activeTab === 'exports' && '📥 Audit Export & Artifact Center'}
              </h1>
              <div className="viewport-subtitle">
                {activeTab === 'dashboard' && `Comprehensive audit posture for ${report?.standard_name || 'Active Audit'}`}
                {activeTab === 'studio' && 'Multi-Agent Regulatory Inference & RAG Verification Pipeline'}
                {activeTab === 'matrix' && `${report?.findings?.length || 0} Controls Audited • ${gapCount} Gaps • ${partialCount} Partial • ${compliantCount} Compliant`}
                {activeTab === 'standards' && 'Pre-indexed ISO 27001, SOC 2, HIPAA, NIST CSF & GDPR Benchmarks'}
                {activeTab === 'diff' && 'Side-by-side delta between two audit runs'}
                {activeTab === 'exports' && 'Download cryptographic PDF, Excel, and JSON audit deliverables'}
              </div>
            </div>
          </div>

          <div className="viewport-actions">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '6px 12px' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Audit ID</span>
              <span style={{ fontSize: '0.78rem', color: 'var(--accent-cyan-light)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{report?.audit_id}</span>
              <span className="badge badge-compliant" style={{ fontSize: '0.70rem', padding: '2px 8px' }}>{compliancePct}%</span>
            </div>

            <button
              className="btn btn-secondary"
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              style={{ padding: '7px 10px', fontSize: '0.88rem' }}
            >
              {theme === 'dark' ? '☀️' : '🌙'}
            </button>

            {activeTab === 'dashboard' && (
              <button className="btn btn-secondary" onClick={() => triggerDownload('pdf')} style={{ padding: '7px 14px', fontSize: '0.82rem' }}>
                📄 Export PDF
              </button>
            )}

            {activeTab === 'matrix' && (
              <button className="btn btn-secondary" onClick={() => triggerDownload('pdf')} style={{ padding: '7px 14px', fontSize: '0.82rem' }}>
                📄 Download PDF Matrix
              </button>
            )}

            {activeTab !== 'studio' && (
              <button className="btn btn-primary" onClick={() => setActiveTab('studio')} style={{ padding: '7px 14px', fontSize: '0.82rem' }} disabled={user?.role === 'viewer'}>
                ⚡ Run Audit
              </button>
            )}
          </div>
        </header>

        {/* MAIN APPLICATION VIEWPORT CONTENT */}
        <main className={activeTab === 'matrix' ? 'viewport-content-matrix' : 'viewport-content'}>

          {/* =========================================================================
            VIEW 1: EXECUTIVE DASHBOARD (REDESIGNED FOR CLEAN SPACING & CONSISTENCY)
            ========================================================================= */}
          {activeTab === 'dashboard' && (
            <div className="view-container">

              {/* 1. Hero Compliance Posture Card */}
              <div className="dashboard-hero-card">
                <div className="dashboard-hero-main">
                  {/* SVG Donut Health Gauge */}
                  <div style={{ position: 'relative', width: '120px', height: '120px', flexShrink: 0 }}>
                    <svg viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
                      <circle cx="50" cy="50" r="42" fill="transparent" stroke="var(--border-subtle)" strokeWidth="10" />
                      <circle
                        cx="50"
                        cy="50"
                        r="42"
                        fill="transparent"
                        stroke={compliancePct >= 75 ? 'var(--status-compliant)' : compliancePct >= 50 ? 'var(--status-partial)' : 'var(--status-non-compliant)'}
                        strokeWidth="10"
                        strokeDasharray="264"
                        strokeDashoffset={264 - (264 * (compliancePct / 100))}
                        strokeLinecap="round"
                        style={{ transition: 'stroke-dashoffset 0.8s ease' }}
                      />
                    </svg>
                    <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                      <span style={{ fontSize: '1.65rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--text-main)', lineHeight: 1 }}>
                        {compliancePct}%
                      </span>
                      <span style={{ fontSize: '0.62rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--accent-cyan-light)', letterSpacing: '0.05em', marginTop: '3px' }}>
                        Audit Score
                      </span>
                    </div>
                  </div>

                  {/* Narrative & Standard Context */}
                  <div className="dashboard-hero-narrative">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                      <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--text-main)', margin: 0 }}>
                        Regulatory Compliance Posture
                      </h2>
                      <span className="badge badge-compliant" style={{ fontFamily: 'var(--font-mono)' }}>
                        ID: {report.audit_id}
                      </span>
                      <span className="badge" style={{ background: 'var(--bg-card)', color: 'var(--accent-cyan-light)', border: '1px solid var(--border-subtle)' }}>
                        {report.standard_name.replace('.pdf', '').replace('.txt', '')}
                      </span>
                    </div>
                    <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)', lineHeight: '1.55', margin: 0 }}>
                      {report?.summary?.executive_overview || 'Comprehensive evaluation completed. Controls have been audited against evidence extractions with cryptographic verification.'}
                    </p>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                      <span>Audited Corpus:</span>
                      <strong style={{ color: 'var(--text-main)' }}>{report.policy_name}</strong>
                      <span>•</span>
                      <span>Last run: {report.timestamp}</span>
                    </div>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="dashboard-hero-actions">
                  <button className="btn btn-primary" onClick={() => setActiveTab('matrix')} style={{ justifyContent: 'center' }}>
                    📋 Inspect Findings Matrix
                  </button>
                  <button className="btn btn-secondary" onClick={() => triggerDownload('pdf')} style={{ justifyContent: 'center' }}>
                    📄 Export Signed PDF
                  </button>
                  <button className="btn btn-secondary" onClick={() => triggerDownload('tasks')} style={{ justifyContent: 'center' }}>
                    🎯 Export Jira Remediation Tasks
                  </button>
                </div>
              </div>

              {/* 2. Four Unified KPI Cards */}
              <div className="kpi-grid">
                <div className="kpi-stat-card">
                  <div className="kpi-top-row">
                    <span className="kpi-title">Overall Compliance</span>
                    <span className="kpi-icon">📊</span>
                  </div>
                  <div className="kpi-val-row">
                    <span className="kpi-num" style={{ color: compliancePct >= 75 ? 'var(--status-compliant)' : 'var(--status-partial)' }}>
                      {compliancePct}%
                    </span>
                    <span className="badge badge-compliant" style={{ fontSize: '0.68rem', padding: '1px 6px' }}>Ready</span>
                  </div>
                  <div className="progress-bar-container" style={{ margin: 0, height: '6px' }}>
                    <div className="progress-bar-fill" style={{ width: `${compliancePct}%` }}></div>
                  </div>
                  <div className="kpi-subtext">Calculated across {report.summary?.total_clauses_audited || 0} evaluated controls</div>
                </div>

                <div className="kpi-stat-card">
                  <div className="kpi-top-row">
                    <span className="kpi-title">Compliant Controls</span>
                    <span className="kpi-icon">🟢</span>
                  </div>
                  <div className="kpi-val-row">
                    <span className="kpi-num" style={{ color: 'var(--status-compliant)' }}>{compliantCount}</span>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-dim)' }}>/ {report.summary?.total_clauses_audited || 0}</span>
                  </div>
                  <div className="progress-bar-container" style={{ margin: 0, height: '6px' }}>
                    <div className="progress-bar-fill" style={{ width: `${((compliantCount / (report.summary?.total_clauses_audited || 1)) * 100)}%`, background: 'var(--status-compliant)' }}></div>
                  </div>
                  <div className="kpi-subtext">Fully validated against policy evidence</div>
                </div>

                <div className="kpi-stat-card">
                  <div className="kpi-top-row">
                    <span className="kpi-title">Partial / Ambiguous</span>
                    <span className="kpi-icon">🟡</span>
                  </div>
                  <div className="kpi-val-row">
                    <span className="kpi-num" style={{ color: 'var(--status-partial)' }}>{partialCount}</span>
                    <span className="badge badge-partial" style={{ fontSize: '0.68rem', padding: '1px 6px' }}>In Review</span>
                  </div>
                  <div className="progress-bar-container" style={{ margin: 0, height: '6px' }}>
                    <div className="progress-bar-fill" style={{ width: `${((partialCount / (report.summary?.total_clauses_audited || 1)) * 100)}%`, background: 'var(--status-partial)' }}></div>
                  </div>
                  <div className="kpi-subtext">Compensating controls or documentation needed</div>
                </div>

                <div className="kpi-stat-card">
                  <div className="kpi-top-row">
                    <span className="kpi-title">Critical & High Gaps</span>
                    <span className="kpi-icon">🔴</span>
                  </div>
                  <div className="kpi-val-row">
                    <span className="kpi-num" style={{ color: 'var(--status-non-compliant)' }}>{gapCount}</span>
                    <span className="badge badge-non-compliant" style={{ fontSize: '0.68rem', padding: '1px 6px' }}>Action Req.</span>
                  </div>
                  <div className="progress-bar-container" style={{ margin: 0, height: '6px' }}>
                    <div className="progress-bar-fill" style={{ width: `${((gapCount / (report.summary?.total_clauses_audited || 1)) * 100)}%`, background: 'var(--status-non-compliant)' }}></div>
                  </div>
                  <div className="kpi-subtext">Immediate remediation workflow assigned</div>
                </div>
              </div>

              {/* 3. Balanced 2-Column Analytical Section */}
              <div className="dashboard-split-grid">

                {/* Left Column: Risk Severity Breakdown */}
                <div className="dashboard-card">
                  <div className="dashboard-card-header">
                    <div className="dashboard-card-title">
                      <span>🎯</span> Risk Severity Breakdown
                    </div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontWeight: 600 }}>By Impact Level</span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {[
                      { label: 'Critical Risk Gaps', count: report.summary?.risk_breakdown?.Critical || 1, color: '#EF4444', desc: 'Direct regulatory exposure; SCIM de-provisioning, root credentials' },
                      { label: 'High Risk Gaps', count: report.summary?.risk_breakdown?.High || 1, color: '#F59E0B', desc: 'Missing hardware MFA or network segmentation' },
                      { label: 'Medium Risk Items', count: report.summary?.risk_breakdown?.Medium || 1, color: '#EAB308', desc: 'Tabletop breach drills, logging latency review' },
                      { label: 'Low Risk / Compliant', count: report.summary?.risk_breakdown?.Low || 3, color: '#10B981', desc: 'Cryptographic key rotation, SIEM retention alignment' },
                    ].map(r => (
                      <div key={r.label} className="severity-row">
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: r.color }}></span>
                            <span style={{ fontSize: '0.86rem', fontWeight: 600, color: 'var(--text-main)' }}>{r.label}</span>
                          </div>
                          <span style={{ fontSize: '0.74rem', color: 'var(--text-dim)', marginLeft: '16px' }}>{r.desc}</span>
                        </div>
                        <span style={{ fontSize: '1.2rem', fontWeight: 800, color: r.color, fontFamily: 'var(--font-mono)' }}>
                          {r.count}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Right Column: Top High-Priority Audit Findings */}
                <div className="dashboard-card">
                  <div className="dashboard-card-header">
                    <div className="dashboard-card-title">
                      <span>⚠️</span> Priority Attention Findings
                    </div>
                    <button className="btn btn-ghost" onClick={() => setActiveTab('matrix')} style={{ fontSize: '0.78rem', padding: '4px 8px' }}>
                      View All in Matrix →
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {(report.findings || []).slice(0, 3).map(f => {
                      const badgeClass = f.status === 'Compliant' ? 'badge-compliant' :
                        f.status === 'Partially Compliant' ? 'badge-partial' : 'badge-non-compliant';
                      const riskClass = f.risk_level === 'Critical' ? 'risk-critical' :
                        f.risk_level === 'High' ? 'risk-high' :
                          f.risk_level === 'Medium' ? 'risk-medium' : 'risk-low';

                      return (
                        <div
                          key={f.clause_id}
                          className="finding-preview-item"
                          onClick={() => {
                            setSelectedFinding(f);
                            setActiveTab('matrix');
                          }}
                          title="Click to inspect finding in Compliance Matrix"
                        >
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', minWidth: 0, paddingRight: '12px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span className="clause-tag-pill">{f.clause_id}</span>
                              <span className={`risk-tag ${riskClass}`}>{f.risk_level}</span>
                              <span className={`badge ${badgeClass}`} style={{ fontSize: '0.68rem', padding: '1px 6px' }}>{f.status}</span>
                            </div>
                            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--text-main)', marginTop: '2px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                              {f.clause_title}
                            </div>
                            <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', display: '-webkit-box', WebkitLineClamp: 1, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                              {f.remediation_recommendation || f.requirement_summary}
                            </div>
                          </div>
                          <span style={{ fontSize: '0.85rem', color: 'var(--accent-cyan-light)', fontWeight: 700, whiteSpace: 'nowrap' }}>
                            Inspect →
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>

              </div>

              {/* 4. Historical Executions Card */}
              <div className="dashboard-card">
                <div className="dashboard-card-header">
                  <div className="dashboard-card-title">
                    <span>⏱️</span> Audit Run History & Benchmarks
                  </div>
                  <button className="btn btn-ghost" onClick={loadAuditHistory} style={{ fontSize: '0.78rem' }}>
                    🔄 Refresh Records
                  </button>
                </div>

                {pastAudits.length === 0 ? (
                  <div style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '32px 0' }}>
                    No historical records saved yet. Launch your first audit in the Audit Studio!
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {pastAudits.slice(0, 5).map(a => (
                      <div
                        key={a.audit_id}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          background: 'var(--bg-card)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: '10px',
                          padding: '12px 18px',
                          transition: 'all 0.2s'
                        }}
                      >
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.85rem', color: 'var(--accent-cyan-light)' }}>
                              {a.audit_id}
                            </span>
                            <span style={{ fontSize: '0.74rem', color: 'var(--text-dim)' }}>
                              {a.timestamp}
                            </span>
                          </div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '3px' }}>
                            Standard: <strong>{a.standard_name}</strong> vs Policy: <strong>{a.policy_name}</strong>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                          <span style={{
                            fontFamily: 'var(--font-mono)',
                            fontWeight: 800,
                            fontSize: '1rem',
                            color: a.compliance_pct >= 75 ? 'var(--status-compliant)' : a.compliance_pct >= 50 ? 'var(--status-partial)' : 'var(--status-non-compliant)'
                          }}>
                            {a.compliance_pct}%
                          </span>
                          <button
                            className="btn btn-secondary"
                            style={{ padding: '5px 12px', fontSize: '0.75rem' }}
                            onClick={() => {
                              loadReport(a.audit_id);
                              setActiveTab('matrix');
                            }}
                          >
                            Inspect
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

            </div>
          )}

          {/* =========================================================================
            VIEW 2: AUDIT STUDIO (LAUNCH & STREAM)
            ========================================================================= */}
          {activeTab === 'studio' && (
            <div className="view-container">
              <div className="studio-wizard" style={{ width: '100%', maxWidth: '1080px', margin: '0 auto' }}>

                <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '18px' }}>
                  <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-main)' }}>
                    ⚡ Autonomous Multi-Agent Audit Studio
                  </h2>
                  <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Configure regulatory frameworks, select policy corpora, and execute parallel LLM agent audits with real-time SSE streaming telemetry.
                  </p>
                </div>

                {/* STEP 1: SELECT REGULATORY STANDARD */}
                <div>
                  <div className="wizard-step-header">
                    <span className="wizard-step-number">1</span>
                    <div>
                      <div className="wizard-step-title">Select Regulatory Standard / Framework</div>
                      <div className="wizard-step-subtitle">Choose from verified pre-seeded standards or specify a custom framework document.</div>
                    </div>
                  </div>

                  <div className="standards-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
                    {[
                      { key: 'iso_27001_2022', title: 'ISO/IEC 27001:2022', badge: 'ISMS Standard', clauses: 93, desc: 'International benchmark for information security controls & Annex A domains.' },
                      { key: 'soc_2_type_ii', title: 'SOC 2 Type II', badge: 'Trust Services', clauses: 64, desc: 'AICPA security, confidentiality, availability, and processing integrity criteria.' },
                      { key: 'gdpr_compliance', title: 'GDPR Article 32', badge: 'EU Privacy', clauses: 18, desc: 'Mandatory technical and organizational measures for personal data processing.' },
                      { key: 'nist_csf_2_0', title: 'NIST CSF 2.0', badge: 'Cybersecurity', clauses: 106, desc: 'Govern, Identify, Protect, Detect, Respond, and Recover core functions.' },
                    ].map(std => {
                      const isSelected = studioStandardKey === std.key;
                      return (
                        <div
                          key={std.key}
                          className={`standard-card ${isSelected ? 'selected' : ''}`}
                          onClick={() => {
                            setStudioStandardKey(std.key);
                            setStudioCustomStandard('');
                          }}
                        >
                          <div>
                            <div className="standard-card-header">
                              <span className="standard-card-title">{std.title}</span>
                              <span className="standard-badge">{std.badge}</span>
                            </div>
                            <div className="standard-card-desc" style={{ marginTop: '8px' }}>{std.desc}</div>
                          </div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                            <span>{std.clauses} Controls Cataloged</span>
                            {isSelected && <span style={{ color: 'var(--accent-cyan-light)', fontWeight: 700 }}>✓ Selected</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* STEP 2: SELECT POLICY CORPUS */}
                <div>
                  <div className="wizard-step-header">
                    <span className="wizard-step-number">2</span>
                    <div>
                      <div className="wizard-step-title">Select Target Company Policy Corpus</div>
                      <div className="wizard-step-subtitle">Audit against single or multiple policy documents simultaneously.</div>
                    </div>
                  </div>

                  <div className="policy-selection-box">
                    <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}>
                      Available Documents in Data Directory:
                    </div>

                    {availableDocs.map(doc => {
                      const isChecked = selectedPolicies.includes(doc.filename);
                      return (
                        <div
                          key={doc.filename}
                          className={`policy-item ${isChecked ? 'checked' : ''}`}
                          onClick={() => {
                            if (isChecked) {
                              setSelectedPolicies(selectedPolicies.filter(p => p !== doc.filename));
                            } else {
                              setSelectedPolicies([...selectedPolicies, doc.filename]);
                            }
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <input type="checkbox" checked={isChecked} readOnly style={{ cursor: 'pointer' }} />
                            <span style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-main)' }}>📄 {doc.filename}</span>
                          </div>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                            {(doc.size_bytes / 1024).toFixed(1)} KB
                          </span>
                        </div>
                      );
                    })}

                    {/* Upload Dropzone */}
                    <label className="upload-dropzone">
                      <input type="file" accept=".pdf,.txt,.md" onChange={handleFileUpload} style={{ display: 'none' }} />
                      <div style={{ fontSize: '1.8rem', marginBottom: '6px' }}>📤</div>
                      <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-main)' }}>
                        Click to Upload New Policy Document (PDF, TXT, MD)
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                        Automatic semantic chunking & vector embedding will be performed.
                      </div>
                    </label>
                  </div>
                </div>

                {/* STEP 3: PARAMETERS & EXECUTION */}
                <div>
                  <div className="wizard-step-header">
                    <span className="wizard-step-number">3</span>
                    <div>
                      <div className="wizard-step-title">Configure Execution Parameters</div>
                      <div className="wizard-step-subtitle">Adjust clause extraction depth and launch autonomous multi-agent audit.</div>
                    </div>
                  </div>

                  <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '12px', padding: '20px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
                    <div className="form-group">
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <label className="form-label">Clause Extraction Depth</label>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--accent-cyan-light)' }}>
                          {studioMaxClauses} Clauses
                        </span>
                      </div>
                      <input
                        type="range"
                        min="3"
                        max="25"
                        value={studioMaxClauses}
                        onChange={e => setStudioMaxClauses(parseInt(e.target.value))}
                        disabled={isAuditing}
                      />
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                        <span>Fast (3 Clauses)</span>
                        <span>Standard (10 Clauses)</span>
                        <span>Comprehensive (25 Clauses)</span>
                      </div>
                    </div>

                    <button
                      className="btn btn-primary"
                      style={{ width: '100%', justifyContent: 'center', padding: '14px', fontSize: '1rem', fontWeight: 700 }}
                      onClick={launchAutonomousAudit}
                      disabled={isAuditing || user?.role === 'viewer'}
                    >
                      {isAuditing ? '⏳ Audit Execution Active (Telemetry Streaming Below)...' : '🚀 Launch Autonomous Multi-Agent Audit'}
                    </button>
                  </div>
                </div>

                {/* REAL-TIME AGENT TELEMETRY CONSOLE */}
                <div className="audit-telemetry-box">
                  <div className="telemetry-header">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span className="agent-pulse" style={{ background: isAuditing ? '#34D399' : '#64748B' }}></span>
                      <span style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-main)' }}>
                        Real-Time Multi-Agent Telemetry Stream
                      </span>
                      <span style={{ fontSize: '0.78rem', color: 'var(--accent-cyan-light)', fontFamily: 'var(--font-mono)' }}>
                        {isAuditing ? `[${auditProgress}% Active]` : '[Ready]'}
                      </span>
                    </div>

                    {/* Agent Activity Badges */}
                    <div className="telemetry-agents-row">
                      {[
                        'Orchestrator',
                        'ClauseExtractorAgent',
                        'EvidenceHunterAgent',
                        'ComplianceAuditorAgent',
                        'MatrixGeneratorAgent'
                      ].map(ag => (
                        <span key={ag} className={`agent-chip ${activeAgent.includes(ag.substring(0, 8)) ? 'active' : ''}`}>
                          {ag}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Progress Bar */}
                  <div className="progress-bar-container">
                    <div className="progress-bar-fill" style={{ width: `${auditProgress}%` }}></div>
                  </div>

                  {/* Streaming Log Output */}
                  <div className="agent-log-window">
                    {agentLogs.length === 0 ? (
                      <div style={{ color: 'var(--text-dim)', textAlign: 'center', margin: 'auto' }}>
                        Agent telemetry is idle. Launch an audit above to view live thought processes and semantic matches.
                      </div>
                    ) : (
                      agentLogs.map((log, i) => (
                        <div key={i} className="log-entry">
                          <span className="log-time">[{log.timestamp}]</span>
                          <span className="log-agent">{log.agent_name}:</span>
                          <span className="log-msg">{log.message}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

              </div>
            </div>
          )}

          {/* =========================================================================
            VIEW 3: COMPLIANCE MATRIX & TWO-PANE EVIDENCE INSPECTOR
            ========================================================================= */}
          {activeTab === 'matrix' && (
            <div className="workspace">

              {/* LEFT PANE: FINDINGS MATRIX LIST */}
              <div className="matrix-panel">
                <div className="panel-header">
                  <div className="panel-title">
                    <span>📋</span> Compliance Matrix ({filteredFindings.length})
                  </div>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                    {report?.audit_id}
                  </span>
                </div>

                {/* Filter & Search Bar */}
                <div className="filter-bar">
                  <input
                    type="text"
                    className="search-input"
                    placeholder="Search clause ID, title, or requirement..."
                    value={matrixSearch}
                    onChange={e => setMatrixSearch(e.target.value)}
                  />
                  <div className="filter-btn-group">
                    <button className={`filter-btn ${matrixFilter === 'ALL' ? 'active' : ''}`} onClick={() => setMatrixFilter('ALL')}>All</button>
                    <button className={`filter-btn ${matrixFilter === 'GAP' ? 'active' : ''}`} onClick={() => setMatrixFilter('GAP')}>🔴 Gaps</button>
                    <button className={`filter-btn ${matrixFilter === 'PARTIAL' ? 'active' : ''}`} onClick={() => setMatrixFilter('PARTIAL')}>🟡 Partial</button>
                    <button className={`filter-btn ${matrixFilter === 'COMPLIANT' ? 'active' : ''}`} onClick={() => setMatrixFilter('COMPLIANT')}>🟢 Compliant</button>
                    <button className={`filter-btn ${matrixFilter === 'VERIFIED' ? 'active' : ''}`} onClick={() => setMatrixFilter('VERIFIED')}>✓ Verified</button>
                  </div>
                </div>

                {/* Findings List */}
                <div className="findings-list">
                  {filteredFindings.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '48px 20px', color: 'var(--text-dim)' }}>
                      <div style={{ fontSize: '2rem', marginBottom: '8px' }}>🔍</div>
                      <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-main)' }}>No Matching Findings</div>
                      <div style={{ fontSize: '0.80rem', margin: '6px auto 14px', maxWidth: '280px', lineHeight: '1.4' }}>
                        {matrixSearch ? `No controls matched "${matrixSearch}".` : `No controls under filter "${matrixFilter}".`}
                      </div>
                      <button
                        className="btn btn-secondary"
                        style={{ fontSize: '0.78rem', padding: '6px 14px', margin: '0 auto' }}
                        onClick={() => { setMatrixSearch(''); setMatrixFilter('ALL'); }}
                      >
                        Reset Filter
                      </button>
                    </div>
                  ) : (
                    filteredFindings.map(f => {
                      const isSelected = selectedFinding?.clause_id === f.clause_id;
                      const badgeClass = f.status === 'Compliant' ? 'badge-compliant' :
                        f.status === 'Partially Compliant' ? 'badge-partial' : 'badge-non-compliant';
                      const riskClass = f.risk_level === 'Critical' ? 'risk-critical' :
                        f.risk_level === 'High' ? 'risk-high' :
                          f.risk_level === 'Medium' ? 'risk-medium' : 'risk-low';

                      return (
                        <div
                          key={f.clause_id}
                          className={`finding-row ${isSelected ? 'selected' : ''}`}
                          onClick={() => setSelectedFinding(f)}
                        >
                          <div className="finding-header-row">
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <span className="clause-tag-pill">{f.clause_id}</span>
                              <span className={`risk-tag ${riskClass}`}>{f.risk_level}</span>
                              {f.is_verified && (
                                <span style={{ fontSize: '0.72rem', color: '#10B981', fontWeight: 700 }} title="Verified by Lead Auditor">
                                  ✓ Verified
                                </span>
                              )}
                            </div>
                            <span className={`badge ${badgeClass}`}>{f.status}</span>
                          </div>

                          <div className="finding-title">{f.clause_title}</div>
                          <div className="finding-req">{f.requirement_summary}</div>

                          <div className="finding-footer-row">
                            <div style={{ display: 'flex', gap: '6px' }}>
                              {(f.citations || []).map((c, i) => (
                                <span key={i} className="citation-chip">
                                  📄 {c.document_name ? c.document_name.substring(0, 15) : 'Doc'} : P.{c.page_number}
                                </span>
                              ))}
                            </div>
                            <span className="inspect-chevron">Inspect Evidence →</span>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

              {/* RIGHT PANE: DEEP EVIDENCE & AUDITOR GOVERNANCE INSPECTOR */}
              <div className="evidence-panel">
                <div className="panel-header">
                  <div className="panel-title">
                    <span>🔍</span> Deep Evidence & Governance Inspector
                  </div>
                  {selectedFinding && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="badge" style={{ background: 'var(--bg-card)', color: 'var(--accent-cyan-light)', border: '1px solid var(--border-subtle)' }}>
                        Risk: {selectedFinding.risk_level}
                      </span>
                      {selectedFinding.is_verified && (
                        <span className="badge badge-compliant">Auditor Verified</span>
                      )}
                    </div>
                  )}
                </div>

                <div className="evidence-content">
                  {selectedFinding ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

                      {/* Clause Mandate Header */}
                      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '12px', padding: '18px 22px' }}>
                        <div style={{ fontSize: '0.76rem', fontWeight: 700, color: 'var(--accent-cyan-light)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                          Regulatory Clause Requirement • {selectedFinding.clause_id}
                        </div>
                        <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-main)', marginTop: '4px' }}>
                          {selectedFinding.clause_title}
                        </h3>
                        <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)', lineHeight: '1.6', marginTop: '8px' }}>
                          {selectedFinding.requirement_summary}
                        </p>
                      </div>

                      {/* Policy Evidence Card */}
                      <div className="doc-quote-card">
                        <div className="doc-quote-meta">
                          FOUND POLICY EVIDENCE | SOURCE: {selectedFinding.citations?.[0]?.document_name || 'Enterprise Policy'} (Page {selectedFinding.citations?.[0]?.page_number || 'N/A'})
                        </div>
                        <div className="doc-quote-text">
                          "{selectedFinding.evidence_found || 'No formal policy statements detected in document.'}"
                        </div>
                      </div>

                      {/* Gap Analysis Box */}
                      <div className="gap-box">
                        <div className="gap-title">⚠️ Identified Compliance Gap / Ambiguity</div>
                        <div style={{ fontSize: '0.88rem', color: '#FECACA', lineHeight: '1.5' }}>
                          {selectedFinding.gap_analysis || 'No compliance gap identified.'}
                        </div>
                      </div>

                      {/* Prescriptive Remediation Box */}
                      <div className="fix-box">
                        <div className="fix-title">💡 Prescribed Engineering Remediation</div>
                        <div style={{ fontSize: '0.88rem', color: '#D1FAE5', lineHeight: '1.5' }}>
                          {selectedFinding.remediation_recommendation || 'Maintain current policy enforcement.'}
                        </div>
                      </div>

                      {/* Auditor Governance & Override Review Card */}
                      <div className="auditor-review-card">
                        <div className="auditor-review-title">
                          <span>🛡️</span> Auditor Review & Governance Override
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                          <div className="form-group">
                            <label className="form-label">Compliance Status Override</label>
                            <select
                              className="form-input"
                              value={editStatus}
                              onChange={e => setEditStatus(e.target.value)}
                              disabled={user?.role === 'viewer'}
                            >
                              <option value="Compliant">Compliant</option>
                              <option value="Partially Compliant">Partially Compliant</option>
                              <option value="Non-Compliant">Non-Compliant</option>
                            </select>
                          </div>

                          <div className="form-group">
                            <label className="form-label">Remediation Status</label>
                            <select
                              className="form-input"
                              value={editRemediationStatus}
                              onChange={e => setEditRemediationStatus(e.target.value)}
                              disabled={user?.role === 'viewer'}
                            >
                              <option value="Open">Open</option>
                              <option value="In Progress">In Progress</option>
                              <option value="Under Review">Under Review</option>
                              <option value="Resolved">Resolved</option>
                            </select>
                          </div>
                        </div>

                        <div className="form-group">
                          <label className="form-label">Assigned Remediation Owner</label>
                          <input
                            type="text"
                            className="form-input"
                            value={editOwner}
                            onChange={e => setEditOwner(e.target.value)}
                            placeholder="e.g. SecOps Lead / Jane Doe"
                            disabled={user?.role === 'viewer'}
                          />
                        </div>

                        <div className="form-group">
                          <label className="form-label">Auditor Governance Notes</label>
                          <textarea
                            className="form-input"
                            rows="3"
                            value={editNotes}
                            onChange={e => setEditNotes(e.target.value)}
                            placeholder="Add auditor observations, verified compensating controls, or follow-up milestones..."
                            disabled={user?.role === 'viewer'}
                            style={{ resize: 'vertical' }}
                          />
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '6px' }}>
                          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '0.86rem', color: 'var(--text-main)', fontWeight: 600 }}>
                            <input
                              type="checkbox"
                              checked={editVerified}
                              onChange={e => setEditVerified(e.target.checked)}
                              disabled={user?.role === 'viewer'}
                            />
                            Mark Finding as Verified by Auditor
                          </label>

                          <button
                            className="btn btn-primary"
                            onClick={saveAuditorReview}
                            disabled={isSavingReview || user?.role === 'viewer'}
                            style={{ padding: '8px 18px', fontSize: '0.84rem' }}
                          >
                            {isSavingReview ? 'Saving...' : '💾 Save Review'}
                          </button>
                        </div>
                      </div>

                    </div>
                  ) : (
                    <div style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '60px 0' }}>
                      Select a regulatory clause on the left to inspect evidence, gap analysis, and auditor actions.
                    </div>
                  )}
                </div>
              </div>

            </div>
          )}

          {/* =========================================================================
            VIEW 4: STANDARDS CATALOG
            ========================================================================= */}
          {activeTab === 'standards' && (
            <div className="view-container">

              <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '16px' }}>
                <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-main)' }}>
                  📚 Pre-Seeded Regulatory Standards & Frameworks
                </h2>
                <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                  AegisAudit AI includes curated, pre-seeded compliance frameworks ready for instant zero-setup evaluation.
                </p>
              </div>

              <div className="standards-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))' }}>
                {(standardsCatalog.length > 0 ? standardsCatalog : [
                  {
                    key: 'iso_27001_2022',
                    title: 'ISO/IEC 27001:2022',
                    full_name: 'Information Security Management System (ISMS)',
                    badge: 'International Standard',
                    clause_count: 93,
                    description: 'Global benchmark for establishing, implementing, maintaining and continually improving an information security management system.',
                    key_controls: ['A.5.15 Access Control', 'A.8.5 Secure Authentication & MFA', 'A.8.8 Vulnerability Management', 'A.8.20 Network Security']
                  },
                  {
                    key: 'soc_2_type_ii',
                    title: 'SOC 2 Type II',
                    full_name: 'Trust Services Criteria for Security & Confidentiality',
                    badge: 'AICPA Standard',
                    clause_count: 64,
                    description: 'Rigorous audit standard evaluating controls relevant to security, availability, processing integrity, confidentiality, and privacy.',
                    key_controls: ['CC6.1 Logical Access Controls', 'CC6.6 Network Boundary Protections', 'CC7.1 Vulnerability Detection', 'CC8.1 Change Management']
                  },
                  {
                    key: 'gdpr_compliance',
                    title: 'GDPR Article 32',
                    full_name: 'Security of Processing Personal Data',
                    badge: 'EU Regulation',
                    clause_count: 18,
                    description: 'Mandates technical and organizational measures to ensure data protection, pseudonymization, encryption, and regular security testing.',
                    key_controls: ['Art. 32(1)(a) Encryption & Pseudonymisation', 'Art. 32(1)(b) Confidentiality & Integrity', 'Art. 32(1)(d) Regular Security Testing']
                  },
                  {
                    key: 'nist_csf_2_0',
                    title: 'NIST CSF 2.0',
                    full_name: 'NIST Cybersecurity Framework 2.0',
                    badge: 'Federal Framework',
                    clause_count: 106,
                    description: 'Comprehensive guidelines across Govern, Identify, Protect, Detect, Respond, and Recover to manage cybersecurity risks.',
                    key_controls: ['GV.OC-01 Organizational Context', 'PR.AA-01 Identity & Access', 'DE.CM-01 Continuous Monitoring', 'RS.MA-01 Incident Execution']
                  }
                ]).map(std => (
                  <div key={std.key} className="standard-card">
                    <div>
                      <div className="standard-card-header">
                        <div>
                          <div className="standard-card-title">{std.title}</div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginTop: '2px' }}>{std.full_name}</div>
                        </div>
                        <span className="standard-badge">{std.badge || 'Standard'}</span>
                      </div>

                      <p className="standard-card-desc" style={{ marginTop: '12px' }}>
                        {std.description}
                      </p>

                      <div style={{ marginTop: '14px' }}>
                        <div style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                          Key Controls Included:
                        </div>
                        <div className="standard-controls-list">
                          {(std.key_controls || []).map((ctrl, i) => (
                            <span key={i} className="standard-control-pill">{ctrl}</span>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '14px', paddingTop: '12px', borderTop: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                        {std.clause_count || 50}+ Regulatory Controls
                      </span>
                      <button
                        className="btn btn-primary"
                        style={{ padding: '6px 14px', fontSize: '0.78rem' }}
                        onClick={() => {
                          setStudioStandardKey(std.key);
                          setActiveTab('studio');
                        }}
                      >
                        Audit With This Standard →
                      </button>
                    </div>
                  </div>
                ))}
              </div>

            </div>
          )}

          {/* =========================================================================
            VIEW 5: COMPLIANCE DIFF & BENCHMARKING
            ========================================================================= */}
          {activeTab === 'diff' && (
            <div className="view-container">
              <div className="diff-container" style={{ width: '100%', margin: '0 auto' }}>

                <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '16px' }}>
                  <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-main)' }}>
                    🔀 Compliance Diff & Historical Benchmarking
                  </h2>
                  <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Compare two audit runs to evaluate remediation progress, track resolved compliance gaps, and catch regressions.
                  </p>
                </div>

                {/* Audit Selection Row */}
                <div className="diff-selectors-row">
                  <div className="form-group" style={{ flex: 1 }}>
                    <label className="form-label">Baseline Audit (Before)</label>
                    <select
                      className="form-input"
                      value={diffBaselineId}
                      onChange={e => setDiffBaselineId(e.target.value)}
                    >
                      <option value="">Select Baseline Run...</option>
                      {pastAudits.map(a => (
                        <option key={a.audit_id} value={a.audit_id}>
                          {a.audit_id} - {a.standard_name} ({a.compliance_pct}%) [{a.timestamp}]
                        </option>
                      ))}
                    </select>
                  </div>

                  <div style={{ fontSize: '1.5rem', color: 'var(--accent-cyan-light)', marginTop: '20px' }}>
                    ➔
                  </div>

                  <div className="form-group" style={{ flex: 1 }}>
                    <label className="form-label">Target Audit (After)</label>
                    <select
                      className="form-input"
                      value={diffTargetId}
                      onChange={e => setDiffTargetId(e.target.value)}
                    >
                      <option value="">Select Target Run...</option>
                      {pastAudits.map(a => (
                        <option key={a.audit_id} value={a.audit_id}>
                          {a.audit_id} - {a.standard_name} ({a.compliance_pct}%) [{a.timestamp}]
                        </option>
                      ))}
                    </select>
                  </div>

                  <button
                    className="btn btn-primary"
                    style={{ height: '42px', marginTop: '24px', padding: '0 20px' }}
                    onClick={runDiffComparison}
                    disabled={isDiffLoading}
                  >
                    {isDiffLoading ? 'Comparing...' : 'Run Diff Analysis'}
                  </button>
                </div>

                {/* Diff Results Display */}
                {diffResult ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

                    {/* Metric Delta Cards */}
                    <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                      <div className="diff-stat-card">
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Posture Delta</div>
                        <div className="diff-stat-val" style={{ color: diffResult.score_delta >= 0 ? 'var(--status-compliant)' : 'var(--status-non-compliant)' }}>
                          {diffResult.score_delta >= 0 ? `+${diffResult.score_delta}%` : `${diffResult.score_delta}%`}
                        </div>
                        <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                          {diffResult.baseline_score}% ➔ {diffResult.target_score}%
                        </div>
                      </div>

                      <div className="diff-stat-card">
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Resolved Gaps</div>
                        <div className="diff-stat-val" style={{ color: 'var(--status-compliant)' }}>
                          {diffResult.resolved_gaps_count}
                        </div>
                        <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '4px' }}>Successfully Remediated</div>
                      </div>

                      <div className="diff-stat-card">
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>New Gaps</div>
                        <div className="diff-stat-val" style={{ color: 'var(--status-non-compliant)' }}>
                          {diffResult.new_gaps_count}
                        </div>
                        <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '4px' }}>Requires Attention</div>
                      </div>

                      <div className="diff-stat-card">
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Unchanged Controls</div>
                        <div className="diff-stat-val" style={{ color: 'var(--accent-cyan-light)' }}>
                          {diffResult.unchanged_count}
                        </div>
                        <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '4px' }}>Stable Alignment</div>
                      </div>
                    </div>

                    {/* Resolved Gaps List */}
                    {diffResult.resolved_gaps?.length > 0 && (
                      <div style={{ background: 'var(--bg-card)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '12px', padding: '20px' }}>
                        <h4 style={{ color: 'var(--status-compliant)', fontSize: '0.95rem', fontWeight: 700, marginBottom: '10px' }}>
                          🎉 Resolved Gaps ({diffResult.resolved_gaps.length})
                        </h4>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                          {diffResult.resolved_gaps.map((item, i) => (
                            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.84rem' }}>
                              <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{item.clause_id}: {item.title}</span>
                              <span className="badge badge-compliant">Improved: {item.old_status} ➔ {item.new_status}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* New Regressions List */}
                    {diffResult.new_gaps?.length > 0 && (
                      <div style={{ background: 'var(--bg-card)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '12px', padding: '20px' }}>
                        <h4 style={{ color: 'var(--status-non-compliant)', fontSize: '0.95rem', fontWeight: 700, marginBottom: '10px' }}>
                          ⚠️ Newly Introduced Gaps ({diffResult.new_gaps.length})
                        </h4>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                          {diffResult.new_gaps.map((item, i) => (
                            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.84rem' }}>
                              <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{item.clause_id}: {item.title}</span>
                              <span className="badge badge-non-compliant">Regressed: {item.new_status}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  </div>
                ) : (
                  <div style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '60px 0' }}>
                    Select baseline and target runs above and click <strong>Run Diff Analysis</strong> to see progression.
                  </div>
                )}

              </div>
            </div>
          )}

          {/* =========================================================================
            VIEW 6: REPORTS & EXPORT CENTER
            ========================================================================= */}
          {activeTab === 'exports' && (
            <div className="view-container">

              <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-main)' }}>
                      📥 Reports & Governance Export Center
                    </h2>
                    <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                      One-click export tools for executive distributions, engineering task trackers, and compliance archives.
                    </p>
                  </div>
                  <span className="badge" style={{ background: 'var(--bg-card)', color: 'var(--accent-cyan-light)', padding: '6px 14px', fontSize: '0.8rem' }}>
                    Target: {report?.audit_id}
                  </span>
                </div>
              </div>

              <div className="export-grid">

                {/* PDF Export Card */}
                <div className="export-card">
                  <div>
                    <div className="export-card-icon">📄</div>
                    <div className="export-card-title">Executive PDF Report</div>
                    <div className="export-card-desc">
                      Publication-ready executive compliance report with SHA-256 cryptographic seal, executive summaries, and clause finding breakdowns.
                    </div>
                  </div>
                  <button className="btn btn-primary" onClick={() => triggerDownload('pdf')}>
                    Download Sealed PDF
                  </button>
                </div>

                {/* Jira / Linear Tasks CSV */}
                <div className="export-card">
                  <div>
                    <div className="export-card-icon">🎯</div>
                    <div className="export-card-title">Jira / Linear Tasks CSV</div>
                    <div className="export-card-desc">
                      Actionable CSV file formatted for direct import into Jira, Linear, or Asana with severity, remediation owners, and fix steps.
                    </div>
                  </div>
                  <button className="btn btn-secondary" onClick={() => triggerDownload('tasks')}>
                    Download Jira Tasks CSV
                  </button>
                </div>

                {/* Compliance Matrix CSV */}
                <div className="export-card">
                  <div>
                    <div className="export-card-icon">📊</div>
                    <div className="export-card-title">Compliance Matrix CSV</div>
                    <div className="export-card-desc">
                      Full spreadsheet export containing all audited clauses, citations, found evidence text, risk ratings, and compliance statuses.
                    </div>
                  </div>
                  <button className="btn btn-secondary" onClick={() => triggerDownload('csv')}>
                    Download Full Matrix CSV
                  </button>
                </div>

                {/* Markdown Wiki Export */}
                <div className="export-card">
                  <div>
                    <div className="export-card-icon">📝</div>
                    <div className="export-card-title">Executive Markdown</div>
                    <div className="export-card-desc">
                      Clean GitHub-flavored markdown document with formatted tables and quotes, suitable for internal documentation wikis.
                    </div>
                  </div>
                  <button className="btn btn-secondary" onClick={() => triggerDownload('markdown')}>
                    Download Markdown (.md)
                  </button>
                </div>

              </div>

              {/* Cryptographic Verification Seal Box */}
              <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', borderRadius: '14px', padding: '20px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span>🔒</span> Cryptographic Audit Trail Assurance
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    All PDF reports generated by AegisAudit AI incorporate an SHA-256 audit digest to ensure immutable chain-of-custody.
                  </div>
                </div>
                <span className="badge badge-compliant" style={{ fontFamily: 'var(--font-mono)' }}>
                  SHA-256 VERIFIED
                </span>
              </div>

            </div>
          )}

        </main>
      </div>

      {/* AUTHENTICATION MODAL */}
      {showAuthModal && (
        <div className="modal-overlay" onClick={() => setShowAuthModal(false)}>
          <div className="modal-dialog" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)' }}>
                {authMode === 'login' ? '🔐 Sign In to AegisAudit' : '📝 Create Organization Account'}
              </h3>
              <button className="btn btn-ghost" onClick={() => setShowAuthModal(false)}>✕</button>
            </div>

            <form className="modal-body" onSubmit={authMode === 'login' ? handleLogin : handleRegister}>
              {authMode === 'register' && (
                <>
                  <div className="form-group">
                    <label className="form-label">Full Name</label>
                    <input
                      type="text"
                      className="form-input"
                      value={authName}
                      onChange={e => setAuthName(e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Organization Role</label>
                    <select
                      className="form-input"
                      value={authRole}
                      onChange={e => setAuthRole(e.target.value)}
                    >
                      <option value="admin">Administrator (Full Control)</option>
                      <option value="auditor">Lead Auditor (Review & Run Audits)</option>
                      <option value="viewer">Viewer (Read-Only Reports)</option>
                    </select>
                  </div>
                </>
              )}

              <div className="form-group">
                <label className="form-label">Work Email</label>
                <input
                  type="email"
                  className="form-input"
                  value={authEmail}
                  onChange={e => setAuthEmail(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Password</label>
                <input
                  type="password"
                  className="form-input"
                  value={authPass}
                  onChange={e => setAuthPass(e.target.value)}
                  required
                />
              </div>

              {/* Demo Helper Pill */}
              <div
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  padding: '10px 14px',
                  fontSize: '0.78rem',
                  color: 'var(--accent-cyan-light)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between'
                }}
                onClick={() => {
                  setAuthEmail('admin@aegisaudit.com');
                  setAuthPass('AdminPass123!');
                  showToast('Filled default Admin credentials');
                }}
              >
                <span>💡 Click to Fill Demo Admin Credentials</span>
                <span style={{ fontWeight: 700 }}>Auto-Fill →</span>
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                style={{ width: '100%', justifyContent: 'center', marginTop: '6px' }}
              >
                {authMode === 'login' ? 'Sign In to Workspace' : 'Create Account & Continue'}
              </button>

              <div style={{ textAlign: 'center', fontSize: '0.8rem', color: 'var(--text-dim)', marginTop: '6px' }}>
                {authMode === 'login' ? (
                  <span>Need an account? <a href="#register" onClick={(e) => { e.preventDefault(); setAuthMode('register'); }} style={{ color: 'var(--accent-cyan-light)' }}>Register here</a></span>
                ) : (
                  <span>Already registered? <a href="#login" onClick={(e) => { e.preventDefault(); setAuthMode('login'); }} style={{ color: 'var(--accent-cyan-light)' }}>Sign in here</a></span>
                )}
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}

// Mount Pure React Application
const rootElement = document.getElementById('root');
if (rootElement) {
  const root = ReactDOM.createRoot(rootElement);
  root.render(<App />);
}
