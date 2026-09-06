// OT-BASE Asset Center Frontend Application Logic

let currentFacility = "Municipal Water Treatment Facility";
let currentAssets = [];
let currentChassisAsset = null;
let currentTopology = null;

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initFacilitySelector();
    loadDashboard();
    initDropzone();
});

// Tab Management
function initTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-tab");
            switchTab(targetId);
        });
    });
}

function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

    const activeBtn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
    const activePane = document.getElementById(tabId);
    if (activeBtn) activeBtn.classList.add("active");
    if (activePane) activePane.classList.add("active");

    // Lazy load tab data
    if (tabId === "tab-dashboard") loadDashboard();
    if (tabId === "tab-assets") loadAssets();
    if (tabId === "tab-chassis") loadChassisView();
    if (tabId === "tab-topology") loadTopology();
    if (tabId === "tab-vulns") loadVulnerabilities();
    if (tabId === "tab-lifecycle") loadLifecycle();
    if (tabId === "tab-compliance") loadCompliance();
}

// Facility / Scenario Selector
async function initFacilitySelector() {
    const select = document.getElementById("facility-select");
    try {
        const res = await fetch("/api/scenarios");
        const scenarios = await res.json();
        select.innerHTML = scenarios.map(s => 
            `<option value="${s.id}">${s.name}</option>`
        ).join("");

        select.addEventListener("change", async (e) => {
            const scenarioId = e.target.value;
            await fetch(`/api/scenarios/${scenarioId}`, { method: "POST" });
            showToast(`Loaded scenario: ${e.target.options[e.target.selectedIndex].text}`);
            // Reload active tab
            const activeTab = document.querySelector(".tab-btn.active").getAttribute("data-tab");
            switchTab(activeTab);
        });
    } catch (err) {
        console.error("Failed to load scenarios:", err);
    }
}

// ============================================================================
// 1. DASHBOARD
// ============================================================================
async function loadDashboard() {
    try {
        const res = await fetch("/api/dashboard");
        const data = await res.json();

        currentFacility = data.active_facility;
        document.getElementById("dash-facility-name").textContent = data.active_facility;
        document.getElementById("kpi-total-assets").textContent = data.total_assets;
        document.getElementById("kpi-avg-risk").textContent = data.avg_ot_risk_score;
        document.getElementById("kpi-total-cves").textContent = data.total_cves;
        document.getElementById("kpi-violations").textContent = data.total_violations;
        document.getElementById("kpi-eol").textContent = data.eol_hardware_count;
        document.getElementById("kpi-compliance").textContent = `${data.compliance_score}%`;

        // Render Top Riskiest Assets
        const tbody = document.getElementById("top-risky-body");
        tbody.innerHTML = data.top_risky_assets.map(a => `
            <tr>
                <td><strong>${a.tag}</strong></td>
                <td>${a.name}</td>
                <td><span class="badge badge-blue">${a.level.split(" - ")[0]}</span></td>
                <td>${a.vendor}</td>
                <td>
                    <span class="badge ${a.ot_risk_score >= 8.0 ? 'badge-red' : (a.ot_risk_score >= 5.0 ? 'badge-amber' : 'badge-green')}">
                        ${a.ot_risk_score} / 10.0
                    </span>
                </td>
                <td>
                    ${a.active_cves.length > 0 
                        ? a.active_cves.map(c => `<span class="badge badge-red" style="margin-right:4px;">${c}</span>`).join("")
                        : '<span class="badge badge-gray">None</span>'}
                </td>
                <td>
                    <button class="btn btn-secondary" onclick="inspectAsset('${a.id}')">Inspect</button>
                </td>
            </tr>
        `).join("");

        // Render Purdue Distribution Bar
        renderDistributionBars("purdue-bars", data.purdue_distribution, "Purdue Distribution");
        renderDistributionBars("vuln-bars", data.cve_severity_distribution, "CVE Severity");
    } catch (err) {
        console.error("Error loading dashboard:", err);
    }
}

function renderDistributionBars(containerId, dataObj, title) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const total = Object.values(dataObj).reduce((a, b) => a + b, 0);
    if (total === 0) {
        container.innerHTML = `<p style="color:var(--text-muted);font-size:0.8rem;">No data available</p>`;
        return;
    }

    container.innerHTML = Object.entries(dataObj).map(([key, val]) => {
        const pct = Math.round((val / total) * 100);
        return `
            <div style="margin-bottom:0.6rem;">
                <div style="display:flex;justify-content:space-between;font-size:0.75rem;margin-bottom:0.2rem;">
                    <span>${key}</span>
                    <span style="font-weight:700;">${val} (${pct}%)</span>
                </div>
                <div style="width:100%;background-color:rgba(255,255,255,0.08);height:8px;border-radius:4px;overflow:hidden;">
                    <div style="width:${pct}%;background-color:var(--accent-cyan);height:100%;"></div>
                </div>
            </div>
        `;
    }).join("");
}

// ============================================================================
// 2. ASSETS INVENTORY
// ============================================================================
async function loadAssets() {
    try {
        const res = await fetch("/api/assets");
        currentAssets = await res.json();
        renderAssetsTable(currentAssets);
    } catch (err) {
        console.error("Error loading assets:", err);
    }
}

function renderAssetsTable(assets) {
    const tbody = document.getElementById("assets-table-body");
    tbody.innerHTML = assets.map(a => {
        const ip = a.network_interfaces && a.network_interfaces.length > 0 ? a.network_interfaces[0].ip_address : "N/A";
        const hasChassis = a.chassis && a.chassis.modules && a.chassis.modules.length > 0;
        
        return `
            <tr>
                <td><strong>${a.tag_name}</strong></td>
                <td>${a.display_name}</td>
                <td><span class="badge badge-blue">${a.purdue_level.split(" - ")[0]}</span></td>
                <td>${a.vendor}</td>
                <td>${a.model}</td>
                <td><code>${a.firmware_version || 'N/A'}</code></td>
                <td><code>${ip}</code></td>
                <td>
                    <select class="filter-select" onchange="changeKeySwitch('${a.id}', this.value)" style="font-size:0.75rem;padding:0.2rem 0.4rem;">
                        <option value="RUN" ${a.key_switch.startsWith("RUN") ? "selected" : ""}>RUN (Locked)</option>
                        <option value="REMOTE_RUN" ${a.key_switch.startsWith("REM") ? "selected" : ""}>REM (Remote)</option>
                        <option value="PROG" ${a.key_switch.startsWith("PROG") ? "selected" : ""}>PROG (Halt)</option>
                        <option value="NOT_APPLICABLE" ${a.key_switch === "N/A" ? "selected" : ""}>N/A</option>
                    </select>
                </td>
                <td>
                    <span class="badge ${a.ot_risk_score >= 8.0 ? 'badge-red' : (a.ot_risk_score >= 5.0 ? 'badge-amber' : 'badge-green')}">
                        ${a.ot_risk_score}
                    </span>
                </td>
                <td>
                    ${hasChassis ? `
                        <button class="btn btn-primary" onclick="viewChassis('${a.id}')" style="font-size:0.75rem;padding:0.25rem 0.6rem;">
                            View Rack (${a.chassis.modules.length} slots)
                        </button>
                    ` : '<span style="color:var(--text-muted);font-size:0.75rem;">Standalone</span>'}
                </td>
            </tr>
        `;
    }).join("");
}

function filterAssets() {
    const q = document.getElementById("asset-search-input").value.toLowerCase();
    const plevel = document.getElementById("asset-purdue-filter").value;
    const vendor = document.getElementById("asset-vendor-filter").value;

    let filtered = currentAssets.filter(a => {
        const matchesQuery = !q || (
            a.tag_name.toLowerCase().includes(q) ||
            a.display_name.toLowerCase().includes(q) ||
            a.model.toLowerCase().includes(q) ||
            a.vendor.toLowerCase().includes(q)
        );
        const matchesLevel = !plevel || a.purdue_level.includes(plevel);
        const matchesVendor = !vendor || a.vendor.toLowerCase().includes(vendor.toLowerCase());
        return matchesQuery && matchesLevel && matchesVendor;
    });
    renderAssetsTable(filtered);
}

async function changeKeySwitch(assetId, mode) {
    try {
        const res = await fetch(`/api/assets/${assetId}/keyswitch?mode=${mode}`, { method: "PUT" });
        const data = await res.json();
        showToast(data.message);
        loadAssets();
    } catch (err) {
        console.error("Failed to update key switch:", err);
    }
}

// ============================================================================
// 3. RACK & CHASSIS BACKPLANE EXPLORER (SIGNATURE OT-BASE FEATURE)
// ============================================================================
async function loadChassisView(assetId = null) {
    try {
        if (!assetId) {
            // Pick first asset with chassis
            const res = await fetch("/api/assets");
            const assets = await res.json();
            const modular = assets.find(a => a.chassis && a.chassis.modules && a.chassis.modules.length > 0);
            if (modular) assetId = modular.id;
        }

        if (!assetId) {
            document.getElementById("chassis-content").innerHTML = `
                <div style="padding:2rem;text-align:center;color:var(--text-muted);">
                    No modular rack chassis found in this facility.
                </div>
            `;
            return;
        }

        const res = await fetch(`/api/chassis/${assetId}`);
        const data = await res.json();
        currentChassisAsset = data;
        renderChassis(data);
    } catch (err) {
        console.error("Error loading chassis:", err);
    }
}

function viewChassis(assetId) {
    switchTab("tab-chassis");
    loadChassisView(assetId);
}

function renderChassis(data) {
    const container = document.getElementById("chassis-content");
    const chassis = data.chassis;
    const modulesMap = {};
    chassis.modules.forEach(m => { modulesMap[m.slot] = m; });

    let slotsHtml = "";
    for (let slotIdx = 0; slotIdx < chassis.total_slots; slotIdx++) {
        const mod = modulesMap[slotIdx];
        if (mod) {
            const hasCve = mod.cve_count > 0;
            const ledsHtml = mod.status_leds.map(led => `
                <div class="led-item">
                    <div class="led-bulb ${led.state}"></div>
                    <span>${led.name}</span>
                </div>
            `).join("");

            slotsHtml += `
                <div class="chassis-slot" onclick="inspectModule(${slotIdx})">
                    <span class="slot-number-badge">SLOT ${mod.slot}</span>
                    <div>
                        <div class="slot-type-indicator" style="color:var(--accent-cyan);">${mod.module_type}</div>
                        <div class="slot-cat">${mod.catalog_number}</div>
                        <div class="slot-name">${mod.name}</div>
                        <div class="slot-firmware">FW: ${mod.firmware_version}</div>
                    </div>
                    <div class="slot-leds">
                        ${ledsHtml}
                    </div>
                    ${hasCve ? `
                        <div class="slot-cve-badge">
                            ⚠️ ${mod.cve_count} Vulnerability
                        </div>
                    ` : '<div style="font-size:0.65rem;color:var(--accent-green);font-weight:700;margin-top:auto;text-align:center;">✓ SECURE</div>'}
                </div>
            `;
        } else {
            slotsHtml += `
                <div class="chassis-slot slot-empty">
                    <span class="slot-number-badge">SLOT ${slotIdx}</span>
                    <div style="margin:auto;text-align:center;color:var(--text-muted);font-size:0.75rem;font-weight:600;">
                        [ EMPTY SLOT ]
                    </div>
                </div>
            `;
        }
    }

    container.innerHTML = `
        <div class="chassis-container">
            <div class="chassis-header-bar">
                <div>
                    <div class="chassis-title">RACK CHASSIS: ${data.asset_tag} (${chassis.model})</div>
                    <div style="font-size:0.8rem;color:var(--text-secondary);">
                        Serial Number: <code>${chassis.serial_number || 'N/A'}</code> | Total Capacity: ${chassis.total_slots} Slots | Occupied: ${chassis.modules.length} Modules
                    </div>
                </div>
                <div>
                    <button class="btn btn-secondary" onclick="exportChassisHBOM()">Export Rack HBOM</button>
                </div>
            </div>
            <div class="chassis-rack">
                ${slotsHtml}
            </div>
            <div id="module-detail-drawer" style="margin-top:1rem;display:none;"></div>
        </div>
    `;
}

function inspectModule(slotIdx) {
    if (!currentChassisAsset) return;
    const mod = currentChassisAsset.chassis.modules.find(m => m.slot === slotIdx);
    if (!mod) return;

    const drawer = document.getElementById("module-detail-drawer");
    drawer.style.display = "block";
    drawer.innerHTML = `
        <div class="card" style="margin-top:1rem;border-color:var(--accent-cyan);">
            <div class="card-header">
                <div class="card-title">
                    🔍 Slot ${mod.slot}: ${mod.name} [${mod.catalog_number}]
                </div>
                <button class="close-btn" onclick="document.getElementById('module-detail-drawer').style.display='none'">&times;</button>
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:1rem;font-size:0.85rem;">
                <div>
                    <span style="color:var(--text-muted);">Vendor:</span>
                    <div><strong>${mod.vendor}</strong></div>
                </div>
                <div>
                    <span style="color:var(--text-muted);">Catalog / Part Number:</span>
                    <div><code>${mod.catalog_number}</code></div>
                </div>
                <div>
                    <span style="color:var(--text-muted);">Serial Number:</span>
                    <div><code>${mod.serial_number || 'N/A'}</code></div>
                </div>
                <div>
                    <span style="color:var(--text-muted);">Hardware Revision:</span>
                    <div><strong>Revision ${mod.hardware_revision || 'A'}</strong></div>
                </div>
                <div>
                    <span style="color:var(--text-muted);">Firmware Version:</span>
                    <div><strong style="color:#38bdf8;">${mod.firmware_version}</strong></div>
                </div>
                <div>
                    <span style="color:var(--text-muted);">Module Type:</span>
                    <div>${mod.module_type}</div>
                </div>
            </div>
            <div style="margin-top:1rem;font-size:0.85rem;">
                <span style="color:var(--text-muted);">Description:</span>
                <div>${mod.description || 'Standard industrial backplane module.'}</div>
            </div>
            ${mod.cves && mod.cves.length > 0 ? `
                <div style="margin-top:1rem;padding:0.75rem;background-color:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:6px;">
                    <strong style="color:#f87171;">Matched Slot Vulnerabilities:</strong>
                    <div style="margin-top:0.35rem;">
                        ${mod.cves.map(c => `<span class="badge badge-red" style="margin-right:6px;">${c}</span>`).join("")}
                    </div>
                </div>
            ` : '<div style="margin-top:1rem;color:var(--accent-green);font-size:0.85rem;">✓ No known firmware advisories for this slot.</div>'}
        </div>
    `;
}

// ============================================================================
// 4. PURDUE NETWORK & ZONE VISUALIZER
// ============================================================================
async function loadTopology() {
    try {
        const res = await fetch("/api/topology");
        currentTopology = await res.json();
        renderTopology(currentTopology);
    } catch (err) {
        console.error("Error loading topology:", err);
    }
}

function renderTopology(topo) {
    const container = document.getElementById("topology-view");
    
    // Violations List
    let violationsHtml = "";
    if (topo.violations && topo.violations.length > 0) {
        violationsHtml = topo.violations.map(v => `
            <div class="violation-banner">
                <div style="font-size:1.5rem;">⚠️</div>
                <div style="flex:1;">
                    <div class="violation-title">${v.title} [${v.severity}]</div>
                    <div class="violation-desc">${v.description}</div>
                    <div class="violation-rem"><strong>Remediation:</strong> ${v.remediation} (${v.standard_reference})</div>
                </div>
            </div>
        `).join("");
    } else {
        violationsHtml = `<div class="badge badge-green" style="margin-bottom:1rem;">✓ Zero Purdue Segmentation Violations Detected</div>`;
    }

    // Purdue Levels Breakdown
    const purdueLevels = [
        "Level 3.5 - Industrial DMZ (IDMZ)",
        "Level 3 - Operations & Historians",
        "Level 2 - Supervisory / HMIs",
        "Level 1 - Basic Control (PLCs/RTUs)",
        "Level 0 - Process / Field"
    ];

    let levelsHtml = purdueLevels.map(lvl => {
        const zones = topo.zones.filter(z => z.purdue_level === lvl);
        const assets = topo.assets.filter(a => a.purdue_level === lvl);

        return `
            <div style="background-color:rgba(15,23,42,0.6);border:1px solid var(--border-color);border-radius:8px;padding:1rem;margin-bottom:1rem;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
                    <span style="font-weight:700;color:#38bdf8;font-size:0.9rem;">${lvl}</span>
                    <span class="badge badge-gray">${assets.length} Assets</span>
                </div>
                <div style="display:flex;flex-wrap:wrap;gap:0.75rem;">
                    ${assets.map(a => `
                        <div style="background-color:var(--bg-card);border:1px solid var(--border-color);border-radius:6px;padding:0.6rem 0.85rem;min-width:180px;">
                            <div style="font-weight:700;font-size:0.85rem;color:#f8fafc;">${a.tag_name}</div>
                            <div style="font-size:0.75rem;color:var(--text-secondary);">${a.display_name}</div>
                            <div style="display:flex;justify-content:space-between;margin-top:0.4rem;font-size:0.72rem;">
                                <code>${a.ip_address || 'No IP'}</code>
                                <span class="badge ${a.ot_risk_score >= 8 ? 'badge-red' : (a.ot_risk_score >= 5 ? 'badge-amber' : 'badge-green')}">
                                    Risk ${a.ot_risk_score}
                                </span>
                            </div>
                        </div>
                    `).join("")}
                </div>
            </div>
        `;
    }).join("");

    // Conduits List
    let conduitsHtml = topo.conduits.map(c => `
        <div style="background-color:var(--bg-card);border:1px solid var(--border-color);border-radius:6px;padding:0.75rem;margin-bottom:0.5rem;display:flex;justify-content:space-between;align-items:center;">
            <div>
                <strong>${c.name}</strong>
                <div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.2rem;">
                    Protocols: ${c.allowed_protocols.join(", ")} | Ports: ${c.ports.join(", ")}
                </div>
            </div>
            <div>
                <span class="badge ${c.is_inspected ? 'badge-green' : 'badge-red'}">
                    ${c.is_inspected ? '🛡️ Inspected by ' + (c.inspection_device || 'Firewall') : '⚠️ UNINSPECTED'}
                </span>
            </div>
        </div>
    `).join("");

    container.innerHTML = `
        <div style="margin-bottom:1rem;">
            ${violationsHtml}
        </div>
        <div style="display:grid;grid-template-columns:2fr 1fr;gap:1.5rem;">
            <div>
                <h3 style="margin-bottom:0.75rem;font-size:0.95rem;color:#fff;">Purdue Architectural Zones</h3>
                ${levelsHtml}
            </div>
            <div>
                <h3 style="margin-bottom:0.75rem;font-size:0.95rem;color:#fff;">Inter-Zone Conduits (ISA/IEC 62443)</h3>
                ${conduitsHtml}
            </div>
        </div>
    `;
}

// ============================================================================
// 5. VULNERABILITY CENTER & COMPENSATING CONTROLS
// ============================================================================
async function loadVulnerabilities() {
    try {
        const res = await fetch("/api/vulnerabilities");
        const data = await res.json();
        renderVulnerabilitiesTable(data.vulnerabilities);
    } catch (err) {
        console.error("Error loading vulnerabilities:", err);
    }
}

function renderVulnerabilitiesTable(vulns) {
    const tbody = document.getElementById("vulns-table-body");
    tbody.innerHTML = vulns.map(v => {
        const hasControls = v.active_compensating_controls && v.active_compensating_controls.length > 0;
        return `
            <tr>
                <td><strong>${v.cve_id}</strong><br><span style="font-size:0.7rem;color:var(--text-muted);">${v.advisory_id}</span></td>
                <td><strong>${v.asset_tag}</strong></td>
                <td>${v.title}</td>
                <td><span class="badge ${v.severity === 'Critical' ? 'badge-red' : (v.severity === 'High' ? 'badge-amber' : 'badge-blue')}">${v.severity} (${v.cvss_base_score})</span></td>
                <td>
                    <span class="badge ${v.ot_contextual_risk >= 8 ? 'badge-red' : (v.ot_contextual_risk >= 5 ? 'badge-amber' : 'badge-green')}">
                        ${v.ot_contextual_risk} / 10.0
                    </span>
                </td>
                <td>
                    ${hasControls ? `
                        <span class="badge badge-green">🛡️ ${v.active_compensating_controls.length} Applied</span>
                        <div style="font-size:0.7rem;color:var(--text-secondary);margin-top:2px;">
                            ${v.active_compensating_controls.map(c => c.name).join(", ")}
                        </div>
                    ` : '<span class="badge badge-gray">None Applied</span>'}
                </td>
                <td>
                    <button class="btn btn-secondary" onclick="openCompensateModal('${v.asset_id}', '${v.cve_id}')" style="font-size:0.75rem;padding:0.25rem 0.6rem;">
                        Add Defense Control
                    </button>
                </td>
            </tr>
        `;
    }).join("");
}

function openCompensateModal(assetId, cveId) {
    document.getElementById("modal-asset-id").value = assetId;
    document.getElementById("modal-cve-id").textContent = cveId;
    document.getElementById("compensate-modal").classList.add("show");
}

function closeCompensateModal() {
    document.getElementById("compensate-modal").classList.remove("show");
}

async function submitCompensatingControl() {
    const assetId = document.getElementById("modal-asset-id").value;
    const ctrlType = document.getElementById("modal-control-type").value;
    const justification = document.getElementById("modal-justification").value;

    const payload = {
        control_type: ctrlType,
        name: ctrlType,
        description: `Compensating control enforced for ${assetId}`,
        risk_reduction_pct: 35.0,
        justification: justification || "Compensating defense applied per ISA/IEC 62443 guidance."
    };

    try {
        const res = await fetch(`/api/vulnerabilities/${assetId}/compensate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        showToast(data.message);
        closeCompensateModal();
        loadVulnerabilities();
    } catch (err) {
        console.error("Failed to apply compensating control:", err);
    }
}

// ============================================================================
// 6. HARDWARE LIFECYCLE (EOL/EOS)
// ============================================================================
async function loadLifecycle() {
    try {
        const res = await fetch("/api/lifecycle");
        const data = await res.json();

        // Render Obsolescence Risks
        const tbody = document.getElementById("lifecycle-table-body");
        tbody.innerHTML = data.obsolescence_risks.map(r => `
            <tr>
                <td><strong>${r.tag_name}</strong></td>
                <td>${r.vendor}</td>
                <td>${r.model}</td>
                <td><code>${r.firmware_version}</code></td>
                <td><span class="badge ${r.state.includes('Support') || r.state.includes('Discontinued') ? 'badge-red' : 'badge-amber'}">${r.state}</span></td>
                <td><span class="badge ${r.urgency === 'Critical' ? 'badge-red' : (r.urgency === 'High' ? 'badge-amber' : 'badge-blue')}">${r.urgency}</span></td>
                <td>${r.replacement_recommendation}</td>
            </tr>
        `).join("");

        // Milestones
        const mbody = document.getElementById("milestones-table-body");
        mbody.innerHTML = data.milestones.map(m => `
            <tr>
                <td><strong>${m.model}</strong></td>
                <td>${m.vendor}</td>
                <td>${m.release_year}</td>
                <td>${m.eol_year || 'TBD'}</td>
                <td>${m.eos_year || 'TBD'}</td>
                <td><span class="badge ${m.state.includes('Active') ? 'badge-green' : 'badge-amber'}">${m.state}</span></td>
                <td><strong>${m.replacement_model || 'N/A'}</strong></td>
            </tr>
        `).join("");
    } catch (err) {
        console.error("Error loading lifecycle:", err);
    }
}

// ============================================================================
// 7. INGESTION LAB
// ============================================================================
function initDropzone() {
    const dropzone = document.getElementById("file-dropzone");
    const fileInput = document.getElementById("file-input");

    if (!dropzone || !fileInput) return;

    dropzone.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.style.borderColor = "var(--accent-cyan)";
    });

    dropzone.addEventListener("dragleave", () => {
        dropzone.style.borderColor = "var(--border-color)";
    });

    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.style.borderColor = "var(--border-color)";
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });
}

async function handleFileUpload(file) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("file_type", "auto");

    showToast(`Uploading and parsing ${file.name}...`);
    try {
        const res = await fetch("/api/ingest/upload", {
            method: "POST",
            body: formData
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message);
            switchTab("tab-assets");
        } else {
            alert(`Upload error: ${data.detail}`);
        }
    } catch (err) {
        console.error("Upload error:", err);
        alert("Failed to upload file.");
    }
}

async function triggerPassiveProbe() {
    showToast("Launching safe passive OT broadcast probe...");
    try {
        const res = await fetch("/api/discovery/probe", { method: "POST" });
        const data = await res.json();
        showToast(data.message);
        loadAssets();
    } catch (err) {
        console.error("Probe error:", err);
    }
}

function loadSampleL5X() {
    const sampleXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<RSLogix5000Content SchemaRevision="1.0" SoftwareRevision="33.01" TargetName="PUMP_STATION_B" TargetType="Controller" ContainsContext="true">
  <Controller Use="Context" Name="PUMP_STATION_B" ProcessorType="1756-L85E" MajorRev="33" MinorRev="011">
    <Modules>
      <Module Name="Local" CatalogNumber="1756-L85E" Slot="0" Major="33" Minor="11"/>
      <Module Name="EN2T_COMM" CatalogNumber="1756-EN2T" Slot="1" Major="5" Minor="28"/>
      <Module Name="VALVE_INPUTS" CatalogNumber="1756-IB16" Slot="2" Major="3" Minor="2"/>
      <Module Name="PUMP_DRIVES" CatalogNumber="1756-OB16E" Slot="3" Major="3" Minor="1"/>
      <Module Name="PRESSURE_SENSORS" CatalogNumber="1756-IF8" Slot="4" Major="2" Minor="1"/>
    </Modules>
  </Controller>
</RSLogix5000Content>`;

    const blob = new Blob([sampleXml], { type: "text/xml" });
    const file = new File([blob], "PUMP_STATION_B.L5X", { type: "text/xml" });
    handleFileUpload(file);
}

function loadSampleIgnitionTags() {
    const sampleTags = {
        "name": "IgnitionDefaultProvider",
        "tagType": "Provider",
        "tags": [
            {
                "name": "WaterTreatment",
                "tagType": "Folder",
                "tags": [
                    {
                        "name": "IntakePump_Flow_GPM",
                        "tagType": "AtomicTag",
                        "dataType": "Float4",
                        "valueSource": "opc",
                        "opcServer": "Ignition OPC UA Server",
                        "opcItemPath": "ns=1;s=[Intake_ControlLogix_PLC]Program:Intake.FlowRate"
                    },
                    {
                        "name": "ChlorineGas_Feed_PPM",
                        "tagType": "AtomicTag",
                        "dataType": "Float4",
                        "valueSource": "opc",
                        "opcServer": "Ignition OPC UA Server",
                        "opcItemPath": "ns=1;s=[Chemical_CompactLogix_PLC]Program:Dosing.ChlorineFeedRate"
                    },
                    {
                        "name": "Boiler_EmergencyShutdown_Trip",
                        "tagType": "AtomicTag",
                        "dataType": "Boolean",
                        "valueSource": "opc",
                        "opcServer": "Ignition OPC UA Server",
                        "opcItemPath": "ns=1;s=[Boiler_Safety_SIS]Program:Safety.ESD_TripActive"
                    }
                ]
            }
        ]
    };

    const blob = new Blob([JSON.stringify(sampleTags, null, 2)], { type: "application/json" });
    const file = new File([blob], "Ignition_Tags_Export.json", { type: "application/json" });
    handleFileUpload(file);
}

// ============================================================================
// 8. COMPLIANCE & EXPORTS
// ============================================================================
async function loadCompliance() {
    try {
        const res = await fetch("/api/export/compliance?format=json");
        const scorecard = await res.json();

        document.getElementById("comp-overall-score").textContent = `${scorecard.overall_score}%`;
        document.getElementById("comp-iec-score").textContent = `${scorecard.iec_62443_score}%`;
        document.getElementById("comp-nist-score").textContent = `${scorecard.nist_800_82_score}%`;
        document.getElementById("comp-summary").textContent = scorecard.summary;

        const container = document.getElementById("compliance-reqs-list");
        container.innerHTML = scorecard.requirements.map(req => {
            const badgeClass = req.status === "Passed" ? "badge-green" : (req.status === "Warning" ? "badge-amber" : "badge-red");
            return `
                <div class="card" style="margin-bottom:1rem;">
                    <div class="card-header">
                        <div class="card-title">
                            [${req.code}] ${req.title} (${req.standard})
                        </div>
                        <span class="badge ${badgeClass}">${req.status} (${req.actual_score}%)</span>
                    </div>
                    <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:0.75rem;">${req.description}</p>
                    ${req.findings && req.findings.length > 0 ? `
                        <div style="background-color:rgba(239,68,68,0.1);padding:0.6rem;border-radius:6px;margin-bottom:0.6rem;">
                            <strong style="color:#f87171;font-size:0.8rem;">Findings:</strong>
                            <ul style="margin-left:1.2rem;font-size:0.8rem;color:#fca5a5;">
                                ${req.findings.map(f => `<li>${f}</li>`).join("")}
                            </ul>
                        </div>
                    ` : '<div style="color:var(--accent-green);font-size:0.8rem;">✓ No non-compliant findings detected.</div>'}
                    ${req.recommendations && req.recommendations.length > 0 ? `
                        <div style="font-size:0.8rem;color:#38bdf8;">
                            <strong>Remediation:</strong> ${req.recommendations.join("; ")}
                        </div>
                    ` : ''}
                </div>
            `;
        }).join("");
    } catch (err) {
        console.error("Error loading compliance:", err);
    }
}

function exportHBOM(format = "json") {
    window.location.href = `/api/export/hbom/${format}`;
}

function exportChassisHBOM() {
    exportHBOM("csv");
}

function inspectAsset(assetId) {
    switchTab("tab-assets");
    const search = document.getElementById("asset-search-input");
    search.value = assetId;
    filterAssets();
}

function showToast(msg) {
    const toast = document.createElement("div");
    toast.textContent = msg;
    toast.style.position = "fixed";
    toast.style.bottom = "20px";
    toast.style.right = "20px";
    toast.style.backgroundColor = "#1e293b";
    toast.style.color = "#38bdf8";
    toast.style.border = "1px solid #38bdf8";
    toast.style.padding = "10px 18px";
    toast.style.borderRadius = "8px";
    toast.style.boxShadow = "0 10px 20px rgba(0,0,0,0.5)";
    toast.style.zIndex = "9999";
    toast.style.fontSize = "0.85rem";
    toast.style.fontWeight = "600";
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3500);
}
