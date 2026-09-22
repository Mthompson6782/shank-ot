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
    if (tabId === "tab-flows") loadFlows();
    if (tabId === "tab-locations") loadLocations();
    if (tabId === "tab-systems") loadSystems();
    if (tabId === "tab-vulns") loadVulnerabilities();
    if (tabId === "tab-lifecycle") loadLifecycle();
    if (tabId === "tab-compliance") loadCompliance();
    if (tabId === "tab-armis") loadArmis();
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
// 4. KANDINSKY NETWORK TOPOLOGY & MULTI-PERSPECTIVE SYNTHESIZER
// ============================================================================
let currentTopologyMode = "connections";

function switchTopologyMode(mode) {
    currentTopologyMode = mode;
    document.querySelectorAll(".topo-mode-btn").forEach(b => {
        b.classList.toggle("active", b.getAttribute("data-mode") === mode);
    });
    loadTopology();
}

async function loadTopology() {
    try {
        const [resPersp, resViolations] = await Promise.all([
            fetch(`/api/topology/perspectives?mode=${currentTopologyMode}`),
            fetch("/api/topology")
        ]);
        const perspData = await resPersp.json();
        const topoData = await resViolations.json();
        renderKandinskyTopology(perspData, topoData.violations);
    } catch (err) {
        console.error("Error loading Kandinsky topology:", err);
    }
}

function renderKandinskyTopology(data, violations) {
    const container = document.getElementById("kandinsky-canvas-container");
    const violationsContainer = document.getElementById("topology-violations-list");

    // Render Violations
    if (violations && violations.length > 0) {
        violationsContainer.innerHTML = violations.map(v => `
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
        violationsContainer.innerHTML = `<div class="badge badge-green" style="margin-bottom:1rem;">✓ Zero Purdue Segmentation Violations Detected</div>`;
    }

    if (!data.nodes || data.nodes.length === 0) {
        container.innerHTML = `<p style="padding:2rem;color:var(--text-muted);text-align:center;">No topology nodes in this perspective.</p>`;
        return;
    }

    // Determine canvas dimensions from node bounds
    let maxX = 1200;
    let maxY = 700;
    data.nodes.forEach(n => {
        if (n.x + n.width + 100 > maxX) maxX = n.x + n.width + 100;
        if (n.y + n.height + 100 > maxY) maxY = n.y + n.height + 100;
    });

    let svgHtml = `
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${maxX} ${maxY}" width="${maxX}px" height="${maxY}px" style="background:#090d16;min-width:100%;font-family:Inter,sans-serif;">
            <defs>
                <pattern id="canvas-grid" width="20" height="20" patternUnits="userSpaceOnUse">
                    <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#1e293b" stroke-width="0.5"/>
                </pattern>
                <marker id="arrow-blue" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 1 L 8 5 L 0 9 z" fill="#0284c7"/>
                </marker>
            </defs>
            <rect width="100%" height="100%" fill="url(#canvas-grid)" />
    `;

    // 1. Draw Orthogonal Edges
    (data.edges || []).forEach(edge => {
        const strokeColor = edge.is_manual ? "#ef4444" : "#0284c7";
        const strokeDash = edge.is_manual ? "stroke-dasharray:6,6;" : "";
        const pts = (edge.waypoints || []).map(p => `${p[0]},${p[1]}`).join(" ");

        if (pts) {
            svgHtml += `<polyline points="${pts}" fill="none" stroke="${strokeColor}" stroke-width="2.5" style="${strokeDash}" />`;
            if (edge.source_port && edge.waypoints.length > 0) {
                const p0 = edge.waypoints[0];
                svgHtml += `
                    <rect x="${p0[0] + 4}" y="${p0[1] - 18}" width="50" height="15" rx="3" fill="#0369a1" />
                    <text x="${p0[0] + 8}" y="${p0[1] - 7}" fill="#f8fafc" font-size="9" font-weight="bold">${edge.source_port}</text>
                `;
            }
        }
    });

    // 2. Draw Nodes
    data.nodes.forEach(node => {
        let fill = "#0f172a";
        let stroke = "#38bdf8";
        let icon = "⚡";

        if (node.node_type === "managed_switch") {
            fill = "#082f49";
            stroke = "#06b6d4";
            icon = "🔀";
        } else if (node.node_type === "unmanaged_switch") {
            fill = "#422006";
            stroke = "#eab308";
            icon = "🔌";
        } else if (node.node_type === "router_firewall") {
            fill = "#450a0a";
            stroke = "#dc2626";
            icon = "🛡️";
        } else if (node.node_type === "location_box") {
            fill = "rgba(30, 41, 59, 0.4)";
            stroke = "#475569";
            icon = "🏢";
        } else if (node.node_type === "hmi") {
            fill = "#172554";
            stroke = "#60a5fa";
            icon = "🖥️";
        }

        const lines = (node.label || "").split("\n");

        svgHtml += `
            <g style="cursor:pointer;" onclick="inspectAsset('${node.id}')">
                <rect x="${node.x}" y="${node.y}" width="${node.width}" height="${node.height}" rx="6" fill="${fill}" stroke="${stroke}" stroke-width="1.8" />
                <text x="${node.x + 10}" y="${node.y + 22}" fill="#f8fafc" font-size="12" font-weight="bold">${icon} ${lines[0] || ''}</text>
        `;
        if (lines[1]) {
            svgHtml += `<text x="${node.x + 10}" y="${node.y + 38}" fill="#94a3b8" font-size="10">${lines[1]}</text>`;
        }
        if (node.ip_address) {
            svgHtml += `<text x="${node.x + 10}" y="${node.y + node.height - 10}" fill="#38bdf8" font-size="10" font-family="monospace">${node.ip_address}</text>`;
        }
        svgHtml += `</g>`;
    });

    svgHtml += `</svg>`;
    container.innerHTML = svgHtml;
}

function exportTopology(format) {
    window.open(`/api/export/topology-${format}?mode=${currentTopologyMode}`, "_blank");
}

function openUnmanagedSwitchModal() {
    const sel = document.getElementById("unsw-asset-select");
    sel.innerHTML = currentAssets.map(a => `<option value="${a.id}">${a.tag_name} - ${a.display_name} (${a.purdue_level.split(" - ")[0]})</option>`).join("");
    document.getElementById("unmanaged-switch-modal").style.display = "flex";
}

function closeUnmanagedSwitchModal() {
    document.getElementById("unmanaged-switch-modal").style.display = "none";
}

async function submitUnmanagedSwitch() {
    const label = document.getElementById("unsw-label").value || "UNM-SW-SKID-01";
    const assetId = document.getElementById("unsw-asset-select").value;
    const switchId = `unsw-${Date.now().toString().slice(-4)}`;

    await fetch("/api/topology/unmanaged-switch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            id: switchId,
            label: label,
            x: 480,
            y: 380,
            connected_asset_ids: [assetId]
        })
    });

    closeUnmanagedSwitchModal();
    showToast(`Hybrid unmanaged switch added. Asserted dashed link to ${assetId}.`);
    loadTopology();
}

// ============================================================================
// 5. FLOW TELEMETRY & SANKEY
// ============================================================================
async function loadFlows() {
    try {
        const [resSankey, resAssets] = await Promise.all([
            fetch("/api/telemetry/sankey"),
            fetch("/api/assets")
        ]);
        const sankey = await resSankey.json();
        const assets = await resAssets.json();

        // Populate table
        const tbody = document.getElementById("sankey-table-body");
        tbody.innerHTML = (sankey.links || []).map(l => `
            <tr>
                <td><strong>${l.source_name}</strong></td>
                <td style="color:#38bdf8;font-weight:bold;">━━━━▶</td>
                <td><strong>${l.target_name}</strong></td>
                <td><span class="badge badge-cyan">${l.value} ${l.unit}</span></td>
                <td><span class="badge badge-gray">sFlow 1:128 Hardware Line-Rate</span></td>
            </tr>
        `).join("");

        // Populate Asset picker
        const picker = document.getElementById("flow-asset-picker");
        picker.innerHTML = `<option value="">-- Choose Asset to Profile --</option>` + 
            assets.filter(a => a.network_interfaces && a.network_interfaces.length > 0 && a.network_interfaces[0].ip_address)
                  .map(a => `<option value="${a.network_interfaces[0].ip_address}">${a.tag_name} (${a.network_interfaces[0].ip_address})</option>`).join("");
    } catch (err) {
        console.error("Error loading flows:", err);
    }
}

async function profileAssetTraffic(ip) {
    if (!ip) return;
    try {
        const res = await fetch(`/api/telemetry/profile/${ip}`);
        const data = await res.json();
        const container = document.getElementById("asset-flow-profile-container");

        let anomaliesHtml = "";
        if (data.anomalies && data.anomalies.length > 0) {
            anomaliesHtml = `
                <div class="violation-banner" style="margin-bottom:1rem;">
                    <div style="font-size:1.5rem;">🚨</div>
                    <div>
                        <div class="violation-title">Anomalous / Rogue Flow Detected</div>
                        <div class="violation-desc">${data.anomalies.map(a => a.reason + ': ' + a.flow).join('<br>')}</div>
                    </div>
                </div>
            `;
        }

        container.innerHTML = `
            ${anomaliesHtml}
            <div style="display:flex;gap:1.5rem;margin-bottom:1rem;font-size:0.85rem;">
                <div><span style="color:var(--text-muted);">Target IP:</span> <code>${data.target_ip}</code></div>
                <div><span style="color:var(--text-muted);">Total Inbound:</span> <strong style="color:#38bdf8;">${data.total_inbound_mb} MB</strong></div>
                <div><span style="color:var(--text-muted);">Total Outbound:</span> <strong style="color:#34d399;">${data.total_outbound_mb} MB</strong></div>
                <div><span style="color:var(--text-muted);">Observed Ports:</span> <code>${data.observed_services.join(', ') || 'None'}</code></div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
                <div>
                    <h4 style="font-size:0.85rem;color:#f8fafc;margin-bottom:0.5rem;">Inbound Talkers</h4>
                    ${data.inbound_peers.map(p => `
                        <div style="background:rgba(255,255,255,0.03);padding:0.5rem;border-radius:4px;margin-bottom:0.4rem;font-size:0.75rem;">
                            <strong>${p.peer_name}</strong> (${p.peer_ip}) &rarr; Port ${p.port} (${p.protocol})
                            <div style="color:var(--text-muted);">${(p.bytes / 1024 / 1024).toFixed(2)} MB (${p.packets} packets)</div>
                        </div>
                    `).join('') || '<div style="color:var(--text-muted);font-size:0.8rem;">No inbound flows observed.</div>'}
                </div>
                <div>
                    <h4 style="font-size:0.85rem;color:#f8fafc;margin-bottom:0.5rem;">Outbound Destinations</h4>
                    ${data.outbound_peers.map(p => `
                        <div style="background:rgba(255,255,255,0.03);padding:0.5rem;border-radius:4px;margin-bottom:0.4rem;font-size:0.75rem;">
                            &rarr; <strong>${p.peer_name}</strong> (${p.peer_ip}) Port ${p.port} (${p.protocol})
                            <div style="color:var(--text-muted);">${(p.bytes / 1024 / 1024).toFixed(2)} MB (${p.packets} packets)</div>
                        </div>
                    `).join('') || '<div style="color:var(--text-muted);font-size:0.8rem;">No outbound flows observed.</div>'}
                </div>
            </div>
        `;
    } catch (err) {
        console.error("Error profiling traffic:", err);
    }
}

// ============================================================================
// 6. LOCATION TREES & DUPLICATE IP DISAMBIGUATION
// ============================================================================
async function loadLocations() {
    try {
        const res = await fetch("/api/locations");
        const data = await res.json();

        // Duplicate IP Banner
        const banner = document.getElementById("duplicate-ip-report-banner");
        const dup = data.duplicate_ip_report;
        if (dup && dup.total_duplicate_ips_tracked > 0) {
            banner.innerHTML = `
                <div style="background:rgba(168,85,247,0.1);border:1px solid rgba(168,85,247,0.3);border-radius:8px;padding:1rem;">
                    <div style="font-weight:700;color:#c084fc;margin-bottom:0.35rem;">✓ Duplicate IP Address Spaces Disambiguated by Location Trees</div>
                    <div style="font-size:0.82rem;color:var(--text-secondary);">
                        Detected ${dup.total_duplicate_ips_tracked} duplicated private subnet IP(s) across modular skids. OTbase binds each asset strictly to its unique Location ID, preventing data collisions.
                    </div>
                </div>
            `;
        } else {
            banner.innerHTML = `
                <div style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);border-radius:8px;padding:0.75rem;color:#34d399;font-size:0.82rem;">
                    ✓ All private IP subnets verified with clean Location ID bindings.
                </div>
            `;
        }

        // Table
        const tbody = document.getElementById("locations-table-body");
        tbody.innerHTML = (data.location_tree || []).map(l => `
            <tr>
                <td><code>${l.id}</code></td>
                <td><strong>${l.name}</strong></td>
                <td><span class="badge badge-purple">${l.tier}</span></td>
                <td><code>${l.parent_id || 'ROOT'}</code></td>
                <td><span class="badge ${l.metadata && l.metadata.duplicate_subnet_enabled ? 'badge-amber' : 'badge-green'}">${l.metadata && l.metadata.duplicate_subnet_enabled ? 'Duplicate Skid Namespace (' + l.metadata.subnet + ')' : 'Unique Subnet'}</span></td>
            </tr>
        `).join("");
    } catch (err) {
        console.error("Error loading locations:", err);
    }
}

// ============================================================================
// 7. OT SYSTEMS ABSTRACTION
// ============================================================================
async function loadSystems() {
    try {
        const res = await fetch("/api/systems");
        const data = await res.json();

        // Shared switch warning
        const warnContainer = document.getElementById("shared-switch-warning-container");
        if (data.shared_trunk_switches && data.shared_trunk_switches.length > 0) {
            warnContainer.innerHTML = data.shared_trunk_switches.map(sw => `
                <div class="violation-banner">
                    <div style="font-size:1.5rem;">⚠️</div>
                    <div>
                        <div class="violation-title">Shared Trunk Infrastructure Warning: ${sw.switch_id}</div>
                        <div class="violation-desc">${sw.shared_risk_warning}</div>
                    </div>
                </div>
            `).join("");
        } else {
            warnContainer.innerHTML = "";
        }

        // Systems Cards
        const grid = document.getElementById("ot-systems-cards-grid");
        grid.innerHTML = (data.systems || []).map(sys => `
            <div class="card" style="border-color:rgba(56,189,248,0.3);">
                <div class="card-header">
                    <div class="card-title">${sys.name}</div>
                    <span class="badge badge-blue">${sys.process_criticality}</span>
                </div>
                <p style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.75rem;">${sys.description}</p>
                <div style="font-size:0.75rem;color:var(--text-muted);display:grid;gap:0.4rem;">
                    <div>Primary Controller: <strong style="color:#f8fafc;">${sys.primary_controller_id}</strong></div>
                    <div>Associated Assets: <strong style="color:#f8fafc;">${sys.asset_ids.join(', ')}</strong></div>
                    <div>Serving Switches: <strong style="color:#06b6d4;">${sys.shared_switch_ids.join(', ')}</strong></div>
                    <div>Operational Bandwidth: <strong style="color:#34d399;">${sys.total_bandwidth_kbps} kbps</strong></div>
                </div>
            </div>
        `).join("");
    } catch (err) {
        console.error("Error loading systems:", err);
    }
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

// ============================================================================
// 12. ARMIS INTEGRATION & RECONCILIATION
// ============================================================================
let armisLiveConfig = {
    tenantUrl: "",
    apiSecretKey: ""
};

async function loadArmis() {
    try {
        const [devRes, reconRes] = await Promise.all([
            fetch("/api/armis/devices"),
            fetch("/api/armis/reconciliation")
        ]);

        const devData = await devRes.json();
        const reconData = await reconRes.json();

        // Update KPIs
        const devCount = devData.count || (devData.devices ? devData.devices.length : 0);
        document.getElementById("kpi-armis-devices").textContent = devCount;
        document.getElementById("kpi-armis-correlated").textContent = reconData.correlated_assets_count || 0;
        document.getElementById("kpi-armis-rogue").textContent = reconData.rogue_assets_count || 0;
        document.getElementById("kpi-armis-dormant").textContent = reconData.dormant_assets_count || 0;
        document.getElementById("kpi-armis-discrepancies").textContent = (reconData.discrepancies || []).length;

        document.getElementById("badge-discrepancy-count").textContent = `${(reconData.discrepancies || []).length} Detected`;
        document.getElementById("badge-armis-count").textContent = `${devCount} Devices`;

        // Render Discrepancies Table
        renderArmisDiscrepancies(reconData.discrepancies || []);

        // Render Armis Devices Table
        renderArmisDevices(devData.devices || []);
    } catch (e) {
        console.error("Failed to load Armis data:", e);
        showToast("Failed to load Armis data");
    }
}

function renderArmisDiscrepancies(discrepancies) {
    const tbody = document.getElementById("armis-discrepancies-table-body");
    if (!tbody) return;
    if (!discrepancies || discrepancies.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-secondary);padding:2rem;">✓ Zero discrepancies detected between Armis passive visibility and OTbase ground truth.</td></tr>`;
        return;
    }

    const sevColors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#38bdf8",
        "INFO": "#94a3b8"
    };

    tbody.innerHTML = discrepancies.map(d => {
        const sevColor = sevColors[d.severity] || "#94a3b8";
        const armisVal = d.armis_value !== null ? `<span style="font-family:monospace;color:#38bdf8;">${escapeHtml(String(d.armis_value))}</span>` : "-";
        const groundVal = d.ground_truth_value !== null ? `<span style="font-family:monospace;color:#4ade80;">${escapeHtml(String(d.ground_truth_value))}</span>` : "-";

        return `
            <tr>
                <td><span class="badge" style="background:${sevColor};color:#fff;font-weight:700;">${d.severity}</span></td>
                <td><code style="color:#c084fc;font-weight:600;">${d.discrepancy_type}</code></td>
                <td><strong>${escapeHtml(d.asset_tag || d.ip_address || "Unknown")}</strong><br><small style="color:var(--text-secondary);font-family:monospace;">${escapeHtml(d.ip_address || "")}</small></td>
                <td>${armisVal}</td>
                <td>${groundVal}</td>
                <td style="max-width:340px;">
                    <div style="font-size:0.8rem;color:#f1f5f9;margin-bottom:0.35rem;">${escapeHtml(d.description)}</div>
                    <div style="font-size:0.75rem;color:#94a3b8;border-left:2px solid ${sevColor};padding-left:0.5rem;">
                        <strong>Remediation:</strong> ${escapeHtml(d.remediation_recommendation)}
                    </div>
                </td>
            </tr>
        `;
    }).join("");
}

function renderArmisDevices(devices) {
    const tbody = document.getElementById("armis-devices-table-body");
    if (!tbody) return;
    if (!devices || devices.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-secondary);padding:2rem;">No Armis devices currently cached. Click 'Sync Armis Data' to query.</td></tr>`;
        return;
    }

    tbody.innerHTML = devices.map(dev => {
        const riskColor = dev.risk_level >= 7 ? "#ef4444" : dev.risk_level >= 4 ? "#eab308" : "#22c55e";
        const portStr = dev.switch_port ? `${escapeHtml(dev.switch_name || "")} (${escapeHtml(dev.switch_port)})` : `<span style="color:var(--text-secondary);">Direct / Wi-Fi</span>`;
        const protos = (dev.protocols || []).map(p => `<span class="badge" style="background:rgba(56,189,248,0.15);color:#38bdf8;font-size:0.7rem;">${p}</span>`).join(" ");

        return `
            <tr>
                <td><code style="color:#94a3b8;">${dev.id}</code></td>
                <td><strong>${escapeHtml(dev.name || "")}</strong><br><small style="color:var(--text-secondary);">${escapeHtml(dev.manufacturer || "")} ${escapeHtml(dev.model || "")}</small></td>
                <td><code style="color:#38bdf8;">${escapeHtml(dev.ip_address || "-")}</code></td>
                <td><code style="color:var(--text-secondary);">${escapeHtml(dev.mac_address || "-")}</code></td>
                <td><span class="badge" style="background:rgba(255,255,255,0.08);color:#f1f5f9;">${escapeHtml(dev.device_type || dev.category)}</span></td>
                <td><small>${portStr}</small></td>
                <td>${protos || "-"}</td>
                <td><span class="badge" style="background:${riskColor};color:#fff;font-weight:700;">${dev.risk_level} / 10</span></td>
            </tr>
        `;
    }).join("");
}

async function triggerArmisSync() {
    const aqlInput = document.getElementById("armis-aql-input");
    const aql = aqlInput ? aqlInput.value : "in:devices";

    showToast("Querying Armis Platform...");
    try {
        const res = await fetch("/api/armis/sync", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                simulate: !armisLiveConfig.tenantUrl,
                tenant_url: armisLiveConfig.tenantUrl || null,
                api_secret_key: armisLiveConfig.apiSecretKey || null,
                aql: aql
            })
        });
        const data = await res.json();
        showToast(`✓ Armis Sync Complete: ${data.devices_discovered} devices, ${data.discrepancies_count} discrepancies`);
        await loadArmis();
    } catch (e) {
        showToast("Error triggering Armis sync: " + e.message);
    }
}

async function ingestArmisFlows() {
    showToast("Ingesting Armis flows into Sankey Matrix...");
    try {
        const res = await fetch("/api/armis/connections/ingest-to-flows", { method: "POST" });
        const data = await res.json();
        showToast(`✓ Ingested ${data.new_flows_ingested} new flows (Total: ${data.total_flows})`);
    } catch (e) {
        showToast("Error ingesting flows: " + e.message);
    }
}

function toggleArmisConfigModal() {
    const tenant = prompt("Enter Armis Tenant URL (or leave blank to use high-fidelity simulator):", armisLiveConfig.tenantUrl);
    if (tenant !== null) {
        if (tenant.trim()) {
            const secret = prompt("Enter Armis API Secret Key:", armisLiveConfig.apiSecretKey);
            if (secret) {
                armisLiveConfig.tenantUrl = tenant.trim();
                armisLiveConfig.apiSecretKey = secret.trim();
                document.getElementById("armis-mode-status").textContent = `Mode: Live Cloud Tenant (${armisLiveConfig.tenantUrl})`;
                showToast("Configured for Live Armis Tenant");
            }
        } else {
            armisLiveConfig.tenantUrl = "";
            armisLiveConfig.apiSecretKey = "";
            document.getElementById("armis-mode-status").textContent = "Mode: Active Simulation (No external credentials required)";
            showToast("Reset to Armis Simulator");
        }
    }
}
