/**
 * Fake Login Page Awareness Detector
 * Client-Side Controller & Dynamic Renderer
 */

document.addEventListener("DOMContentLoaded", () => {
    const scanForm = document.getElementById("scan-form");
    const urlInput = document.getElementById("url-input");
    const inspectCheckbox = document.getElementById("inspect-checkbox");
    const btnScan = document.getElementById("btn-scan");
    const loadingBox = document.getElementById("loading-box");
    const resultsWrapper = document.getElementById("results-wrapper");
    const presetChips = document.querySelectorAll(".preset-chip");

    // Circumference of SVG circle with radius 54
    const CIRCLE_CIRCUMFERENCE = 2 * Math.PI * 54; // ~339.292

    // Initialize Preset Chips
    presetChips.forEach(chip => {
        chip.addEventListener("click", () => {
            const url = chip.getAttribute("data-url");
            if (url) {
                urlInput.value = url;
                executeScan(url);
            }
        });
    });

    // Form Submission
    if (scanForm) {
        scanForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const rawUrl = urlInput.value.trim();
            if (!rawUrl) {
                urlInput.focus();
                return;
            }
            executeScan(rawUrl);
        });
    }

    async function executeScan(url) {
        const inspectPage = inspectCheckbox ? inspectCheckbox.checked : true;

        // UI State: Loading
        btnScan.disabled = true;
        btnScan.innerHTML = `<span class="spinner" style="width:16px;height:16px;border-width:2px;margin:0;display:inline-block;"></span> Analyzing...`;
        loadingBox.style.display = "block";
        resultsWrapper.style.display = "none";

        // Cycle through inspection step text for UX engagement
        const stepItems = document.querySelectorAll(".loading-steps li");
        let stepIdx = 0;
        const stepInterval = setInterval(() => {
            if (stepItems.length > 0) {
                stepItems.forEach((item, i) => {
                    if (i <= stepIdx) {
                        item.style.color = "#06b6d4";
                        item.querySelector("span").textContent = "✓";
                    }
                });
                stepIdx = (stepIdx + 1) % stepItems.length;
            }
        }, 500);

        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    url: url,
                    inspect_page: inspectPage
                })
            });

            clearInterval(stepInterval);
            const data = await response.json();

            if (!response.ok || data.status !== "success") {
                alert(`Scan failed: ${data.message || "Unknown error"}`);
                return;
            }

            renderResults(data.data);
        } catch (err) {
            clearInterval(stepInterval);
            alert(`Error communicating with backend server: ${err.message}`);
        } finally {
            btnScan.disabled = false;
            btnScan.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
                Scan URL
            `;
            loadingBox.style.display = "none";
        }
    }

    function renderResults(report) {
        resultsWrapper.style.display = "block";

        // 1. Verdict Banner Styling
        const banner = document.getElementById("verdict-banner");
        banner.className = `verdict-banner ${report.risk_level}-risk`;

        document.getElementById("verdict-badge").textContent = `${report.risk_level.toUpperCase()} RISK`;
        document.getElementById("verdict-title").textContent = report.verdict;
        document.getElementById("scanned-url-text").textContent = report.url;

        // 2. Animate Gauge Meter
        const gaugeCircle = document.getElementById("gauge-progress-circle");
        const gaugeText = document.getElementById("gauge-score-text");
        
        const score = report.risk_score;
        gaugeText.textContent = score;

        // Calculate stroke color & dashoffset
        let strokeColor = "#10b981"; // Low (Green)
        if (report.risk_level === "high") {
            strokeColor = "#ef4444"; // Red
        } else if (report.risk_level === "medium") {
            strokeColor = "#f59e0b"; // Amber
        }
        
        gaugeCircle.style.stroke = strokeColor;
        const offset = CIRCLE_CIRCUMFERENCE - (CIRCLE_CIRCUMFERENCE * (score / 100));
        gaugeCircle.style.strokeDashoffset = offset;

        // 3. Render Visual Domain Breakdown
        renderDomainBreakdown(report.visual_tokens, report.indicators);

        // 4. Render Triggered Indicators
        renderIndicators(report.indicators);

        // 5. Render Page Inspection Findings
        renderPageInspection(report.page_inspection);

        // 6. Render Safety Advice
        renderSafetyAdvice(report.safety_advice);

        // Scroll into view
        resultsWrapper.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function renderDomainBreakdown(tokens, indicators) {
        const bar = document.getElementById("url-tokens-bar");
        if (!bar || !tokens) return;

        bar.innerHTML = "";

        // Check if scheme has issue
        const isInsecureScheme = tokens.scheme === "http" || tokens.scheme === "missing";
        const schemePill = createTokenPill("Protocol", tokens.scheme ? `${tokens.scheme}://` : "http://", `token-scheme ${isInsecureScheme ? 'insecure' : ''}`);
        bar.appendChild(schemePill);

        // Subdomain
        if (tokens.subdomain) {
            const subPill = createTokenPill("Subdomain", `${tokens.subdomain}.`, "token-subdomain");
            bar.appendChild(subPill);
        }

        // Domain
        const domPill = createTokenPill("Main Domain", tokens.domain, "token-domain");
        bar.appendChild(domPill);

        // TLD
        if (tokens.tld) {
            const tldPill = createTokenPill("TLD", `.${tokens.tld}`, "token-tld");
            bar.appendChild(tldPill);
        }

        // Port
        if (tokens.port) {
            const portPill = createTokenPill("Port", tokens.port, "token-path");
            bar.appendChild(portPill);
        }

        // Path
        if (tokens.path && tokens.path !== "/") {
            const pathPill = createTokenPill("Path", tokens.path, "token-path");
            bar.appendChild(pathPill);
        }

        // Query
        if (tokens.query) {
            const queryPill = createTokenPill("Query", tokens.query, "token-path");
            bar.appendChild(queryPill);
        }
    }

    function createTokenPill(label, value, extraClass) {
        const span = document.createElement("span");
        span.className = `token-pill ${extraClass}`;
        span.innerHTML = `<span class="token-tag">${label}</span><span>${escapeHtml(value)}</span>`;
        return span;
    }

    function renderIndicators(indicators) {
        const grid = document.getElementById("indicators-grid");
        const countBadge = document.getElementById("indicators-count-badge");
        
        countBadge.textContent = `${indicators.length} Found`;
        grid.innerHTML = "";

        if (indicators.length === 0) {
            grid.innerHTML = `
                <div class="indicator-card severity-low" style="text-align: center; padding: 2rem;">
                    <div style="font-size: 2rem; margin-bottom: 0.5rem;">🛡️</div>
                    <h3 style="color: #34d399; margin-bottom: 0.4rem;">Clean Bill of Health</h3>
                    <p style="color: #94a3b8; font-size: 0.95rem;">None of our rule-based heuristics flagged this domain or page structure.</p>
                </div>
            `;
            return;
        }

        indicators.forEach(ind => {
            const card = document.createElement("div");
            card.className = `indicator-card severity-${ind.severity}`;
            card.innerHTML = `
                <div class="indicator-top">
                    <div class="indicator-title-group">
                        <span class="indicator-category">${escapeHtml(ind.category)}</span>
                        <span class="indicator-title">${escapeHtml(ind.title)}</span>
                    </div>
                    <span class="indicator-points">+${ind.points} pts</span>
                </div>
                <p class="indicator-explanation">${escapeHtml(ind.explanation)}</p>
                ${ind.suspicious_part ? `
                    <div style="font-size: 0.82rem; margin-bottom: 0.5rem; color: #f87171;">
                        <strong>Flagged Token:</strong> <code style="background: rgba(0,0,0,0.4); padding: 0.15rem 0.4rem; border-radius: 4px;">${escapeHtml(ind.suspicious_part)}</code>
                    </div>
                ` : ''}
                <div class="indicator-technical">
                    <strong>Examiner Note:</strong> ${escapeHtml(ind.technical_detail)}
                </div>
            `;
            grid.appendChild(card);
        });
    }

    function renderPageInspection(inspection) {
        const grid = document.getElementById("inspection-grid");
        if (!grid || !inspection) return;

        grid.innerHTML = `
            <div class="inspection-item">
                <div class="inspection-item-label">Server Connectivity</div>
                <div class="inspection-item-val" style="color: ${inspection.reachable ? '#34d399' : '#f87171'};">
                    ${inspection.reachable ? '✓ Accessible (HTTP ' + (inspection.status_code || 200) + ')' : '✗ Unreachable / Offline'}
                </div>
            </div>
            <div class="inspection-item">
                <div class="inspection-item-label">Redirect Count</div>
                <div class="inspection-item-val">${inspection.redirect_count} hops</div>
            </div>
            <div class="inspection-item">
                <div class="inspection-item-label">Login Form Present</div>
                <div class="inspection-item-val" style="color: ${inspection.has_login_form ? '#fbbf24' : '#94a3b8'};">
                    ${inspection.has_login_form ? '⚠️ Yes (<form> detected)' : 'None'}
                </div>
            </div>
            <div class="inspection-item">
                <div class="inspection-item-label">Password Input Field</div>
                <div class="inspection-item-val" style="color: ${inspection.has_password_input ? '#f87171' : '#94a3b8'};">
                    ${inspection.has_password_input ? '⚠️ Found (type="password")' : 'None'}
                </div>
            </div>
            <div class="inspection-item" style="grid-column: 1 / -1;">
                <div class="inspection-item-label">Page Title Extracted</div>
                <div class="inspection-item-val" style="font-family: var(--font-mono); font-size: 0.85rem;">
                    ${inspection.page_title ? escapeHtml(inspection.page_title) : '<i>(No title tag detected)</i>'}
                </div>
            </div>
        `;
    }

    function renderSafetyAdvice(adviceList) {
        const list = document.getElementById("safety-list");
        if (!list || !adviceList) return;

        list.innerHTML = "";
        adviceList.forEach(item => {
            const li = document.createElement("li");
            li.textContent = item;
            list.appendChild(li);
        });
    }

    // Helper functions
    function escapeHtml(text) {
        if (!text) return "";
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }

    // Export / Action buttons
    const btnPrint = document.getElementById("btn-print-report");
    if (btnPrint) {
        btnPrint.addEventListener("click", () => {
            window.print();
        });
    }

    const btnScanNew = document.getElementById("btn-scan-new");
    if (btnScanNew) {
        btnScanNew.addEventListener("click", () => {
            urlInput.value = "";
            urlInput.focus();
            window.scrollTo({ top: 0, behavior: "smooth" });
        });
    }
});
