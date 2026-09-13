async function scanURL() {
    const urlInput = document.getElementById("url");
    const resultDiv = document.getElementById("result");

    if (!urlInput || !resultDiv) {
        console.error("PhishGuard UI elements not found.");
        return;
    }

    const url = urlInput.value.trim();

    // -----------------------------
    // Validate input
    // -----------------------------
    if (!url) {
        resultDiv.innerHTML = `
            <div class="alert alert-warning">
                <h4>⚠️ Invalid Input</h4>
                <p>Please enter a URL to scan.</p>
            </div>
        `;
        return;
    }

    // -----------------------------
    // Initial loading state
    // -----------------------------
    resultDiv.innerHTML = `
        <div class="alert alert-info shadow-sm">
            <div class="d-flex align-items-center">
                <div class="spinner-border spinner-border-sm me-2" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>

                <div>
                    <strong>Scan queued...</strong>
                    <div class="small text-muted">
                        Preparing URL analysis.
                    </div>
                </div>
            </div>
        </div>
    `;

    try {
        const formData = new FormData();
        formData.append("url", url);

        // =========================================================
        // STEP 1: Create asynchronous scan job
        // =========================================================
        const response = await fetch("/scan/async", {
            method: "POST",
            body: formData,
            headers: {
                "Accept": "application/json"
            }
        });

        let data = {};

        try {
            data = await response.json();
        } catch (jsonError) {
            throw new Error(
                `Server returned ${response.status}, but response was not valid JSON.`
            );
        }

        // -----------------------------
        // Handle rate limit
        // -----------------------------
        if (response.status === 429) {
            const retryAfter = data.retry_after || 60;

            resultDiv.innerHTML = `
                <div class="alert alert-warning shadow-sm">
                    <h4>⚠️ Too Many Requests</h4>
                    <p>${escapeHtml(
                        data.message ||
                        "Too many scan requests. Please try again later."
                    )}</p>
                    <small class="text-muted">
                        Try again in approximately ${retryAfter} seconds.
                    </small>
                </div>
            `;

            return;
        }

        // -----------------------------
        // Handle validation/server errors
        // -----------------------------
        if (!response.ok || !data.success) {
            throw new Error(
                data.error ||
                data.message ||
                `Server returned ${response.status}`
            );
        }

        const scanId = data.scan_id;

        if (!scanId) {
            throw new Error("Server did not return a scan ID.");
        }

        // =========================================================
        // STEP 2: Poll scan status
        // =========================================================
        await pollScanStatus(scanId, resultDiv);

    } catch (error) {
        console.error("Scan error:", error);

        resultDiv.innerHTML = `
            <div class="alert alert-danger shadow-sm">
                <h4>❌ Scan Failed</h4>
                <p>${escapeHtml(error.message)}</p>
                <small class="text-muted">
                    Please check that the PhishGuard server is running.
                </small>
            </div>
        `;
    }
}


// =============================================================
// Poll asynchronous scan status
// =============================================================
async function pollScanStatus(scanId, resultDiv) {

    const maxAttempts = 60;
    const pollingInterval = 1000;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {

        try {
            const response = await fetch(
                `/scan/${encodeURIComponent(scanId)}`,
                {
                    method: "GET",
                    headers: {
                        "Accept": "application/json"
                    }
                }
            );

            let data = {};

            try {
                data = await response.json();
            } catch (jsonError) {
                throw new Error("Server returned invalid JSON.");
            }

            // -----------------------------------------
            // Job not found
            // -----------------------------------------
            if (response.status === 404) {
                throw new Error(
                    data.error || "Scan job was not found."
                );
            }

            // -----------------------------------------
            // Other server errors
            // -----------------------------------------
            if (!response.ok || !data.success) {
                throw new Error(
                    data.error ||
                    data.message ||
                    `Status request failed (${response.status})`
                );
            }

            // -----------------------------------------
            // QUEUED
            // -----------------------------------------
            if (data.status === "queued") {

                resultDiv.innerHTML = `
                    <div class="alert alert-info shadow-sm">
                        <div class="d-flex align-items-center">
                            <div class="spinner-border spinner-border-sm me-2"
                                 role="status">
                                <span class="visually-hidden">
                                    Loading...
                                </span>
                            </div>

                            <div>
                                <strong>Scan queued</strong>
                                <div class="small text-muted">
                                    Waiting for the analysis worker...
                                </div>
                            </div>
                        </div>

                        <hr>

                        <small>
                            Scan ID:
                            <code>${escapeHtml(scanId)}</code>
                        </small>
                    </div>
                `;
            }

            // -----------------------------------------
            // PROCESSING
            // -----------------------------------------
            else if (data.status === "processing") {

                resultDiv.innerHTML = `
                    <div class="alert alert-info shadow-sm">
                        <div class="d-flex align-items-center">
                            <div class="spinner-border spinner-border-sm me-2"
                                 role="status">
                                <span class="visually-hidden">
                                    Loading...
                                </span>
                            </div>

                            <div>
                                <strong>Scanning URL...</strong>
                                <div class="small text-muted">
                                    Running ML models and threat intelligence.
                                </div>
                            </div>
                        </div>

                        <hr>

                        <small>
                            Scan ID:
                            <code>${escapeHtml(scanId)}</code>
                        </small>
                    </div>
                `;
            }

            // -----------------------------------------
            // COMPLETED
            // -----------------------------------------
            else if (data.status === "completed") {

                if (!data.result) {
                    throw new Error(
                        "Scan completed but no result was returned."
                    );
                }

                renderScanResult(data.result, data.duration_ms);

                return;
            }

            // -----------------------------------------
            // FAILED
            // -----------------------------------------
            else if (data.status === "failed") {

                resultDiv.innerHTML = `
                    <div class="alert alert-danger shadow-sm">
                        <h4>❌ Scan Failed</h4>

                        <p>
                            ${escapeHtml(
                                data.error ||
                                "The scan worker failed to analyze this URL."
                            )}
                        </p>

                        <small class="text-muted">
                            Scan ID:
                            <code>${escapeHtml(scanId)}</code>
                        </small>
                    </div>
                `;

                return;
            }

            // -----------------------------------------
            // Unknown state
            // -----------------------------------------
            else {
                console.warn(
                    "Unknown scan status:",
                    data.status
                );
            }

        } catch (error) {
            console.error(
                `Polling attempt ${attempt + 1} failed:`,
                error
            );

            if (attempt === maxAttempts - 1) {
                throw error;
            }
        }

        // Wait before polling again
        await sleep(pollingInterval);
    }

    // =========================================================
    // Polling timeout
    // =========================================================
    resultDiv.innerHTML = `
        <div class="alert alert-warning shadow-sm">
            <h4>⏳ Scan Taking Too Long</h4>

            <p>
                The scan is still being processed.
                You can check the status again shortly.
            </p>

            <small class="text-muted">
                Scan ID:
                <code>${escapeHtml(scanId)}</code>
            </small>
        </div>
    `;
}


// =============================================================
// Render final scan result
// =============================================================
function renderScanResult(result, durationMs) {

    const resultDiv = document.getElementById("result");

    const riskLevel = result.risk_level || "UNKNOWN";
    const riskScore = Number(result.risk_score || 0);

    // -----------------------------------------
    // Risk UI
    // -----------------------------------------
    let alertClass = "alert-secondary";
    let icon = "ℹ️";
    let riskDescription = "Analysis completed.";

    if (riskLevel === "SAFE") {
        alertClass = "alert-success";
        icon = "✅";
        riskDescription =
            "This URL appears safe based on the available analysis.";
    }
    else if (riskLevel === "SUSPICIOUS") {
        alertClass = "alert-warning";
        icon = "⚠️";
        riskDescription =
            "This URL shows suspicious characteristics. Proceed with caution.";
    }
    else if (riskLevel === "PHISHING") {
        alertClass = "alert-danger";
        icon = "🚨";
        riskDescription =
            "This URL has been identified as potentially malicious.";
    }

    // -----------------------------------------
    // VirusTotal data
    // -----------------------------------------
    const threatIntel =
        result.threat_intelligence || {};

    const malicious =
        Number(threatIntel.malicious || 0);

    const suspicious =
        Number(threatIntel.suspicious || 0);

    const harmless =
        Number(threatIntel.harmless || 0);

    const undetected =
        Number(threatIntel.undetected || 0);

    const totalEngines =
        Number(
            threatIntel.total_engines ||
            (malicious + suspicious + harmless + undetected)
        );

    // -----------------------------------------
    // Models
    // -----------------------------------------
    const models =
        result.models || {};

    const urlMl =
        models.url_ml || {};

    const hostnameMl =
        models.hostname_ml || {};

    const urlMlScore =
        Number(
            models.url_ml_score ??
            (Number(urlMl.probability || 0) * 100)
        );

    const hostnameMlScore =
        Number(
            models.hostname_ml_score ??
            (Number(hostnameMl.probability || 0) * 100)
        );

    const modelScore =
        Number(models.model_score || 0);

    const ruleScore =
        Number(models.rule_score || 0);

    // -----------------------------------------
    // Confidence
    // -----------------------------------------
    const confidence =
        Number(result.confidence || 0);

    // Backend currently returns confidence
    // as a percentage (e.g. 64.2)
    const confidencePercent =
        confidence <= 1
            ? confidence * 100
            : confidence;

    // -----------------------------------------
    // Trusted domain
    // -----------------------------------------
    const trustedDomain =
        result.trusted_domain === true;

    // -----------------------------------------
    // Reasons
    // -----------------------------------------
    const reasons =
        Array.isArray(result.reasons)
            ? result.reasons
            : [];

    const reasonsHtml =
        reasons.length > 0
            ? reasons.map(reason => `
                <li>${escapeHtml(reason)}</li>
              `).join("")
            : "<li>No additional risk factors reported.</li>";

    // -----------------------------------------
    // Scan duration
    // -----------------------------------------
    const duration =
        durationMs !== undefined && durationMs !== null
            ? `${Number(durationMs).toFixed(0)} ms`
            : "N/A";

    // -----------------------------------------
    // Render
    // -----------------------------------------
    resultDiv.innerHTML = `
        <div class="alert ${alertClass} shadow-sm">

            <h4 class="alert-heading">
                ${icon} ${escapeHtml(riskLevel)}
            </h4>

            <p class="mb-3">
                ${escapeHtml(riskDescription)}
            </p>

            <hr>

            <p class="mb-2">
                <strong>URL:</strong>
                <code>${escapeHtml(result.url || "N/A")}</code>
            </p>

            <!-- Risk score -->
            <div class="text-center my-4">
                <div class="display-6 fw-bold">
                    ${riskScore.toFixed(1)}
                </div>

                <div class="text-muted">
                    Risk Score / 100
                </div>
            </div>

            <!-- Summary -->
            <div class="row text-center my-3">

                <div class="col-4">
                    <div class="badge bg-danger fs-6">
                        ${malicious}
                    </div>
                    <div class="small">
                        Malicious
                    </div>
                </div>

                <div class="col-4">
                    <div class="badge bg-warning text-dark fs-6">
                        ${suspicious}
                    </div>
                    <div class="small">
                        Suspicious
                    </div>
                </div>

                <div class="col-4">
                    <div class="badge bg-success fs-6">
                        ${harmless}
                    </div>
                    <div class="small">
                        Safe
                    </div>
                </div>

            </div>

            <small class="text-muted">
                VirusTotal:
                ${totalEngines} security vendors analyzed this URL.
            </small>

            <hr>

            <!-- ML information -->
            <h6 class="fw-bold">
                🤖 Machine Learning
            </h6>

            <div class="row text-center mb-3">

                <div class="col-md-4">
                    <strong>URL Model</strong>
                    <div>
                        ${urlMlScore.toFixed(1)}%
                    </div>
                </div>

                <div class="col-md-4">
                    <strong>Hostname Model</strong>
                    <div>
                        ${hostnameMlScore.toFixed(1)}%
                    </div>
                </div>

                <div class="col-md-4">
                    <strong>Model Score</strong>
                    <div>
                        ${modelScore.toFixed(1)}
                    </div>
                </div>

            </div>

            <!-- Risk engine -->
            <h6 class="fw-bold">
                🛡️ Risk Engine
            </h6>

            <div class="row text-center mb-3">

                <div class="col-md-4">
                    <strong>Rules</strong>
                    <div>
                        ${ruleScore.toFixed(1)}
                    </div>
                </div>

                <div class="col-md-4">
                    <strong>Confidence</strong>
                    <div>
                        ${confidencePercent.toFixed(1)}%
                    </div>
                </div>

                <div class="col-md-4">
                    <strong>Trusted Domain</strong>
                    <div>
                        ${trustedDomain ? "Yes" : "No"}
                    </div>
                </div>

            </div>

            <!-- Reasons -->
            <h6 class="fw-bold">
                🔎 Analysis
            </h6>

            <ul class="mb-3">
                ${reasonsHtml}
            </ul>

            <!-- Scan metadata -->
            <hr>

            <div class="small text-muted">
                <div>
                    <strong>Threat Intel:</strong>
                    ${escapeHtml(
                        threatIntel.provider || "N/A"
                    )}
                </div>

                <div>
                    <strong>Status:</strong>
                    ${escapeHtml(
                        threatIntel.status || "N/A"
                    )}
                </div>

                <div>
                    <strong>Scan Duration:</strong>
                    ${duration}
                </div>

                ${
                    result.scan_id
                        ? `
                        <div>
                            <strong>Scan ID:</strong>
                            <code>
                                ${escapeHtml(result.scan_id)}
                            </code>
                        </div>
                        `
                        : ""
                }
            </div>

        </div>
    `;
}


// =============================================================
// Utility: sleep
// =============================================================
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}


// =============================================================
// Utility: prevent HTML injection
// =============================================================
function escapeHtml(value) {

    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}