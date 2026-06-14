async function scanURL() {
    const urlInput = document.getElementById("url");
    const url = urlInput.value.trim();
    const resultDiv = document.getElementById("result");

    // Validate input
    if (!url) {
        resultDiv.innerHTML = `
            <div class="alert alert-warning">
                <h4>⚠️ Invalid Input</h4>
                <p>Please enter a URL to scan.</p>
            </div>
        `;
        return;
    }

    // Show loading state
    resultDiv.innerHTML = `
        <div class="alert alert-info">
            <div class="spinner-border spinner-border-sm me-2" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <strong>Scanning URL...</strong> Please wait.
        </div>
    `;

    try {
        const formData = new FormData();
        formData.append("url", url);

        const response = await fetch("/scan", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (data.risk === "Error") {
            resultDiv.innerHTML = `
                <div class="alert alert-danger">
                    <h4>❌ Error</h4>
                    <p>${data.message || "An error occurred during scanning."}</p>
                </div>
            `;
            return;
        }

        // Determine alert class based on risk
        let alertClass = "alert-success";
        let icon = "✅";
        
        if (data.risk === "Phishing") {
            alertClass = "alert-danger";
            icon = "🚨";
        } else if (data.risk === "Suspicious") {
            alertClass = "alert-warning";
            icon = "⚠️";
        }

        let mlInfo = "";
        if (data.ml_prediction && data.confidence) {
            mlInfo = `
                <hr>
                <p><strong>ML Prediction:</strong> ${data.ml_prediction}</p>
                <p><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(2)}%</p>
            `;
        }

        resultDiv.innerHTML = `
            <div class="alert ${alertClass}">
                <h4>${icon} Risk Level: ${data.risk}</h4>
                <p><strong>URL:</strong> ${data.url}</p>
                <hr>
                <p><strong>Malicious Vendors:</strong> ${data.malicious}</p>
                <p><strong>Suspicious Vendors:</strong> ${data.suspicious}</p>
                <p><strong>Trusted Vendors:</strong> ${data.harmless}</p>
                ${mlInfo}
                <small class="text-muted">Scanned at: ${new Date(data.timestamp).toLocaleString()}</small>
            </div>
        `;

    } catch (error) {
        console.error("Scan error:", error);
        resultDiv.innerHTML = `
            <div class="alert alert-danger">
                <h4>❌ Network Error</h4>
                <p>Failed to connect to the server. Please try again later.</p>
                <small class="text-muted">${error.message}</small>
            </div>
        `;
    }
}

// Allow Enter key to trigger scan
document.addEventListener("DOMContentLoaded", function() {
    const urlInput = document.getElementById("url");
    if (urlInput) {
        urlInput.addEventListener("keypress", function(event) {
            if (event.key === "Enter") {
                event.preventDefault();
                scanURL();
            }
        });
    }
});