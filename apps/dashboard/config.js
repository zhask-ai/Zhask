// IntegriShield Dashboard — Runtime Configuration
// LOCAL DEV: points to local backend
// PRODUCTION: this file is replaced by GitHub Actions with the real backend URL
window.__INTEGRISHIELD_API = (
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1"
    ? "http://localhost:8787"
    : null  // replaced at deploy time → see .github/workflows/deploy.yml
);
