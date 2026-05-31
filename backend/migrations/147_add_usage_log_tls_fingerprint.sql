-- Store a TLS fingerprint profile snapshot for admin usage diagnostics.
ALTER TABLE usage_logs
  ADD COLUMN IF NOT EXISTS tls_fingerprint JSONB;

