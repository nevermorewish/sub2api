-- Store a redacted request-header snapshot for admin usage diagnostics.
ALTER TABLE usage_logs
  ADD COLUMN IF NOT EXISTS request_headers JSONB;
