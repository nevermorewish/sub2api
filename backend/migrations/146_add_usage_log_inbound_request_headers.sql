-- Store redacted client-to-sub2api request headers separately from upstream request headers.
ALTER TABLE usage_logs
  ADD COLUMN IF NOT EXISTS inbound_request_headers JSONB;

