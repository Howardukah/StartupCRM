-- 1. Create asset_buckets table (per-project Backblaze B2 asset bucket)
CREATE TABLE IF NOT EXISTS asset_buckets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token text UNIQUE NOT NULL,
  project_id text NOT NULL,
  project_name text NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz DEFAULT now(),
  revoked boolean DEFAULT false,
  client_email text,
  quota_bytes bigint DEFAULT 2147483648   -- default 2 GB per bucket
);

-- 2. Create assets table (files stored in Backblaze B2, metadata in Supabase)
CREATE TABLE IF NOT EXISTS assets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id text NOT NULL,
  bucket_id uuid REFERENCES asset_buckets(id) ON DELETE CASCADE,
  filename text NOT NULL,
  size_bytes bigint NOT NULL,
  content_type text NOT NULL,
  storage_path text NOT NULL,
  uploaded_at timestamptz DEFAULT now(),
  client_name text
);

-- If you already created asset_buckets earlier, run these to add the new columns:
-- ALTER TABLE asset_buckets ADD COLUMN IF NOT EXISTS revoked boolean DEFAULT false;
-- ALTER TABLE asset_buckets ADD COLUMN IF NOT EXISTS client_email text;
-- ALTER TABLE asset_buckets ADD COLUMN IF NOT EXISTS quota_bytes bigint DEFAULT 2147483648;

-- Note: Row Level Security (RLS) is disabled by default for new tables.
-- Since the server uses the service_role key, it can query and modify these tables freely.
