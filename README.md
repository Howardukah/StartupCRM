# Startup Build Unified Platform

An Express-based Node.js backend serving both the Startup CRM and Client Asset Storage Portal under one host with subdomain routing:

- `crm.startupbuild.tech`: admin sprint planner and client relations board.
- `storage.startupbuild.tech`: client asset uploading and management portal.

## Database Setup (Supabase)

Run the contents of [supabase_setup.sql](supabase_setup.sql) in the Supabase SQL editor. This provisions:

- `asset_buckets`: per-project upload links and bucket metadata.
- `assets`: uploaded file metadata stored in Supabase.

## File Storage Setup (Backblaze B2)

The storage portal uses Backblaze B2 through its S3-compatible API.

1. Create or choose a B2 bucket.
2. Create an application key with access to that bucket.
3. Set the B2 environment variables listed in [.env.example](.env.example).

Required B2 variables:

```env
B2_KEY_ID=your_backblaze_key_id
B2_APP_KEY=your_backblaze_application_key
B2_ENDPOINT=https://s3.us-west-004.backblazeb2.com
B2_BUCKET_NAME=your-b2-bucket-name
```

## Environment Variables

Create a `.env` file in the root folder matching [.env.example](.env.example). At minimum, the app expects:

```env
GROQ_API_KEY=gsk_...
PORT=8787
PLANS_DIR=./PDF
ENCRYPTION_KEY=your_aes_encryption_key
SUPABASE_URL=https://...supabase.co
SUPABASE_SERVICE_KEY=your_service_role_key
B2_KEY_ID=your_backblaze_key_id
B2_APP_KEY=your_backblaze_application_key
B2_ENDPOINT=https://s3.us-west-004.backblazeb2.com
B2_BUCKET_NAME=your-b2-bucket-name
```

## Local Development

Install dependencies:

```bash
npm install
```

Start the server:

```bash
npm start
```

Local URLs:

- CRM: `http://localhost:8787/index.html`
- Storage portal: `http://localhost:8787/storage.html`

## Production Deployment (Render)

This platform is configured for Render using [render.yaml](render.yaml).

1. Connect the repository in Render.
2. Add the environment variables listed in `.env.example`.
3. Point both subdomains to the Render web app domain:

- `crm.startupbuild.tech`
- `storage.startupbuild.tech`
