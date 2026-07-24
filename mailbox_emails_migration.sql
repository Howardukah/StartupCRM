-- Create mailbox_emails table for internal fully-managed Resend mailbox
CREATE TABLE IF NOT EXISTS mailbox_emails (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  message_id text NOT NULL,
  folder text NOT NULL DEFAULT 'inbox', -- 'inbox' | 'sent'
  from_name text,
  from_email text NOT NULL,
  to_email text NOT NULL,
  cc text,
  subject text,
  body text,
  html text,
  attachments jsonb DEFAULT '[]'::jsonb, -- metadata [ { filename, storagePath, contentType, size } ]
  unread boolean DEFAULT true,
  in_reply_to text,
  references_header text,
  created_at timestamptz DEFAULT now(),
  UNIQUE (user_id, message_id)
);

-- Index for optimized mail retrieval per user/folder
CREATE INDEX IF NOT EXISTS idx_mailbox_emails_user_folder 
ON mailbox_emails (user_id, folder, created_at DESC);
