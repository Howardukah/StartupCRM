-- ============================================================
-- activity_log table migration
-- Run once in the Supabase SQL editor.
-- ============================================================

CREATE TABLE IF NOT EXISTS activity_log (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  time        timestamptz NOT NULL    DEFAULT now(),
  actor_id    text,
  actor_name  text,
  actor_type  text        NOT NULL    DEFAULT 'user',
  action      text        NOT NULL,
  target_type text,
  target_id   text,
  target_name text,
  text        text,
  ip          text,
  user_agent  text,
  source      text                    DEFAULT 'server',
  metadata    jsonb                   DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS activity_log_time_idx   ON activity_log (time DESC);
CREATE INDEX IF NOT EXISTS activity_log_actor_idx  ON activity_log (actor_id);
CREATE INDEX IF NOT EXISTS activity_log_action_idx ON activity_log (action);

ALTER TABLE activity_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_full_access" ON activity_log
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    PERFORM cron.schedule(
      'prune-activity-log-90d',
      '0 3 * * *',
      $sql$DELETE FROM activity_log WHERE time < now() - interval '90 days'$sql$
    );
  ELSE
    RAISE NOTICE 'pg_cron not installed -- skip scheduling auto-prune.';
  END IF;
END $$;

-- OPTIONAL: strip old activity from the crm blob after migration is verified:
-- UPDATE crm SET data = data - 'activity' WHERE id = 'main';

-- Verify: SELECT COUNT(*) FROM activity_log;
