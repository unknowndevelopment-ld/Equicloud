CREATE TABLE IF NOT EXISTS users (
  discord_id TEXT PRIMARY KEY,
  auth_secret TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS settings (
  discord_id TEXT PRIMARY KEY REFERENCES users(discord_id) ON DELETE CASCADE,
  object_key TEXT NOT NULL,
  etag TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS sync_data (
  discord_id TEXT NOT NULL REFERENCES users(discord_id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  object_key TEXT NOT NULL,
  version INTEGER NOT NULL,
  checksum TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (discord_id, key)
);

CREATE INDEX IF NOT EXISTS sync_data_user_idx ON sync_data(discord_id);
