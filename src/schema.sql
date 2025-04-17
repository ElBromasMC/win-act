-- schema.sql
DROP TABLE IF EXISTS keys;
DROP TABLE IF EXISTS activations;

CREATE TABLE keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  -- Statuses: AVAILABLE, PENDING, ACTIVATED, FAILED
  status TEXT DEFAULT 'AVAILABLE' NOT NULL
);

CREATE TABLE activations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  serial_number TEXT NOT NULL,
  key_used TEXT NOT NULL,
  activation_time TEXT NOT NULL -- Time when key was *retrieved* via /activate
);

-- Add index on status for faster lookups by /activate
CREATE INDEX idx_keys_status ON keys (status);

