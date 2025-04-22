CREATE TABLE IF NOT EXISTS protected_urls (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    roles INT[] NOT NULL
);