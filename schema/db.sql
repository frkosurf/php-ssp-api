CREATE TABLE metadata (
    metadata_set VARCHAR(32) NOT NULL,
    entity_id VARCHAR(255),
    revision_id INTEGER DEFAULT 0,
    revision_note TEXT DEFAULT NULL,
    entity_data TEXT NOT NULL,
    UNIQUE (metadata_set , entity_id , revision_id)
);
