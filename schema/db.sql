CREATE TABLE IF NOT EXISTS metadata (
    metadata_set VARCHAR(32) NOT NULL,
    entity_id VARCHAR(255),
    entity_data TEXT NOT NULL,
    UNIQUE (metadata_set , entity_id)
);

CREATE TABLE IF NOT EXISTS db_changelog (
    patch_number INTEGER NOT NULL,
    description TEXT NOT NULL,
    PRIMARY KEY (patch_number)
);
