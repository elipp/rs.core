-- Add migration script here

CREATE TABLE account (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    salt BYTEA NOT NULL,
    CONSTRAINT salt_is_32_bytes CHECK (octet_length(salt) = 32)
    verifier BYTEA NOT NULL,
    CONSTRAINT verifier_is_32_bytes CHECK (octet_length(verifier) = 32)
    gmlevel INT NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT true,
);

