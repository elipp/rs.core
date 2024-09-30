-- Add migration script here

CREATE TABLE account (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    salt BYTEA NOT NULL,
    verifier BYTEA NOT NULL,
    gmlevel INT NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT true
);

