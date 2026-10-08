-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE IF NOT EXISTS execution_grants (
    scope TEXT NOT NULL, operation TEXT NOT NULL, binding TEXT NOT NULL,
    event TEXT NOT NULL, acknowledgement TEXT, custody TEXT,
    PRIMARY KEY(scope,operation)
);
CREATE TABLE IF NOT EXISTS execution_streams (
    scope TEXT PRIMARY KEY, registration TEXT NOT NULL
);
