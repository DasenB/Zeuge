CREATE KEYSPACE proof WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

USE proof;

CREATE TABLE proofs_by_hash (
                                hash text PRIMARY KEY,
                                public_key text,
                                timestamp timestamp,
                                comment text,
                                signature text
);

CREATE TABLE proofs_by_pubkey (
                                  public_key text,
                                  timestamp timestamp,
                                  hash text,
                                  comment text,
                                  signature text,
                                  PRIMARY KEY (public_key, timestamp)
) WITH CLUSTERING ORDER BY (timestamp DESC);

CREATE TABLE proofs_by_day (
                               day text,
                               timestamp timestamp,
                               hash text,
                               public_key text,
                               comment text,
                               signature text,
                               PRIMARY KEY (day, timestamp)
) WITH CLUSTERING ORDER BY (timestamp DESC);
