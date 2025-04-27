DROP KEYSPACE zeuge;

CREATE KEYSPACE zeuge WITH replication = {
    'class': 'SimpleStrategy',
    'replication_factor': 1
    };

USE zeuge;

CREATE TABLE proofs_by_hash (
                                hash text PRIMARY KEY,
                                public_key text,
                                timestamp timestamp,
                                comment text,
                                signature text,
                                algorithm text
);

CREATE TABLE proofs_by_pubkey (
                                  public_key text,
                                  timestamp timestamp,
                                  hash text,
                                  comment text,
                                  signature text,
                                  algorithm text,
                                  PRIMARY KEY ((public_key), timestamp)
) WITH CLUSTERING ORDER BY (timestamp DESC);

CREATE TABLE proofs_by_block (
                                 block text,
                                 timestamp timestamp,
                                 hash text,
                                 public_key text,
                                 comment text,
                                 signature text,
                                 algorithm text,
                                 PRIMARY KEY ((block), timestamp)
) WITH CLUSTERING ORDER BY (timestamp DESC);
