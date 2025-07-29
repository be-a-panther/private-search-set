# Versions

## json template
|Key name| Version 1 | Version 2 |Description|
|:-------|:----------|:----------|:----------|
|algorithm| Blake2 | blake2b<br/>blake3<br/>hmac-sha256<br/>hmac-sha512|used keyed hash algorithm|
|format/filter | (&cross;) | &cross; | Version 1 didn't implement this<br/>Version 2 steps ahead|
|filters | &cross;| &check; | Version 1 revers to it as `filter` or `format`<br>Version 2 takes it as container |
|misp-feed-cache | &cross; | &cross; | Not defined |
|bloomfilter| python-flor | rust-poppy | currently only bloomfilter support |
|capacity| &check; | &check; | the capacity |
|format| &check; | &check; | Version 1: only dcso-v1<br/>Version 2: dcso-v1 and poppy-v2
|fp-probability| &check; | &check; | change for plausible deniability |
|match-count| &cross; | &check; | Version 1 defines it, but didn't implement it<br/> |
|canonicalization_format| (&check;) | &check; | Version 1 defines it, but didn't implement it |
|description| &check; | &check; | freetext. e.g.: <br/> `{TLP}_{given-by}_{origin}_{creator}`|
|generated_timestamp| &check; | &check; | Version 2 generate timestamp if none is provided|
|keyid| (&check;) | &check;| Version 1 contains a clear-text<br/>UUIDv7 in combination with key_storage or userpassword<br/> UUIDv8 delegates the key acquiring|
|key_storage| &cross;| &check; | base64-encoded<br/>UUIDv7 can store the clear-text userpassword<br/>UUIDv8 can use it as blob |
|misp_attribute_types| &check; | &check; | consider items a canonicalization_format selector|
|misp-object-template | &cross; | &cross; | not implemented|
|name | &cross; | &cross; | Version 1: not implemented<br/>Version 2: only virtual via file path |
|openpgp-encrypted-key | &cross; | &cross; |Version 1 defines it, but didn't implement it<br/>Version 2 renamed it to `key_storage`  |
|version| &check; | &check; | |

## cli

|param| Version 1 | Version 2 | Type | Description |
|:----|:----------|:----------|:-----|:------------|
|pss-home| &check; | &check; | PATH | PSS working folder.  [required]<br/>Version 2: variable `_name` |
|json-file| &check; | &check; | PATH | ingest: Path to the PSS JSON template file<br/>|
|ingest| &check; | &check; | switch | ingest stdin into PSS |
|check|  &check; | &check; |  switch | check stdin against PSS |
|bf| &check; | &check; | switch | V1: check only bloom filter <br/> V2: check/ingest only bloom filter |
|timeseries| &cross; | &check; | switch | keep newly added items also in a new bloomfilter |
|key| &check; | &cross; | TEXT | specify direct input for HMAC operations |
|password| &cross; | &check; | TEXT | specify password for scrypt to generate HMAC key operations |
|debug| &check; | &check; | switch | print debug information|
|help| &check; | &check; | switch | Show this message and exit.|

