# Versions

## json template
|Key name| Version 1 | Version 2 |Description|
|:-------|:----------|:----------|:----------|
|algorithm| Blake2 | blake2b<br/>blake3<br/>hmac-sha256<br/>hmac-sha512|used keyed hash algorithm|
|format/filter | :-/ | &cross; | Version 2 steps ahead|
|filters | &cross;| &check; | Version 1 revers to it as filter or format<br>Version 2 takes it as container |
|misp-feed-cache | &cross; | &cross; | Not defined |
|bloomfilter| python-flor | rust-poppy | currently only bloomfilter support |
|capacity| &check; | &check; | the capacity |
|format| &check; | &check; | Version 1: only dcso-v1<br/>Version 2: dcso-v1 and poppy-v2
|fp-probability| &check; | &check; | change for plausible deniability|
|match-count| &cross; | &check; | Version 1 defines it, but didn't implement it<br/> |
|canonicalization_format| &cross;| &check; | Version 1 defines it, but didn't implement it |
|description| &check; | &check; | freetext. e.g.: <br/> `{TLP}|{given-by}|{origin}|{creator}`|
|generated_timestamp| &check; | &check; | Version 2 generate timestamp if none is provided|
|keyid| - | &check;| Version 1 contains a clear-text<br/>UUIDv7 in combination with key_storage or userpassword<br/> UUIDv8 delegates the key acquiring|
|key_storage| &cross;| &check; | base64-encoded<br/>UUIDv7 can store the clear-text userpassword<br/>UUIDv8 can use it as blob |
|misp_attribute_types| &check; | &check; | consider items a canonicalization_format selector|
|misp-object-template | &cross; | &cross; | |
|openpgp-encrypted-key | &cross; | &cross; |Version 1 defines it, but didn't implement it<br/>Version 2 renamed it to `key_storage`  |
|version| &check; | &check; | |

## cli

|param| Version 1 | Version 2 | Type | Description |
|:----|:----------|:----------|:-----|:------------|
|pss-home| &check; | &check; | PATH | PSS working folder.  [required]|
|json-file| &check; | &check; | PATH | ingest: Path to the PSS JSON template file<br/> :q |
|ingest| &check; | &check; | switch | ingest or check stdin into/against PSS |
|check|  &check; | &check; |  switch | ingest or check stdin into/against PSS |
|bf| &check; | &check; | switch | V1: check only bloom filter <br/> V2: check/ingest only bloom filter |
|timeseries| &cross; | &check; | switch | keep newly added items also in a new bloomfilter |
|key| &check; | &cross; | TEXT | specify direct input for HMAC operations |
|password| &cross; | &check; | TEXT | specify password for scrypt to generate HMAC key operations |
|debug| &check; | &check; | switch | print debug information|
|help| &check; | &check; | switch | Show this message and exit.|

## speedtest

The input content is the regulary rockyou.txt with 14344391 lines.

1. V1
2. V2 dcso-v1
3. V2 poppy-v2
4. V2 dcso-v1   blommfilter only
5. V2 poppy-v2  bloomfilter only

testing the ingest speed for different templates.

```
(.venv) [user@self private-search-set]$ time bash -c "cat rockyou.txt | private-search-set --pss-home=tests/V1_benchmark  --ingest --json-file tests/templateV1_rockyou.json "
Ingesting stdin to PSS file.
real	11m20,198s
user	11m12,103s
sys		0m3,626s

(.venv) [user@self private-search-set]$ time bash -c "cat rockyou.txt | private-search-set --pss-home=tests/V2_benchmark  --ingest --json-file tests/templateV2_rockyou.json "
Ingesting stdin to PSS file.
real	0m52,753s
user	0m49,311s
sys		0m3,007s

(.venv) [user@self private-search-set]$ time bash -c "cat rockyou.txt | private-search-set --pss-home=tests/V2_benchmark-v2  --ingest --json-file tests/templateV2_rockyou-v2.json "
Ingesting stdin to PSS file.
real	0m46,386s
user	0m42,960s
sys		0m3,042s


(.venv) [user@self private-search-set]$ time bash -c "cat rockyou.txt | private-search-set --pss-home=tests/V2_benchmark-bf  --ingest --bf --json-file tests/templateV2_rockyou.json "
Ingesting stdin to PSS file.
real	0m38,602s
user	0m37,880s
sys		0m0,454s

(.venv) [user@self private-search-set]$ time bash -c "cat rockyou.txt | private-search-set --pss-home=tests/V2_benchmark-v2bf  --ingest --bf --json-file tests/templateV2_rockyou-v2.json "
Ingesting stdin to PSS file.
real	0m32,326s
user	0m31,571s
sys		0m0,495s

```

and now the check:

```
(.venv) [user@self private-search-set]$ time bash -c "cat rockyou.txt | private-search-set --pss-home=tests/V1_benchmark  --check "
real	3m55,442s
user	1m41,676s
sys		2m10,939s
(.venv) [user@self private-search-set]$ time bash -c "cat rockyou.txt | private-search-set --pss-home=tests/V1_benchmark  --check 1>/dev/null " 
real	0m46,639s
user	0m44,312s
sys		0m1,962s

(.venv) [user@self private-search-set]$ time bash -c "cat rockyou.txt | private-search-set --pss-home=tests/V2_benchmark-bf  --check 1>/dev/null "
real	0m46,130s
user	0m45,022s
sys		0m0,495s

(.venv) [user@self private-search-set]$ time bash -c "cat rockyou.txt | private-search-set --pss-home=tests/V2_benchmark-v2  --check 1>/dev/null "
real	0m51,554s
user	0m48,991s
sys		0m1,948s

(.venv) [user@self private-search-set]$ time bash -c "cat rockyou.txt | private-search-set --pss-home=tests/V2_benchmark-v2bf  --check 1>/dev/null "
real	0m42,922s
user	0m41,780s
sys		0m0,518s

```

## bruteforce for ipv4

## nice to known
