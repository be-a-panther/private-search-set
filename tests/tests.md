<style>
grey { color: Grey }

</style>
# Tests	

## template files

### Overview
input is always the `tests/word_list.txt`.

The userpassword is `infected` ( Base64: `aW5mZWN0ZWQ=`)

### Version 1
|Key name| V1_1 | V1_2 | <grey>V2_0</grey> | 
|:-------|:-----|:-----|:-----|
| algorithm | Blake2 | Blake2 | <grey>blake2b</grey> | 
| capacity | 100000 | 100000 |<grey>100000</grey> | 
| format | dcso-v1 | dcso-v1 | <grey>dcso-v1</grey> | 
| fp-probability | 0.001 | 0.001 | <grey>0.001</grey> |
| match-count | - | - | - | 
| canonicalization_format | null | null | <grey>null</grey> |
| generated_timestamp | 1748271567 | 1748271567 | <grey>1748271567</grey> |
|key_storage| N/A | N/A | <grey>aW5mZWN0ZWQ=</grey> | 
|version| 1 | 1 | <grey>2</grey> | 

### Version 2

|Key name| V2_0 | V2_1 | V2_2 | V2_3 | V2_4 | V2_5 | V2_6 |
|:-------|:---|:-----|:-----|:-----|:-----|:-----|:-----|
| algorithm | blake2b | blake2b | blake2b | <b>blake3</b> | <b>hmac-sha256</b> | <b>hmac-sha512</b> | blake2b | 
| capacity | 100000 | 100000 | 100000 | 100000| 100000 | 100000 | 100000 |
| format | dcso-v1 | dcso-v1 | dcso-v1 | dcso-v1 | dcso-v1 | <b>poppy-v2</b> | dcso-v1 |
| fp-probability | 0.001 | 0.001| 0.001 | 0.001 | 0.001 | 0.001 | 0.001 |
| match-count | - | - | - | - | - | - | <b>2</b> |
| canonicalization_format | null | null | null | null | null | null | null |
| generated_timestamp | 1748271567 | 1748271567 | null | null | null | null | 1748271567 |
| keyid | 01970d1b-1098-72e2-a514-1ded101bb7c7 | 01970d1b-1098-72e2-a514-1ded101bb7<b>b</b>7 | null| null| null| null| 01970d1b-1098-72e2-a514-1ded101bb7c7 
|key_storage|  aW5mZWN0ZWQ= | aW5mZWN0ZWQ= | aW5mZWN0ZWQ= | aW5mZWN0ZWQ= | aW5mZWN0ZWQ= | aW5mZWN0ZWQ= | <b>null</b> |
|version|  2 | 2 | 2 | 2 | 2 | 2 | 2 |

## speedtest

The input content is the regulary `rockyou.txt` with 14344391 lines.

1. V1
2. V2 dcso-v1
3. V2 poppy-v2
4. V2 dcso-v1   bloomfilter only
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
