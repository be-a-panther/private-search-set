# Tests

## template files

### Overview
input is always the `tests/word_list.txt`.

The password is `infected` ( Base64: `aW5mZWN0ZWQK=`)

|Key name| V1_1 | V1_2 | V2_0 | V2_1 | V2_2 | V2_3 | V2_4 | V2_5 | V2_6 |
|:-------|:---|:-----|:---|:-----|:-----|:-----|:-----|:-----|:-----|
| algorithm | Blake2 | Blake2 | blake2b | blake2b | blake2b | blake3 | hmac-sha256 | hmac-sha512 | blake2b | 
| capacity | 100000 | 100000 | 100000 | 100000| 100000 | 100000 | 100000 | 100000 | 100000 |
| format | dcso-v1 | dcso-v1 | dcso-v1 | dcso-v1 | dcso-v1 | dcso-v1 | dcso-v1 | poppy-v2 | dcso-v1 |
| fp-probability | 0.001 | 0.001 | 0.001 | 0.001| 0.001 | 0.001 | 0.001 | 0.001 | 0.001 |
| match-count | - | - | - | - | - | - | - | - | 2 |
| canonicalization_format | null | null | null | null | null | null | null | null | null |
| generated_timestamp | 1748271567 | 1748271567 | 1748271567 | 1748271567 | null | null | null | null | 1748271567 |
| keyid | deadbeef0xff | null| 01970d1b-1098-72e2-a514-1ded101bb7c7 | 01970d1b-1098-72e2-a514-1ded101bb7<b>b</b>7 | null| null| null| null| 01970d1b-1098-72e2-a514-1ded101bb7c7 
|key_storage| N/A | N/A | aW5mZWN0ZWQK= | aW5mZWN0ZWQK= | aW5mZWN0ZWQK= | aW5mZWN0ZWQK= | aW5mZWN0ZWQK= | aW5mZWN0ZWQK= |  |
|version| 1 | 1 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |