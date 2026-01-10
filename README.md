# Uncover it packages

## NPM

### Installation
```shell 
npm i uncoverit
```

### Usage

```js
import { fetchBalance, exists, upload, staticReport } from "uncoverit";

// exported types
import { BalanceResponseType, UploadResponseType, StaticAnalysisDataType }
```

Fetching balance:
```js
await fetchBalance(apiKey);
```
Example Response:
```json
{ 
  "requests_left": 1000, 
  "expiration_date": "2024-08-26T10:00:00Z"
}
```

Checking if file exists (Upload function already does this:
```js
await exists(apiKey, file); // file can be a File, Blog or a SHA-256 hash string
```
Example Response:
```
true
```

Uploading a file:
```js
await upload(apiKey, file); // file can be a File or a Blob
```
Example Response:
```json
{ "blake3Hash": "8347c2669ff2a7d5a1c2e73171bec5c36e3ac5654699c20a622ebf24860255c8" }
```

Fetching a static analysis report:
```js
await staticReport(apiKey, hash); // hash can be SHA-256, SHA-512 or BLAKE3
```
Example Response:
```json
{
  "date": "2024-08-26T10:00:00Z",
  "blake3Hash": "8347c2669ff2a7d5a1c2e73171bec5c36e3ac5654699c20a622ebf24860255c8",
  "sha512Hash": "8b16496acb3c6671439588287940817892c8920249c4bc967072c537a826afb398d381ff654a196726c0763e129e24c4660dfa39cfc5e42ffa14eacf558af61a",
  "sha256Hash": "2c2751b069c34f810f152dd13b6c527d20d1ac6552f2ea702da1c1fb7b0c505b",
  "sha1Hash": "22dff75a842daeff1919b5fae8bcb2785193873e",
  "mD5Hash": "3e0b4724c6cb604ffef0c10dcff400de",
  "ssDeep": "3072:Xc1GZ7XaS7pNifbi+nIhROuvgGUVrYdVCQ2zrUIx0Exaa2kAHRKdey6rOaxrmKSQ:Xc1G1XJp+bzASHzwIx0tEAHREeKam",
  "fileName": "AccountGrabber.exe",
  "sizeInBytes": 270336,
  "tags": [
    {
      "name": "RAT",
      "heat": 1,
    }, {
      "name": "XWORM",
      "heat": 10,
    }
  ],
  "configs": {
    "XWORM": {
      "C2s": "example.com",
      "Ports": "8080",
      "Traffic Encryption Key": "<123456789>",
      "Mutex": "A9lWJ0tQCdsEozbm",
      "Delimiter": "<Xwormmm>",
      "Version": "XWorm V5.2",
      "Bitcoin Address": "0xfaF7bFf63a4C43d6D05eA8733911df2111c3238e",
      "Telegram Bot Token": "8120265505:AAFwq8bHiPgQsIrf26384ddYSCnMRcKVrN0",
      "Telegram Chat Id": "-4916970420",
    },
  },
  "staticAnalysisDuration": "00:00:00.0427370",
}
```


## PIP

### Installation
```shell 
pip install uncoverit
```

### Usage

```py
from uncoverit import UncoveritClient
from uncoverit.exceptions import *
```

Fetching balance:
```py
from uncoverit import UncoveritClient
async with await UncoveritClient.create(api_key) as client:
    print(f"Requests left: {client.requests_left}") # set and tracked internally
    print(f"Requests left: {await client.check_balance()}") # makes a http request to fetch the balance
    # prints "Requests left: 1000"
```
Checking if file exists (Upload function already does this:
```py
from uncoverit import UncoveritClient
async with await UncoveritClient.create(api_key) as client:
    fetched_sample = await client.fetch_static_report("a9e6ea632d75dfd3fa741bhd3659ac5e1423533dfa71c64720d48837cf61fd73")
    # fetched_sample here is None
```

Uploading a file:
```py
from uncoverit import UncoveritClient
async with await UncoveritClient.create(api_key) as client:
    # upload a file and get its analysis information
    uploaded_sample = await client.upload_sample("malware.exe")
    print(uploaded_sample.configs)
    print(uploaded_sample.tags)
    print(uploaded_sample.sha1)
    print(uploaded_sample.ssdeep)
    print(uploaded_sample.md5)
```

Fetching a static analysis report:
```py
from uncoverit import UncoveritClient
async with await UncoveritClient.create(api_key) as client:
    fetched_sample = await client.fetch_static_report("e9e6ea632d75dfd3fa741b4d3659ac5e1423533dfa71c64720d48837cf61fd73")
    print(fetched_sample.json_obj.get("configs")) # print the configs from the json object
    print(fetched_sample.configs) # or get it from the sample
    print(fetched_sample.duration) # static analysis duration

```
