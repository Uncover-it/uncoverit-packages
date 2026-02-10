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
