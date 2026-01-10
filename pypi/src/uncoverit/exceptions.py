import json
import aiohttp
class InvalidApiKey(Exception):
    pass
class InvalidHash(Exception):
    pass
class InvalidFile(Exception):
    pass
class Timeout(Exception):
    pass
class InvalidApiResponse(Exception):
    def __init__(self, status, data):
        self.status = status
        self.data = data
        self.message = f"API Error {status}: {json.dumps(data, indent=2)}"
        super().__init__(self.message)

    @classmethod
    async def from_response(cls, response: aiohttp.ClientResponse):
        try:
            data = await response.json()
        except (aiohttp.ContentTypeError, json.JSONDecodeError):
            data = {"raw_body": await response.text()}
        
        return cls(response.status, data)