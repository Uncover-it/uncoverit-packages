import asyncio
import hashlib
import os
import aiohttp
import websockets
import re
import pefile
import aiofiles
import sys

from .classes import Sample
from .exceptions import InvalidApiKey, InvalidHash, InvalidFile, Timeout, InvalidApiResponse

from typing import Optional
from websockets import WebSocketClientProtocol
from pefile import PEFormatError

ws_endpoint = "wss://api.uncoverit.org/websocket"
key_endpoint = "https://uncoverit.org/api"
api_endpoint = "https://api.uncoverit.org/private"

class UncoveritClient:
    """
    Async API client for uncoverit.org
    """
    def __init__(self, api_key: str, session: Optional[aiohttp.ClientSession] = None):
        self.api_key: str = api_key
        self.requests_left: int = -1
        self.expiration_date: str = ""

        self.sha256_regex = re.compile(r"\b[0-9a-fA-F]{64}\b")
        self.sha512_regex = re.compile(r"\b[0-9a-fA-F]{128}\b")

        self._session = session
        self._managed_session = False
    
    @classmethod
    async def create(cls, api_key: str, session: Optional[aiohttp.ClientSession] = None):
        """
        Asynchronously creates and initializes an Uncoverit client instance.

        This factory method is the preferred way to instantiate the class. It 
        establishes the network session and performs an initial API key validation 
        to ensure the client is ready for use.

        Args:
            api_key (str): Your Uncoverit API key.
            session (Optional[aiohttp.ClientSession]): An existing aiohttp session 
                to reuse. If None, a new session is created automatically. You MUST
                supply the auth headers in this case!

        Returns:
            Uncoverit: An initialized instance of the Uncoverit client.

        Raises:
            InvalidApiKey: If the provided API key is rejected by the server or 
                the balance is zero.
            InvalidApiResponse: If the server returns an error during the 
                initialization handshake.
        """
        instance = cls(api_key, session)
        auth_header = {"Authorization": api_key}    
        
        if instance._session is None:
            instance._session = aiohttp.ClientSession(headers=auth_header)
            instance._managed_session = True
            
        try:
            if not await instance.__validate_api_key():
                if instance._managed_session:
                    await instance.close()
                raise InvalidApiKey("Invalid api key or balance 0")
        except Exception:
            if instance._managed_session:
                await instance.close()
            raise
            
        return instance
    
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._managed_session:
            await self.close()
    
    async def __validate_api_key(self) -> bool:
        """INTERNAL DO NOT USE: Validates API key by checking balance"""
        self.requests_left = await self.check_balance(cached=True)
        if self.requests_left <= 0:
            return False
        return True
    
    def __is_valid_pe(self, filepath: str) -> bool:
        """INTERNAL DO NOT USE: Verifies if the file is a valid PE"""
        try:
            pefile.PE(filepath, fast_load=True).close()
            return True
        except PEFormatError:
            return False

def __is_valid_elf(self, filepath: str) -> bool:
    """INTERNAL DO NOT USE: Verifies if the file is a valid ELF"""
    with open(filepath, "rb") as file:
        return file.read(4) == b"\x7fELF"

    def __is_valid_msi(self, filepath: str) -> bool:
        """INTERNAL DO NOT USE: Verifies if the file is a valid MSI"""
        with open(filepath, "rb") as file:
            data = file.read(8)
            if len(data) < 8:
                return False
            return data == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    
    async def _handle_ws_messages(self, websocket: WebSocketClientProtocol, sha256_hash: str) -> Optional[Sample]:
        """INTERNAL DO NOT USE: Handles ws messages"""
        async for msg in websocket:
            if msg == "UPDATE:STATIC_COMPLETED":
                return await self.fetch_static_report(sha256_hash)
        return None
    
    async def close(self) -> None:
        """Asynchronously cleans up and disposes the client"""
        if self._session and not self._session.closed:
            await self._session.close()
            if sys.platform == 'win32':
                await asyncio.sleep(0.25)

    async def sha256_checksum(self, filepath: str) -> str:
        """
        Asynchronously calculates the sha256 hash for the given file

        Args:
            filepath (str): Filepath

        Returns:
            sha256 (str): Calculated sha256 hash

        Raises:
            FileNotFoundError: If the file does not exist
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError("File does not exist!")
        
        sha256 = hashlib.sha256()
        async with aiofiles.open(filepath, mode='rb') as f:
            while True:
                block = await f.read(65536)
                if not block:
                    break
                sha256.update(block)
        return sha256.hexdigest()
    
    async def check_balance(self, cached: bool = False) -> int:
        """
        Checks the balance for the api key that was initalized with the client.

        Returns:
            balance (int): The leftover balance

        Raises:
            InvalidApiResponse: Incase of a non 200 HTTP status code
        """
        if cached and self.requests_left != -1:
            return self.requests_left
        
        url = f"{key_endpoint}/balance"
        async with self._session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                self.requests_left = data.get("requests_left",0)
                self.expiration_date = data.get("expiration_date","Unknown")
                return self.requests_left
            raise await InvalidApiResponse.from_response(response)                
    
    def validate_hash(self, hash: str) -> bool:
        """
        Validates the given hash

        Args:
            hash (str): The file hash

        Returns:
            True (bool): If the hash is sha256, blake3 or sha512 else False
        """
        if len(hash) == 64:
            return bool(self.sha256_regex.fullmatch(hash))
        
        if len(hash) == 128:
            return bool(self.sha512_regex.fullmatch(hash))
        
        return False
    
    def validate_file(self, filepath: str) -> bool:
        """
        Validates the given file if its usable for analysis

        Args:
            filepath (str): The path to the file

        Returns:
            True (bool): If the file can be uploaded for analysis else False

        Raises:
            FileNotFoundError: If the file does not exist
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError("File does not exist!")
        
        if self.__is_valid_pe(filepath):
            return True
        
        if self.__is_valid_elf(filepath):
            return True
        
        if self.__is_valid_msi(filepath):
            return True
        
        return False

    async def upload_sample(self, filepath: str) -> Optional[Sample]:
        """
        Uploads the given file for analysis and returns the Sample data.
        This functions also tracks the leftover balance locally.

        Args:
            filepath (str): The path to the file to be uploaded

        Returns:
            sample (Sample): If the file was uploaded successfully

        Raises:
            FileNotFoundError: If the file does not exist
            InvalidFile: If the file is not suitable for upload
            InvalidApiResponse: Incase of a non 200 HTTP status code
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError("File does not exist!")
        
        if not self.validate_file(filepath):
            raise InvalidFile("Only PE's and ELF's are supported currently!")
        
        sha256_hash = await self.sha256_checksum(filepath)
        url = f"{ws_endpoint}?hash={sha256_hash}&apikey={self.api_key}"
        async with websockets.connect(url) as websocket:
            message = await websocket.recv()
            
            if message != "STATUS:UPLOAD_REQUIRED":
                return await self.fetch_static_report(sha256_hash)

            async with aiofiles.open(filepath, mode="rb") as f:
                data = aiohttp.FormData()
                data.add_field('file', f, filename=os.path.basename(filepath))
                    
                async with self._session.post(f"{api_endpoint}/upload", data=data) as response:
                    self.requests_left -= 1
                    if response.status != 200:
                        await websocket.close()
                        raise await InvalidApiResponse.from_response(response)
                    
            try:
                return await asyncio.wait_for(self._handle_ws_messages(websocket, sha256_hash), timeout=5)
            except asyncio.TimeoutError:
                raise Timeout("Upload timed out.")


    async def fetch_static_report(self, hash: str) -> Optional[Sample]:
        """
        Fetches the static analysis sample data for the given sha256, sha512 or blake3 hash

        Args:
            hash (str): The sha256, sha512 or blake3 hash

        Returns:
            sample (Sample): If sample data was retrieved successfully

        Raises:
            InvalidHash: If the hash is not sha256, sha512 or blake3
            InvalidApiResponse: Incase of a non 200 HTTP status code
        """
        if not self.validate_hash(hash):
            raise InvalidHash("Invalid hash! Supported hashes: SHA256, SHA512, BLAKE3")
        
        async with self._session.get(f"{api_endpoint}/sample/{hash}") as response:
            self.requests_left -= 1
            if response.status == 200:
                data = await response.json()
                sample = Sample.model_validate(data)
                sample.json_obj = data
                return sample
            if response.status == 404:
                return None
            raise await InvalidApiResponse.from_response(response)
        return None
