from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class Tag(BaseModel):
    name: str
    heat: int

class Sample(BaseModel):
    blake3  : str = Field(alias="blake3Hash")
    sha1    : str = Field(alias="sha1Hash")
    sha256  : str = Field(alias="sha256Hash")
    sha512  : str = Field(alias="sha512Hash")
    ssdeep  : str = Field(alias="ssDeep")
    md5     : str = Field(alias="mD5Hash")

    file_name   : str = Field(alias="fileName")
    file_size_b : int = Field(alias="sizeInBytes")

    date     : datetime
    duration : timedelta = Field(alias="staticAnalysisDuration")
    tags     : List[Tag]
    configs  : Optional[Dict[str, Any]] = None
    json_obj : Any = None

    class Config:
        populate_by_name = True