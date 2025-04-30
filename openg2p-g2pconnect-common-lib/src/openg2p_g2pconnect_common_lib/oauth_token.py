import logging
from datetime import datetime, timedelta, timezone

import httpx
from openg2p_fastapi_common.service import BaseService

from .config import Settings

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class OAuthTokenService(BaseService):
    def __init__(self):
        super().__init__()
        self.oauth_token = None
        self.expiry = datetime.now(timezone.utc)

    async def get_oauth_token(self):
        if self.oauth_token is None or datetime.now(timezone.utc) >= self.expiry:
            self.oauth_token = await self.fetch_oauth_token()
        return self.oauth_token

    async def fetch_oauth_token(self):
        url = _config.oauth_token_url
        payload = {
            "client_id": _config.oauth_client_id,
            "client_secret": _config.oauth_client_secret,
            "grant_type": _config.oauth_grant_type,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        async with httpx.AsyncClient() as client:
            response = await client.post(url, data=payload, headers=headers)
            response_data = response.json()
            expires_in = response_data.get("expires_in", 900)
            self.expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
            return response_data["access_token"]
