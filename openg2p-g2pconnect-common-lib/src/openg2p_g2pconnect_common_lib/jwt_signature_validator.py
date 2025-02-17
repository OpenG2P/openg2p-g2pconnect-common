import base64
import json
import logging
from datetime import datetime

import httpx
from fastapi import Request
from fastapi.security import HTTPBearer

from .config import Settings
from .oauth_token import OAuthTokenService
from .schemas import DomainEnum

_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class JWTSignatureValidator(HTTPBearer):
    async def __call__(self, request: Request) -> bool:
        oauth_token = await OAuthTokenService.get_component().get_oauth_token()
        headers = {
            "accept": "*/*",
            "Content-Type": "application/json",
            "Cookie": f"Authorization={oauth_token}",
        }

        request_body = await request.body()
        request_json = json.loads(request_body)
        actual_data = base64.b64encode(request_body).decode("utf-8")
        jwt_signature_data = request.headers.get("Authorization")
        if jwt_signature_data is None:
            return False

        reference_id = request_json.get("header", {}).get("sender_id")
        payload = {
            "id": "string",
            "version": "string",
            "requesttime": datetime.utcnow().isoformat(),
            "metadata": {},
            "request": {
                "jwtSignatureData": jwt_signature_data,
                "actual_data": actual_data,
                "applicationId": _config.oauth_application_id,
                "referenceId": reference_id,
                "certificateData": "",
                "validateTrust": True,
                "domain": str(DomainEnum.AUTH),
            },
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                _config.jwt_verify_url,
                json=payload,
                headers=headers,
            )
            response_data = response.json()
            try:
                return response_data["response"]["signatureValid"]
            except Exception as e:
                _logger.error(f"Error: {e}")
                return False
