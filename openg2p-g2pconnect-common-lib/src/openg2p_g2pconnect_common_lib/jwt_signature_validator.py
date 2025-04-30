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


def base64url_encode(input: bytes) -> bytes:
    return base64.urlsafe_b64encode(input).replace(b"=", b"")


class JWTSignatureValidator(HTTPBearer):
    async def __call__(self, request: Request) -> bool:
        oauth_token = await OAuthTokenService.get_component().get_oauth_token()
        headers = {
            "accept": "*/*",
            "Content-Type": "application/json",
            "Cookie": f"Authorization={oauth_token}",
        }

        # Get request body and decode to JSON
        request_body = await request.body()
        request_json = json.loads(request_body)

        # Canonicalize JSON using separators and encode to base64url (same as JWT payload encoding)
        canonical_json = json.dumps(request_json, separators=(",", ":")).encode("utf-8")
        actual_data = base64url_encode(canonical_json).decode(
            "utf-8"
        )  # base64url-encoded JSON string

        # Get JWT from header
        jwt_signature_data = request.headers.get("Signature")

        try:
            part1, _, part3 = jwt_signature_data.split(".")
        except ValueError:
            _logger.error(
                "Malformed detached JWT format. Expected format: part1..part3"
            )
            return False

        # Reconstruct full JWT
        reconstructed_jwt = f"{part1}.{actual_data}.{part3}"

        reference_id = (
            "PARTNER_"
            + request_json.get("header", {}).get("sender_id").replace("-", "_").upper()
        )

        # Prepare payload for external verification
        payload = {
            "id": "string",
            "version": "string",
            "requesttime": datetime.now().isoformat(),
            "metadata": {},
            "request": {
                "jwtSignatureData": reconstructed_jwt,
                "actualData": actual_data,
                "applicationId": _config.oauth_application_id,
                "referenceId": reference_id,
                "certificateData": "",
                "validateTrust": False,
                "domain": str(DomainEnum.AUTH),
            },
        }
        # Send request to external service for verification
        async with httpx.AsyncClient() as client:
            response = await client.post(
                _config.jwt_verify_url,
                json=payload,
                headers=headers,
            )
            try:
                return response.json()["response"]["signatureValid"]
            except Exception as e:
                _logger.error(f"Error: {e}")
                return False
