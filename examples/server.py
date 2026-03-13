import os
import uuid

import httpx
import uvicorn
from dotenv import load_dotenv

load_dotenv()

# Disable OpenTelemetry to prevent ContextVar leak that causes 500 Errors
os.environ["OTEL_PYTHON_DISABLED"] = "true"

import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from google.adk.cli.fast_api import get_fast_api_app

from mask import encode

logging.basicConfig(level=logging.DEBUG)

VAULT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
PERMITTED_CORS_ORIGINS = ["http://localhost:8080", "http://localhost"]
ENABLE_UI = True

vault_api_service: FastAPI = get_fast_api_app(
    agents_dir=VAULT_DIRECTORY,
    allow_origins=PERMITTED_CORS_ORIGINS,
    web=ENABLE_UI,
)


@vault_api_service.post("/apps/{application_id}/sessions")
async def initialize_user_session(application_id: str):
    """
    Generates a new session for the given application ID.
    """
    # Generate a unique session ID for every request to avoid collisions
    session_id = f"example_session_{uuid.uuid4().hex[:8]}"
    
    # Hardcoded payload for testing
    request_body = {"user:email": encode("user1@example.com")}

    async with httpx.AsyncClient() as client_http:
        res = await client_http.post(
            f"http://localhost:8000/apps/{application_id}/users/example_user/sessions/{session_id}",
            json=request_body,
        )
        return JSONResponse(content=res.json(), status_code=res.status_code)


if __name__ == "__main__":
    uvicorn.run(vault_api_service, host="localhost", port=8000)
