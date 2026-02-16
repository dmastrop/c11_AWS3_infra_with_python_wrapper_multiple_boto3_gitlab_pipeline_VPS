
##### Very Basic mcp_client code

import requests
import json


# Minimal client used by module2f to send context to the AI Gateway Service.
# This class intentionally contains no multiprocessing or threading logic.

class MCPClient:
    def __init__(self, base_url, schema_version="1.0"):
        self.base_url = base_url
        self.schema_version = schema_version

    def send(self, context: dict):
        #Send context to the AI Gateway Service and return the plan.
        
        try:
            response = requests.post(
                f"{self.base_url}/recover",
                json={
                    "schema_version": self.schema_version,
                    "context": context
                },
                timeout=10
            )
            # --------------------------------------------------------
            # If the HTTP status code is NOT 2xx, this line throws.
            # Example: 500, 404, 401, 503, etc.
            # --------------------------------------------------------
            response.raise_for_status()

            # If we get here, the HTTP status was 200–299.
            return response.json()

        except Exception as e:
            # Any network error, timeout, HTTP error, or JSON error
            # gets caught here and converted into a fallback signal.
            return {"error": str(e), "action": "fallback"}



# module2_2f_my_mcp_client.py
# This is the mcp_client code based on the MCPCLient class.  This consumes the context from module2f (and module2 later)
# The client sends a structured request to the AI Gateway Service which will run on port 8000 (https://localhost:8000)
# The AI Gateway Service will then send the request to teh AI Brain (LLM) for assistance on the command and get a structured
# response back, the "plan". The plan can then be used by module2f to reiterate the failing command on the node.



import json
import logging
import requests

class MCPClient:
    def __init__(self, base_url: str, schema_version: str = "1.0"):
        self.base_url = base_url.rstrip("/")
        self.schema_version = schema_version

    def send(self, context: dict) -> dict:
        payload = {
            "schema_version": self.schema_version,
            "context": context,
        }
        try:
            resp = requests.post(f"{self.base_url}/recover", json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                logging.warning("[MCP] Non-dict response, falling back")
                return {"action": "fallback"}
            return data
        except Exception as e:
            logging.warning(f"[MCP] Error talking to AI Gateway: {e}")
            return {"action": "fallback", "error": str(e)}

