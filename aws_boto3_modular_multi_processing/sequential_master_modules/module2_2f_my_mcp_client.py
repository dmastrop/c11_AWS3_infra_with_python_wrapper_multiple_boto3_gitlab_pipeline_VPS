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

