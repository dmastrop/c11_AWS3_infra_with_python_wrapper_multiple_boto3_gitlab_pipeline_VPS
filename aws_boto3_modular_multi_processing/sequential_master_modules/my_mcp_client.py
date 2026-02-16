# ------------------------------------------------------------
# MCPClient — AI/MCP Request Sender for module2f (and module2)
# ------------------------------------------------------------
# This client sends structured context to the AI Gateway Service
# running on port 8000 and receives a structured "plan" response.
#
# The AI Gateway enforces:
#   - schema versioning
#   - strict JSON mode
#   - plan validation
#   - fallback safety
#
# This client must be deterministic, defensive, and easy to debug.
# All prints use the [AI_MCP] prefix for grep-friendly CI logs.
# ------------------------------------------------------------


# This is the mcp_client code based on the MCPCLient class.  This consumes the context from module2f (and module2 later)
# The client sends a structured request to the AI Gateway Service which will run on port 8000 (https://localhost:8000)
# The AI Gateway Service will then send the request to the AI Brain (LLM) for assistance on the command and get a structured
# response back, the "plan". The plan can then be used by module2f to reiterate the failing command on the node.
# module2f (and module2) must import this MCPClient class by using: from my_mcp_client import MCPClient

# The AI Request Sender block inside module2f (and module2) needs this MCPClient class to call the send method below to 
# structure the context request message to the AI Gateway Service. The AI Request Sender in module2f  does this by using the 
# code block below: 
###### AI Request Sender block from module2f (and module2)

#mcp = MCPClient(
#    base_url="http://localhost:8000",   # AI Gateway Service URL
#    schema_version="1.0"                # Optional versioning for future compatibility
#)
#
#def ask_ai_for_recovery(context: dict):
#    """
#    Send the failure context to the AI Gateway Service
#    and return the AI-generated recovery plan.
#
#    module2f calls THIS function inside the retry loop
#    ONLY on the final failed attempt.
#    """
#    # mcp.send() performs:
#    #   - JSON serialization
#    #   - POST to http://localhost:8000/recover
#    #   - returns parsed JSON from the AI Gateway
#    return mcp.send(context)



import requests

class MCPClient:
    def __init__(self, base_url: str, schema_version: str = "1.0"):
        # Normalize base URL (avoid double slashes)
        self.base_url = base_url.rstrip("/")
        self.schema_version = schema_version

    def send(self, context: dict) -> dict:
        """
        Send context to the AI Gateway Service and return the plan.

        Returns a dict with either:
            - a valid plan from the AI Gateway, OR
            - {"action": "fallback", "error": "..."} on any failure.
        """

        payload = {
            "schema_version": self.schema_version,
            "context": context,
        }

        try:
            print("[AI_MCP] Sending context to AI Gateway Service...")
            resp = requests.post(
                f"{self.base_url}/recover",
                json=payload,
                timeout=30
            )

            # Raise for HTTP errors (non-2xx)
            resp.raise_for_status()

            data = resp.json()

            # Validate that the response is a dict
            if not isinstance(data, dict):
                print("[AI_MCP] WARNING: Non-dict response from AI Gateway — using fallback")
                return {"action": "fallback"}

            print("[AI_MCP] Received valid response from AI Gateway")
            return data

        except Exception as e:
            # Any network error, timeout, HTTP error, or JSON error
            print(f"[AI_MCP] ERROR: Exception talking to AI Gateway: {e}")
            return {"action": "fallback", "error": str(e)}

