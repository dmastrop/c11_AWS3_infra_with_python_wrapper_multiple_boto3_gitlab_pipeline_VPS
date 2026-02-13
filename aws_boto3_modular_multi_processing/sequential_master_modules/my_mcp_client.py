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

