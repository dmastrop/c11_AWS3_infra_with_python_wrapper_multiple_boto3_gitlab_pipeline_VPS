# ------------------------------------------------------------
# AI GATEWAY SERVICE (FastAPI)
# ------------------------------------------------------------
# This is a SEPARATE PROCESS that is run  manually or via CI:
#
#   python ai_gateway_service.py run natively on the VPS will not work. FastAPI apps must be served by an ASGI server
#   The best way to do this on the VPS is to do the following
#   On the VPS do: pip install uvicorn fastapi
#   Then on the VPS do: uvicorn ai_gateway_service:app --host 0.0.0.0 --port 8000
#   This will start the AI Gateway Service (FastAPI) on a ASGI server locally on the VPS
#   This will start the port 8000 locally on the VPS.
#
# 
# Alternatively start it during the gitlab pipeline run using the following in the .gitlab-ci.yml file:
# It has to be started BEFORE any of the python modules run
#   before_script:
#    - pip install fastapi uvicorn requests
#    - nohup uvicorn ai_gateway_service:app --host 0.0.0.0 --port 8000 &
#    - sleep 3
# This:
#
# - launches the gateway in the background  
# - keeps it running during the job  
# - ensures module2f can reach it  
#
#  For gitlab CI Use **uvicorn**, not:
#       python ai_gateway_service.py
#  because FastAPI apps must be served by an ASGI server.

# The proper CI command should be: nohup uvicorn ai_gateway_service:app --host 0.0.0.0 --port 8000 &
#

# This AI Gateway Service listens on port 8000 and acts as a "router" to the LLM:
#
#   (Request path with the context) module2f → MCPClient → AI Gateway → LiLM
#   (Response return path with the plan) LLM → AI Gateway → MCPClient → module2f
#
# module2f NEVER talks to the LLM directly.
# The LLM NEVER sees module2f directly.
# ------------------------------------------------------------

from fastapi import FastAPI
from pydantic import BaseModel
import requests

app = FastAPI()

# URL of the LLM API endpoint
LLM_API = "https://api.openai.com/v1/chat/completions"

# The API key for the LLM
#API_KEY = "api-key"   # <-- replace with real key or load from env
API_KEY = os.getenv("API_KEY") # this is the OpenAPI API_KEY in the variables for this gitlab pipeline.



# ------------------------------------------------------------
# Define the expected POST body using Pydantic
# This ensures FastAPI parses JSON correctly.
# ------------------------------------------------------------
class RecoveryRequest(BaseModel):
    schema_version: str
    context: dict


# ------------------------------------------------------------
# POST http://localhost:8000/recover from AI Request Sender (MCP Client)
# ------------------------------------------------------------
@app.post("/recover")
def recover(request: RecoveryRequest):
    """
    Receive context from MCPClient,
    forward it to the LLM,
    return the LLM's plan.
    """

    # Extract context from AI Request Sender POST to this AI Gateway Service
    context = request.context
    if request.schema_version != "1.0":
        return {"error": "Unsupported schema version", "action": "fallback"}




    # --------------------------------------------------------
    # Forward the context to the LLM
    # --------------------------------------------------------
    try:
        ##### TESTING
        #response = requests.post(
        #    LLM_API,
        #    headers={
        #        "Authorization": f"Bearer {API_KEY}",
        #        "Content-Type": "application/json"
        #    },
        #    json={
        #        "model": "gpt-5",   # or whatever model you use
        #        "messages": [
        #            {"role": "system", "content": "You are a recovery engine."},

        #            # The context from module2f is embedded here.
        #            # The LLM sees the entire failure context.
        #            {"role": "user", "content": str(context)}
        #        ]
        #    },
        #    timeout=15
        #)

        ###### The real deal setup is here ######
        # This is the plan schema for the action responses for the schema in accordance with the MCP Client (AI Request Sender)
        # in module2f. This has the acceptable action responses as I coded it in the AI/MCP HOOK function in module2f.
        response = requests.post(
            LLM_API,
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-5",
                "temperature": 0,
                "response_format": {"type": "json_object"},

                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a recovery engine.\n\n"
                            "Given the failure context, return ONLY a JSON object with the following schema:\n\n"
                            "{\n"
                            "  \"action\": \"cleanup_and_retry\" | \"retry_with_modified_command\" | \"abort\" | \"fallback\",\n"
                            "  \"cleanup\": [string],   # optional\n"
                            "  \"retry\": string        # optional\n"
                            "}\n\n"
                            "Rules:\n"
                            "- ALWAYS choose one of the allowed actions.\n"
                            "- NEVER return text outside the JSON.\n"
                            "- NEVER explain your reasoning.\n"
                            "- Use \"fallback\" if you cannot produce a valid plan.\n"
                        )
                    },

                    # The context from module2f is embedded here.
                    # The LLM sees the entire failure context.
                    {
                        "role": "user",
                        "content": str(context)
                    }
                ]
            },
            timeout=15
        )



        # If HTTP status is not 2xx, raise exception and print the error using except block below.
        response.raise_for_status()
        plan = response.json()
        # --------------------------------------------------------
        # Validate LLM plan schema
        # --------------------------------------------------------
        allowed_actions = {
            "cleanup_and_retry",
            "retry_with_modified_command",
            "abort",
            "fallback",
        }

        # Must be a dict
        if not isinstance(plan, dict):
            return {"error": "Invalid plan format", "action": "fallback"}

        action = plan.get("action")

        # Validate action
        if action not in allowed_actions:
            return {"error": "Invalid or missing action", "action": "fallback"}

        # Validate cleanup
        if "cleanup" in plan and not isinstance(plan["cleanup"], list):
            return {"error": "Invalid cleanup field", "action": "fallback"}

        # Validate retry
        if "retry" in plan and not isinstance(plan["retry"], str):
            return {"error": "Invalid retry field", "action": "fallback"}

        # If we reach here, plan is valid
        return plan        # Return the LLM's JSON response back to module2f
        #return response.json()

    except Exception as e:
        # If anything goes wrong, return fallback
        return {"error": str(e), "action": "fallback"}

