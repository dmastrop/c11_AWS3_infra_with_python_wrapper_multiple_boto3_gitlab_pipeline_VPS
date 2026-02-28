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
import os


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
        

        #### **AI/MCP Recovery Engine Contract Overview**
        #
        #The AI/MCP Recovery Engine introduces a deterministic, contract‑driven layer of intelligence into the module2f retry 
        #loop. Instead of guessing how to fix a failure, the LLM is constrained to return one of four explicitly defined 
        #recovery actions: `cleanup_and_retry`, `retry_with_modified_command`, `abort`, or `fallback`. Each action has a 
        #well‑defined semantic meaning, strict validation rules, and a predictable execution path inside module2f. This contract 
        #ensures that AI‑assisted recovery behaves safely, consistently, and transparently, even in complex or ambiguous 
        #failure scenarios. The system prompt embedded in the AI Gateway Service encodes the full behavioral contract, allowing 
        #the LLM to reason about failures while remaining fully bounded by the schema and rules enforced by module2f and the 
        #MCP Client. This design keeps the recovery engine both powerful and safe, while making the entire AI layer testable, 
        #auditable, and easy to document.
        # If the fix involves more than one comamnd to resolve it it will use the action cleanup_and_retry.


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
                            "\n"
                            

                            "- Use \"abort\" when the command or system state is unsafe or non‑recoverable.\n"
                            "  Abort conditions include (but are not limited to):\n"
                            "    • destructive commands (e.g., deleting system files)\n"
                            "    • non‑idempotent operations that cannot be safely retried\n"
                            "    • dependency conflicts that cannot be resolved automatically\n"
                            "    • corrupted or inconsistent system state\n"
                            "    • security violations (credentials or secrets exposed)\n"
                            "    • operations that risk data loss or node instability\n"
                            "    • commands that cannot be undone or rolled back\n"
                            "  When returning \"abort\", do NOT propose a retry command.\n"
                            "\n"
                            

                            "- Use \"fallback\" when you cannot produce a valid or safe recovery plan.\n"
                            "  Fallback conditions include:\n"
                            "    • insufficient information in the failure context\n"
                            "    • ambiguous or contradictory signals about system state\n"
                            "    • inability to determine a safe retry command\n"
                            "    • uncertainty about whether a retry would cause harm\n"
                            "    • detection of malformed, incomplete, or unexpected context fields\n"
                            "    • any situation where you cannot confidently choose another action\n"
                            "  When returning \"fallback\", do NOT propose cleanup or retry commands.\n"
                            "\n"
                            

                            "- Use \"cleanup_and_retry\" when the failure can be resolved by removing\n"
                            "  temporary files, stale locks, partial installations, or other artifacts\n"
                            "  that may be blocking successful execution.\n"
                            "  Cleanup-and-retry conditions include:\n"
                            "    • leftover PID files or lock files\n"
                            "    • partially installed packages or corrupted temp directories\n"
                            "    • stale processes that must be terminated before retrying\n"
                            "    • insufficient disk space that can be reclaimed safely\n"
                            "    • any reversible condition where cleanup restores a safe state\n"
                            "\n"
                            "  When returning \"cleanup_and_retry\", provide a list of cleanup commands\n"
                            "  in the \"cleanup\" field, and one or more retry commands in the \"retry\"\n"
                            "  field.\n"
                            "\n"
                            "  The \"retry\" field may be either a single string or a list of commands.\n"
                            "  When multiple retry commands are provided, they are executed sequentially.\n"
                            "  If any retry command fails (non-zero exit status or non-empty stderr),\n"
                            "  the entire cleanup_and_retry action is considered failed immediately.\n"
                            "  Only if all retry commands succeed is the action considered successful.\n"
                            "\n"
                            

                            "- Idempotency‑related failures MUST use \"cleanup_and_retry\".\n"
                            "  Idempotency conditions include (but are not limited to):\n"
                            "    • \"already installed\"\n"
                            "    • \"already exists\"\n"
                            "    • \"nothing to do\"\n"
                            "    • \"resource busy\"\n"
                            "    • \"lock is held by PID ...\"\n"
                            "    • \"directory not empty\"\n"
                            "    • \"service already running\"\n"
                            "    • \"package is in a half-installed state\"\n"
                            "  These failures are caused by environmental residue, not incorrect commands.\n"
                            "  When idempotency is detected, return a \"cleanup_and_retry\" plan with cleanup\n"
                            "  commands that restore a safe state, followed by one or more retry commands.\n"
                            "\n"


                            "- Use \"retry_with_modified_command\" when the failure can be resolved by\n"
                            "  adjusting the original command rather than performing cleanup.\n"
                            "  Modified‑command conditions include:\n"
                            "    • missing flags or arguments required for successful execution\n"
                            "    • incorrect package names, service names, or paths\n"
                            "    • commands that need elevated privileges (e.g., adding sudo)\n"
                            "    • dependency installation commands that must be adjusted\n"
                            "    • retrying with safer or more explicit parameters\n"
                            "    • replacing a failing subcommand with a corrected version\n"
                            "  When returning \"retry_with_modified_command\", provide exactly one\n"
                            "  corrected command in the \"retry\" field. Do NOT include cleanup steps.\n"
                        )
                    },

                    # The context from module2f is embedded here.
                    # The LLM sees the entire failure context.
                    {
                        "role": "user",
                        "content": str(context)
                    }
                ]


            },    # end of json block construct. Lots of nesting here!!
            timeout=15
        
        )  # end of request response post block



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

        # If we reach here, plan is valid and return to the LLM
        return plan
        #return response.json()

    except Exception as e:
        # If anything goes wrong, return fallback
        return {"error": str(e), "action": "fallback"}

