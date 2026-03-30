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
#  For gitlab CI OR Dockerfile Use **uvicorn**, not:
#       python ai_gateway_service.py
#  because FastAPI apps must be served by an ASGI server.

# The proper CI command OR Dockefile shell script  should be: nohup uvicorn ai_gateway_service:app --host 0.0.0.0 --port 8000 &
#

# This AI Gateway Service listens on port 8000 and acts as a "router" to the LLM:
#
#   (Request path with the context) module2f → MCPClient → AI Gateway → LiLM
#   (Response return path with the plan) LLM → AI Gateway → MCPClient → module2f
# The port 8000 will not be visible on the VPS if the gateway is run on the deploy docker container, which is the approach that
# is used for this implementation.
#
# module2f NEVER talks to the LLM directly.
# The LLM NEVER sees module2f directly.
# ------------------------------------------------------------


# ---------------------------------------------------------------------------
# HOW THIS FILE IS LOADED BY UVICORN (AI Gateway Service Startup Mechanics)
# ---------------------------------------------------------------------------
# This file defines the FastAPI application used as the AI Gateway Service.
# The key object is:
#
#       app = FastAPI()
#
# When uvicorn is started with:
#
#       uvicorn ai_gateway_service:app --host 0.0.0.0 --port 8000
#
# uvicorn performs the following steps automatically:
#
#   1. Imports the Python module named "ai_gateway_service"
#      (i.e., this file: ai_gateway_service.py).
#
#   2. Searches the module for an attribute named "app".
#      In this file, "app" is the FastAPI() instance defined below.
#
#   3. Loads the entire module into memory.
#      This means ALL of the following are executed and available:
#         • the LLM contract rules
#         • the system prompt
#         • the schema validation logic
#         • the fallback logic
#         • the RecoveryRequest Pydantic model
#         • the /recover POST endpoint
#
#   4. Starts the ASGI server and exposes the FastAPI app on port 8000.
#
# The AI Gateway Service is started *inside the deploy container* via the
# embedded wrapper script in the Dockerfile using:
#
#       nohup uvicorn ai_gateway_service:app --host 0.0.0.0 --port 8000 &
#
# This ensures:
#   • The gateway runs inside the container (not on the VPS host)
#   • Module2f and the MCPClient can reach it at http://localhost:8000
#   • The LLM contract is fully loaded before any recovery requests occur
#
# The gateway acts as the router between module2f and the LLM:
#
#       module2f → MCPClient → AI Gateway → LLM
#       LLM → AI Gateway → MCPClient → module2f
#
# The entire recovery contract is enforced here before any plan is returned.
# ---------------------------------------------------------------------------





from fastapi import FastAPI
from pydantic import BaseModel
import requests
import os
import json

app = FastAPI()

# URL of the LLM API endpoint
#LLM_API = "https://api.openai.com/v1/chat/completions"
# Must use this URL for LLM API endpoint for 4.1-pro model upgrade
LLM_API = "https://api.openai.com/v1/responses"




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

        ##### ######
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

        
        
        # DEBUG: Print the exact payload being sent to OpenAI to troubleshoot the 400 issue. This is the print of the payload
        # after the context is sent to the AI Gateway Service by the curl command inside the deploy container during testing.
        # For example: 
        # root@8e1145bca832:/aws_EC2# curl -X POST "http://localhost:8000/recover" \
        #  -H "Content-Type: application/json" \
        #  -H "Authorization: Bearer $API_KEY" \
        #  -d '{
        #        "schema_version": "1.0",
        #        "context": {
        #            "stderr": "E: Could not get lock /var/lib/dpkg/lock-frontend",
        #            "stdout": "",
        #            "command": "apt-get install -y tomcat9",
        #            "exit_status": 100,
        #            "attempt": 1,
        #            "instance_id": "i-123456",
        #            "ip": "1.2.3.4",
        #            "tags": [],
        #            "os_info": "ubuntu",
        #            "history": []
        #        }
        #      }'
        

        debug_payload = {
            "model": "gpt-4.1-pro",
            "temperature": 0,
            #"response_format": {"type": "json_object"},
            
            #"system": (
            #    "You are a recovery engine.\n\n"
            #    "Given the failure context, return ONLY a JSON object with the following schema:\n\n"
            #    "{\n"
            #    "  \"action\": \"cleanup_and_retry\" | \"retry_with_modified_command\" | \"abort\" | \"fallback\",\n"
            #    "  \"cleanup\": [string],   # optional\n"
            #    "  \"retry\": string        # optional\n"
            #    "}\n\n"
            #    "Rules:\n"
            #    "- ALWAYS choose one of the allowed actions.\n"
            #    "- NEVER return text outside the JSON.\n"
            #    "- NEVER explain your reasoning.\n"
            #    "- Use \"fallback\" if you cannot produce a valid plan.\n"
            #    "\n"
            #    "- Use \"abort\" when the command or system state is unsafe or non‑recoverable.\n"
            #    "  Abort conditions include (but are not limited to):\n"
            #    "    • destructive commands (e.g., deleting system files)\n"
            #    "    • non‑idempotent operations that cannot be safely retried\n"
            #    "    • dependency conflicts that cannot be resolved automatically\n"
            #    "    • corrupted or inconsistent system state\n"
            #    "    • security violations (credentials or secrets exposed)\n"
            #    "    • operations that risk data loss or node instability\n"
            #    "    • commands that cannot be undone or rolled back\n"
            #    "  When returning \"abort\", do NOT propose a retry command.\n"
            #    "\n"
            #    "- Use \"fallback\" when you cannot produce a valid or safe recovery plan.\n"
            #    "  Fallback conditions include:\n"
            #    "    • insufficient information in the failure context\n"
            #    "    • ambiguous or contradictory signals about system state\n"
            #    "    • inability to determine a safe retry command\n"
            #    "    • uncertainty about whether a retry would cause harm\n"
            #    "    • detection of malformed, incomplete, or unexpected context fields\n"
            #    "    • any situation where you cannot confidently choose another action\n"
            #    "  When returning \"fallback\", do NOT propose cleanup or retry commands.\n"
            #    "\n"
            #    "- Use \"cleanup_and_retry\" when the failure can be resolved by removing\n"
            #    "  temporary files, stale locks, partial installations, or other artifacts\n"
            #    "  that may be blocking successful execution.\n"
            #    "  Cleanup-and-retry conditions include:\n"
            #    "    • leftover PID files or lock files\n"
            #    "    • partially installed packages or corrupted temp directories\n"
            #    "    • stale processes that must be terminated before retrying\n"
            #    "    • insufficient disk space that can be reclaimed safely\n"
            #    "    • any reversible condition where cleanup restores a safe state\n"
            #    "\n"
            #    "  When returning \"cleanup_and_retry\", provide a list of cleanup commands\n"
            #    "  in the \"cleanup\" field, and one or more retry commands in the \"retry\"\n"
            #    "  field.\n"
            #    "\n"
            #    "  The \"retry\" field may be either a single string or a list of commands.\n"
            #    "  When multiple retry commands are provided, they are executed sequentially.\n"
            #    "  If any retry command fails (non-zero exit status or non-empty stderr),\n"
            #    "  the entire cleanup_and_retry action is considered failed immediately.\n"
            #    "  Only if all retry commands succeed is the action considered successful.\n"
            #    "\n"
            #    "- Idempotency‑related failures MUST use \"cleanup_and_retry\".\n"
            #    "  Idempotency conditions include (but are not limited to):\n"
            #    "    • \"already installed\"\n"
            #    "    • \"already exists\"\n"
            #    "    • \"nothing to do\"\n"
            #    "    • \"resource busy\"\n"
            #    "    • \"lock is held by PID ...\"\n"
            #    "    • \"directory not empty\"\n"
            #    "    • \"service already running\"\n"
            #    "    • \"package is in a half-installed state\"\n"
            #    "  These failures are caused by environmental residue, not incorrect commands.\n"
            #    "  When idempotency is detected, return a \"cleanup_and_retry\" plan with cleanup\n"
            #    "  commands that restore a safe state, followed by one or more retry commands.\n"
            #    "\n"
            #    "- The \"cleanup\" field may be an empty list when no cleanup steps are required.\n"
            #    "  In such cases, you may still use \"cleanup_and_retry\" to provide one or more\n"
            #    "  retry commands in the \"retry\" field. This is appropriate when the environment\n"
            #    "  is already in a safe state and only the retry commands are needed to repair\n"
            #    "  the failure.\n"
            #    "\n"
            #    "- Use \"retry_with_modified_command\" when the failure can be resolved by\n"
            #    "  adjusting the original command rather than performing cleanup.\n"
            #    "  Modified‑command conditions include:\n"
            #    "    • missing flags or arguments required for successful execution\n"
            #    "    • incorrect package names, service names, or paths\n"
            #    "    • commands that need elevated privileges (e.g., adding sudo)\n"
            #    "    • dependency installation commands that must be adjusted\n"
            #    "    • retrying with safer or more explicit parameters\n"
            #    "    • replacing a failing subcommand with a corrected version\n"
            #    "  When returning \"retry_with_modified_command\", provide exactly one\n"
            #    "  corrected command in the \"retry\" field. Do NOT include cleanup steps.\n"
            #),
            
            #### New system block
            "system": (
                "You are a recovery engine.\n\n"
                "Given the failure context, return ONLY a JSON object with the following schema:\n\n"
                "{\n"
                "  \"action\": \"cleanup_and_retry\" | \"retry_with_modified_command\" | \"abort\" | \"fallback\",\n"
                "  \"cleanup\": [string],\n"
                "  \"retry\": string\n"
                "}\n\n"
                "Rules:\n"
                "- ALWAYS choose one of the allowed actions.\n"
                "- NEVER return text outside the JSON.\n"
                "- NEVER explain your reasoning.\n"
                "- Use \"fallback\" if you cannot produce a valid plan.\n\n"
                "Abort rules:\n"
                "Use \"abort\" when the command or system state is unsafe or non-recoverable.\n"
                "Abort conditions include:\n"
                "  - destructive commands (e.g., deleting system files)\n"
                "  - non-idempotent operations that cannot be safely retried\n"
                "  - dependency conflicts that cannot be resolved automatically\n"
                "  - corrupted or inconsistent system state\n"
                "  - security violations (credentials or secrets exposed)\n"
                "  - operations that risk data loss or node instability\n"
                "  - commands that cannot be undone or rolled back\n"
                "When returning \"abort\", do NOT propose a retry command.\n\n"
                "Fallback rules:\n"
                "Use \"fallback\" when you cannot produce a valid or safe recovery plan.\n"
                "Fallback conditions include:\n"
                "  - insufficient information in the failure context\n"
                "  - ambiguous or contradictory signals about system state\n"
                "  - inability to determine a safe retry command\n"
                "  - uncertainty about whether a retry would cause harm\n"
                "  - detection of malformed, incomplete, or unexpected context fields\n"
                "  - any situation where you cannot confidently choose another action\n"
                "When returning \"fallback\", do NOT propose cleanup or retry commands.\n\n"
                "Cleanup-and-retry rules:\n"
                "Use \"cleanup_and_retry\" when the failure can be resolved by removing temporary files, stale locks, partial installations, or other artifacts that may be blocking successful execution.\n"
                "Cleanup-and-retry conditions include:\n"
                "  - leftover PID files or lock files\n"
                "  - partially installed packages or corrupted temp directories\n"
                "  - stale processes that must be terminated before retrying\n"
                "  - insufficient disk space that can be reclaimed safely\n"
                "  - any reversible condition where cleanup restores a safe state\n\n"
                "When returning \"cleanup_and_retry\", provide a list of cleanup commands in the \"cleanup\" field, and one or more retry commands in the \"retry\" field.\n\n"
                "The \"retry\" field may be either a single string or a list of commands.\n"
                "When multiple retry commands are provided, they are executed sequentially.\n"
                "If any retry command fails (non-zero exit status or non-empty stderr), the entire cleanup_and_retry action is considered failed immediately.\n"
                "Only if all retry commands succeed is the action considered successful.\n\n"
                "Idempotency rules:\n"
                "Idempotency-related failures MUST use \"cleanup_and_retry\".\n"
                "Idempotency conditions include:\n"
                "  - \"already installed\"\n"
                "  - \"already exists\"\n"
                "  - \"nothing to do\"\n"
                "  - \"resource busy\"\n"
                "  - \"lock is held by PID ...\"\n"
                "  - \"directory not empty\"\n"
                "  - \"service already running\"\n"
                "  - \"package is in a half-installed state\"\n"
                "These failures are caused by environmental residue, not incorrect commands.\n"
                "When idempotency is detected, return a \"cleanup_and_retry\" plan with cleanup commands that restore a safe state, followed by one or more retry commands.\n\n"
                "Cleanup field rules:\n"
                "The \"cleanup\" field may be an empty list when no cleanup steps are required.\n"
                "In such cases, you may still use \"cleanup_and_retry\" to provide one or more retry commands in the \"retry\" field.\n\n"
                "Modified-command rules:\n"
                "Use \"retry_with_modified_command\" when the failure can be resolved by adjusting the original command rather than performing cleanup.\n"
                "Modified-command conditions include:\n"
                "  - missing flags or arguments required for successful execution\n"
                "  - incorrect package names, service names, or paths\n"
                "  - commands that need elevated privileges (e.g., adding sudo)\n"
                "  - dependency installation commands that must be adjusted\n"
                "  - retrying with safer or more explicit parameters\n"
                "  - replacing a failing subcommand with a corrected version\n"
                "When returning \"retry_with_modified_command\", provide exactly one corrected command in the \"retry\" field. Do NOT include cleanup steps.\n"
            ),




            # NEW BLOCK STARTS HERE for input_schema
            "input_schema": {
                "type": "json_schema",
                "json_schema": {
                    "name": "FailureContext",
                    "schema": {
                        "$schema": "http://json-schema.org/draft-07/schema#",
                        "type": "object",
                        "properties": {
                            "stderr": {"type": "string"},
                            "stdout": {"type": "string"},
                            "command": {"type": "string"},
                            "exit_status": {"type": "integer"},
                            "attempt": {"type": "integer"},
                            "instance_id": {"type": "string"},
                            "ip": {"type": "string"},
                            "tags": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "os_info": {"type": "string"},
                            "history": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        },
                        "required": ["stderr", "command", "exit_status"],
                        "additionalProperties": False
                    }
                }
            },
            # NEW BLOCK ENDS HERE


            #"input": json.dumps(context, indent=2)
            "input": context,

        }

        print("\n\n=== LLM REQUEST PAYLOAD ===")
        print(json.dumps(debug_payload, indent=2))
        print("=== END PAYLOAD ===\n\n")



        ##### ORIGINAL BLOCK. This is deprecated. For NEW BLOCK see further below that has updated format required for gpt 4.1 ####
        
        # ---------------------------------------------------------------------------
        # DEPRECATED BLOCK — OLD CHAT COMPLETIONS API (KEPT FOR HISTORICAL CONTEXT)
        #
        # This block originally used the legacy Chat Completions endpoint:
        #
        #     POST https://api.openai.com/v1/chat/completions
        #
        # with a payload containing a "messages" array:
        #
        #     "messages": [
        #         {"role": "system", "content": <contract>},
        #         {"role": "user",   "content": <failure context>}
        #     ]
        #
        # WHY THIS BLOCK NO LONGER WORKS:
        # -------------------------------
        # The Chat Completions API is tied to older GPT‑3.5/4.0 model families.
        # The recovery engine now uses GPT‑4.1‑pro, which is **not served** through
        # the Chat Completions endpoint. Attempting to call GPT‑4.1‑pro here results in:
        #
        #     404 Not Found
        #
        # because the model literally does not exist at this URL.
        #
        # Additionally, the Chat Completions API requires the "messages" array format,
        # which is no longer supported for GPT‑4.1 models. The new API uses:
        #
        #     • "system": <string>
        #     • "input":  <string>
        #
        # instead of a list of role‑tagged messages.
        #
        # WHY WE KEEP THIS BLOCK COMMENTED OUT:
        # -------------------------------------
        # This block is preserved for reference so future maintainers can see:
        #     • how the original implementation worked,
        #     • why it failed when upgrading to GPT‑4.1‑pro,
        #     • how the prompt structure evolved,
        #     • and what API format is now deprecated.
        #
        # DO NOT RE‑ENABLE THIS BLOCK.
        # It is incompatible with GPT‑4.1 and all future model families that use
        # the unified /v1/responses API.
        #
        # If a future model upgrade is required, always verify:
        #     1. The correct endpoint for that model family.
        #     2. The required prompt structure ("system" + "input" vs. new formats).
        #     3. That strict JSON output enforcement is still supported.
        #
        # ---------------------------------------------------------------------------



        #response = requests.post(
        #    LLM_API,
        #    headers={
        #        "Authorization": f"Bearer {API_KEY}",
        #        "Content-Type": "application/json"
        #    },
        #    json={
        #        "model": "gpt-4.1-pro",
        #        "temperature": 0,
        #        "response_format": {"type": "json_object"},


        #        "messages": [
        #            {
        #                "role": "system",
        #                "content": (
        #                    "You are a recovery engine.\n\n"
        #                    "Given the failure context, return ONLY a JSON object with the following schema:\n\n"
        #                    "{\n"
        #                    "  \"action\": \"cleanup_and_retry\" | \"retry_with_modified_command\" | \"abort\" | \"fallback\",\n"
        #                    "  \"cleanup\": [string],   # optional\n"
        #                    "  \"retry\": string        # optional\n"
        #                    "}\n\n"
        #                    "Rules:\n"
        #                    "- ALWAYS choose one of the allowed actions.\n"
        #                    "- NEVER return text outside the JSON.\n"
        #                    "- NEVER explain your reasoning.\n"
        #                    "- Use \"fallback\" if you cannot produce a valid plan.\n"
        #                    "\n"
        #                    

        #                    "- Use \"abort\" when the command or system state is unsafe or non‑recoverable.\n"
        #                    "  Abort conditions include (but are not limited to):\n"
        #                    "    • destructive commands (e.g., deleting system files)\n"
        #                    "    • non‑idempotent operations that cannot be safely retried\n"
        #                    "    • dependency conflicts that cannot be resolved automatically\n"
        #                    "    • corrupted or inconsistent system state\n"
        #                    "    • security violations (credentials or secrets exposed)\n"
        #                    "    • operations that risk data loss or node instability\n"
        #                    "    • commands that cannot be undone or rolled back\n"
        #                    "  When returning \"abort\", do NOT propose a retry command.\n"
        #                    "\n"
        #                    

        #                    "- Use \"fallback\" when you cannot produce a valid or safe recovery plan.\n"
        #                    "  Fallback conditions include:\n"
        #                    "    • insufficient information in the failure context\n"
        #                    "    • ambiguous or contradictory signals about system state\n"
        #                    "    • inability to determine a safe retry command\n"
        #                    "    • uncertainty about whether a retry would cause harm\n"
        #                    "    • detection of malformed, incomplete, or unexpected context fields\n"
        #                    "    • any situation where you cannot confidently choose another action\n"
        #                    "  When returning \"fallback\", do NOT propose cleanup or retry commands.\n"
        #                    "\n"
        #                    

        #                    "- Use \"cleanup_and_retry\" when the failure can be resolved by removing\n"
        #                    "  temporary files, stale locks, partial installations, or other artifacts\n"
        #                    "  that may be blocking successful execution.\n"
        #                    "  Cleanup-and-retry conditions include:\n"
        #                    "    • leftover PID files or lock files\n"
        #                    "    • partially installed packages or corrupted temp directories\n"
        #                    "    • stale processes that must be terminated before retrying\n"
        #                    "    • insufficient disk space that can be reclaimed safely\n"
        #                    "    • any reversible condition where cleanup restores a safe state\n"
        #                    "\n"
        #                    "  When returning \"cleanup_and_retry\", provide a list of cleanup commands\n"
        #                    "  in the \"cleanup\" field, and one or more retry commands in the \"retry\"\n"
        #                    "  field.\n"
        #                    "\n"
        #                    "  The \"retry\" field may be either a single string or a list of commands.\n"
        #                    "  When multiple retry commands are provided, they are executed sequentially.\n"
        #                    "  If any retry command fails (non-zero exit status or non-empty stderr),\n"
        #                    "  the entire cleanup_and_retry action is considered failed immediately.\n"
        #                    "  Only if all retry commands succeed is the action considered successful.\n"
        #                    "\n"
        #                    

        #                    "- Idempotency‑related failures MUST use \"cleanup_and_retry\".\n"
        #                    "  Idempotency conditions include (but are not limited to):\n"
        #                    "    • \"already installed\"\n"
        #                    "    • \"already exists\"\n"
        #                    "    • \"nothing to do\"\n"
        #                    "    • \"resource busy\"\n"
        #                    "    • \"lock is held by PID ...\"\n"
        #                    "    • \"directory not empty\"\n"
        #                    "    • \"service already running\"\n"
        #                    "    • \"package is in a half-installed state\"\n"
        #                    "  These failures are caused by environmental residue, not incorrect commands.\n"
        #                    "  When idempotency is detected, return a \"cleanup_and_retry\" plan with cleanup\n"
        #                    "  commands that restore a safe state, followed by one or more retry commands.\n"
        #                    "\n"


        #                    "- The \"cleanup\" field may be an empty list when no cleanup steps are required.\n"
        #                    "  In such cases, you may still use \"cleanup_and_retry\" to provide one or more\n"
        #                    "  retry commands in the \"retry\" field. This is appropriate when the environment\n"
        #                    "  is already in a safe state and only the retry commands are needed to repair\n"
        #                    "  the failure.\n"
        #                    "\n"


        #                    "- Use \"retry_with_modified_command\" when the failure can be resolved by\n"
        #                    "  adjusting the original command rather than performing cleanup.\n"
        #                    "  Modified‑command conditions include:\n"
        #                    "    • missing flags or arguments required for successful execution\n"
        #                    "    • incorrect package names, service names, or paths\n"
        #                    "    • commands that need elevated privileges (e.g., adding sudo)\n"
        #                    "    • dependency installation commands that must be adjusted\n"
        #                    "    • retrying with safer or more explicit parameters\n"
        #                    "    • replacing a failing subcommand with a corrected version\n"
        #                    "  When returning \"retry_with_modified_command\", provide exactly one\n"
        #                    "  corrected command in the \"retry\" field. Do NOT include cleanup steps.\n"
        #                )
        #            },

        #            # The context from module2f is embedded here.
        #            # The LLM sees the entire failure context.
        #            #{
        #            #    "role": "user",
        #            #    "content": str(context)
        #            #}

        #            # The above context formatting with str(context) is python format and NOT JSON format
        #            # The LLM requires JSON format
        #            {
        #                "role": "user",
        #                "content": json.dumps(context, indent=2)
        #            }

        #        ]


        #    },    # end of json block construct. Lots of nesting here!!
        #    timeout=15
        #
        #)  # end of request response post block














        # ---------------------------------------------------------------------------
        # NOTE: This NEW BLOCK (BELOW) replaces the legacy Chat Completions API call (ORIGINAL BLOCK ABOVE).
        #
        # WHY THIS CHANGE WAS REQUIRED:
        # -----------------------------
        # The original implementation used:
        #
        #     POST https://api.openai.com/v1/chat/completions
        #
        # with a payload containing:
        #
        #     "messages": [
        #         {"role": "system", "content": "..."},
        #         {"role": "user", "content": "..."}
        #     ]
        #
        # This endpoint and message format were part of the *old* Chat Completions API.
        # However, the recovery engine now uses the GPT‑4.1 model family (specifically
        # gpt‑4.1‑pro), and these models are **NOT** served through the Chat Completions
        # endpoint. Attempting to call them there results in:
        #
        #     404 Not Found
        #
        # because the model literally does not exist at that path.
        #
        # NEW API REQUIREMENTS:
        # ---------------------
        # GPT‑4.1 models are only available through the new unified Responses API:
        #
        #     POST https://api.openai.com/v1/responses
        #
        # This API does **not** accept a "messages" array. Instead, it requires:
        #
        #     • "system": <string>   → the entire system prompt / contract
        #     • "input":  <string>   → the user prompt (our failure context)
        #     • "response_format": {"type": "json_object"} for strict JSON output
        #
        # The content of our prompts (the full recovery‑engine contract and the
        # failure context) remains **100% identical**. Only the *shape* of the
        # request changed.
        #
        # WHY THIS MATTERS FOR THE RECOVERY ENGINE:
        # -----------------------------------------
        # Our recovery engine depends on:
        #     • strict JSON‑only output
        #     • deterministic action selection
        #     • a large, detailed system contract
        #     • zero tolerance for hallucinated fields
        #
        # GPT‑4.1‑pro is capable of meeting these constraints, but only when called
        # through the correct API with the correct payload structure.
        #
        # This rewrite preserves:
        #     • the full system contract (every rule, every bullet, unchanged)
        #     • the full failure context
        #     • strict JSON enforcement
        #     • deterministic behavior
        #
        # and updates only the transport format to match the new API.
        #
        # FUTURE MAINTAINERS:
        # -------------------
        # If the model is ever upgraded again (e.g., GPT‑5.x or later), verify:
        #     1. The correct endpoint for that model family.
        #     2. Whether the API still uses "system" + "input" or introduces a new format.
        #     3. That "response_format": {"type": "json_object"} is still supported.
        #
        # DO NOT revert to the old Chat Completions format. It is deprecated and
        # incompatible with GPT‑4.1 and later models.
        #
        # ---------------------------------------------------------------------------

        # IMPORTANT:
        # The /v1/responses API does NOT accept JSON-encoded strings as the "input" field.
        # Previously we used:
        #
        #     "input": json.dumps(context, indent=2)
        #
        # which produces a STRING containing escaped JSON. Example:
        #
        #     "{ \"stderr\": \"E: Could not get lock ...\" }"
        #
        # This causes the OpenAI Responses API to return HTTP 400 because the model
        # cannot interpret the failure context as structured data.
        #
        # FIX:
        # Pass the context as a REAL JSON object:
        #
        #     "input": context
        #
        # This sends a proper JSON object to the model, allowing it to read fields like
        # stderr, stdout, exit_status, command, attempt, etc. The model can then apply
        # the recovery-engine contract and return a valid action plan.
        #
        # NOTE:
        # FastAPI (the DEBUG print block ABOVE) will still return 200 OK for the /recover endpoint even when the
        # OpenAI call fails. The 400 error appears INSIDE the JSON response because it
        # comes from the second HTTP request (gateway → OpenAI), not from FastAPI itself.

        response = requests.post(
            LLM_API,
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4.1-pro",
                "temperature": 0,
                #"response_format": {"type": "json_object"},


                ## FULL SYSTEM PROMPT — unchanged, just moved into "system"
                #"system": (
                #    "You are a recovery engine.\n\n"
                #    "Given the failure context, return ONLY a JSON object with the following schema:\n\n"
                #    "{\n"
                #    "  \"action\": \"cleanup_and_retry\" | \"retry_with_modified_command\" | \"abort\" | \"fallback\",\n"
                #    "  \"cleanup\": [string],   # optional\n"
                #    "  \"retry\": string        # optional\n"
                #    "}\n\n"
                #    "Rules:\n"
                #    "- ALWAYS choose one of the allowed actions.\n"
                #    "- NEVER return text outside the JSON.\n"
                #    "- NEVER explain your reasoning.\n"
                #    "- Use \"fallback\" if you cannot produce a valid plan.\n"
                #    "\n"
                #    "- Use \"abort\" when the command or system state is unsafe or non‑recoverable.\n"
                #    "  Abort conditions include (but are not limited to):\n"
                #    "    • destructive commands (e.g., deleting system files)\n"
                #    "    • non‑idempotent operations that cannot be safely retried\n"
                #    "    • dependency conflicts that cannot be resolved automatically\n"
                #    "    • corrupted or inconsistent system state\n"
                #    "    • security violations (credentials or secrets exposed)\n"
                #    "    • operations that risk data loss or node instability\n"
                #    "    • commands that cannot be undone or rolled back\n"
                #    "  When returning \"abort\", do NOT propose a retry command.\n"
                #    "\n"
                #    "- Use \"fallback\" when you cannot produce a valid or safe recovery plan.\n"
                #    "  Fallback conditions include:\n"
                #    "    • insufficient information in the failure context\n"
                #    "    • ambiguous or contradictory signals about system state\n"
                #    "    • inability to determine a safe retry command\n"
                #    "    • uncertainty about whether a retry would cause harm\n"
                #    "    • detection of malformed, incomplete, or unexpected context fields\n"
                #    "    • any situation where you cannot confidently choose another action\n"
                #    "  When returning \"fallback\", do NOT propose cleanup or retry commands.\n"
                #    "\n"
                #    "- Use \"cleanup_and_retry\" when the failure can be resolved by removing\n"
                #    "  temporary files, stale locks, partial installations, or other artifacts\n"
                #    "  that may be blocking successful execution.\n"
                #    "  Cleanup-and-retry conditions include:\n"
                #    "    • leftover PID files or lock files\n"
                #    "    • partially installed packages or corrupted temp directories\n"
                #    "    • stale processes that must be terminated before retrying\n"
                #    "    • insufficient disk space that can be reclaimed safely\n"
                #    "    • any reversible condition where cleanup restores a safe state\n"
                #    "\n"
                #    "  When returning \"cleanup_and_retry\", provide a list of cleanup commands\n"
                #    "  in the \"cleanup\" field, and one or more retry commands in the \"retry\"\n"
                #    "  field.\n"
                #    "\n"
                #    "  The \"retry\" field may be either a single string or a list of commands.\n"
                #    "  When multiple retry commands are provided, they are executed sequentially.\n"
                #    "  If any retry command fails (non-zero exit status or non-empty stderr),\n"
                #    "  the entire cleanup_and_retry action is considered failed immediately.\n"
                #    "  Only if all retry commands succeed is the action considered successful.\n"
                #    "\n"
                #    "- Idempotency‑related failures MUST use \"cleanup_and_retry\".\n"
                #    "  Idempotency conditions include (but are not limited to):\n"
                #    "    • \"already installed\"\n"
                #    "    • \"already exists\"\n"
                #    "    • \"nothing to do\"\n"
                #    "    • \"resource busy\"\n"
                #    "    • \"lock is held by PID ...\"\n"
                #    "    • \"directory not empty\"\n"
                #    "    • \"service already running\"\n"
                #    "    • \"package is in a half-installed state\"\n"
                #    "  These failures are caused by environmental residue, not incorrect commands.\n"
                #    "  When idempotency is detected, return a \"cleanup_and_retry\" plan with cleanup\n"
                #    "  commands that restore a safe state, followed by one or more retry commands.\n"
                #    "\n"
                #    "- The \"cleanup\" field may be an empty list when no cleanup steps are required.\n"
                #    "  In such cases, you may still use \"cleanup_and_retry\" to provide one or more\n"
                #    "  retry commands in the \"retry\" field. This is appropriate when the environment\n"
                #    "  is already in a safe state and only the retry commands are needed to repair\n"
                #    "  the failure.\n"
                #    "\n"
                #    "- Use \"retry_with_modified_command\" when the failure can be resolved by\n"
                #    "  adjusting the original command rather than performing cleanup.\n"
                #    "  Modified‑command conditions include:\n"
                #    "    • missing flags or arguments required for successful execution\n"
                #    "    • incorrect package names, service names, or paths\n"
                #    "    • commands that need elevated privileges (e.g., adding sudo)\n"
                #    "    • dependency installation commands that must be adjusted\n"
                #    "    • retrying with safer or more explicit parameters\n"
                #    "    • replacing a failing subcommand with a corrected version\n"
                #    "  When returning \"retry_with_modified_command\", provide exactly one\n"
                #    "  corrected command in the \"retry\" field. Do NOT include cleanup steps.\n"
                #),




                ##### UPDATED system prompt

                "system": (
                    "You are a recovery engine.\n\n"
                    "Given the failure context, return ONLY a JSON object with the following schema:\n\n"
                    "{\n"
                    "  \"action\": \"cleanup_and_retry\" | \"retry_with_modified_command\" | \"abort\" | \"fallback\",\n"
                    "  \"cleanup\": [string],\n"
                    "  \"retry\": string\n"
                    "}\n\n"
                    "Rules:\n"
                    "- ALWAYS choose one of the allowed actions.\n"
                    "- NEVER return text outside the JSON.\n"
                    "- NEVER explain your reasoning.\n"
                    "- Use \"fallback\" if you cannot produce a valid plan.\n\n"
                    "Abort rules:\n"
                    "Use \"abort\" when the command or system state is unsafe or non-recoverable.\n"
                    "Abort conditions include:\n"
                    "  - destructive commands (e.g., deleting system files)\n"
                    "  - non-idempotent operations that cannot be safely retried\n"
                    "  - dependency conflicts that cannot be resolved automatically\n"
                    "  - corrupted or inconsistent system state\n"
                    "  - security violations (credentials or secrets exposed)\n"
                    "  - operations that risk data loss or node instability\n"
                    "  - commands that cannot be undone or rolled back\n"
                    "When returning \"abort\", do NOT propose a retry command.\n\n"
                    "Fallback rules:\n"
                    "Use \"fallback\" when you cannot produce a valid or safe recovery plan.\n"
                    "Fallback conditions include:\n"
                    "  - insufficient information in the failure context\n"
                    "  - ambiguous or contradictory signals about system state\n"
                    "  - inability to determine a safe retry command\n"
                    "  - uncertainty about whether a retry would cause harm\n"
                    "  - detection of malformed, incomplete, or unexpected context fields\n"
                    "  - any situation where you cannot confidently choose another action\n"
                    "When returning \"fallback\", do NOT propose cleanup or retry commands.\n\n"
                    "Cleanup-and-retry rules:\n"
                    "Use \"cleanup_and_retry\" when the failure can be resolved by removing temporary files, stale locks, partial installations, or other artifacts that may be blocking successful execution.\n"
                    "Cleanup-and-retry conditions include:\n"
                    "  - leftover PID files or lock files\n"
                    "  - partially installed packages or corrupted temp directories\n"
                    "  - stale processes that must be terminated before retrying\n"
                    "  - insufficient disk space that can be reclaimed safely\n"
                    "  - any reversible condition where cleanup restores a safe state\n\n"
                    "When returning \"cleanup_and_retry\", provide a list of cleanup commands in the \"cleanup\" field, and one or more retry commands in the \"retry\" field.\n\n"
                    "The \"retry\" field may be either a single string or a list of commands.\n"
                    "When multiple retry commands are provided, they are executed sequentially.\n"
                    "If any retry command fails (non-zero exit status or non-empty stderr), the entire cleanup_and_retry action is considered failed immediately.\n"
                    "Only if all retry commands succeed is the action considered successful.\n\n"
                    "Idempotency rules:\n"
                    "Idempotency-related failures MUST use \"cleanup_and_retry\".\n"
                    "Idempotency conditions include:\n"
                    "  - \"already installed\"\n"
                    "  - \"already exists\"\n"
                    "  - \"nothing to do\"\n"
                    "  - \"resource busy\"\n"
                    "  - \"lock is held by PID ...\"\n"
                    "  - \"directory not empty\"\n"
                    "  - \"service already running\"\n"
                    "  - \"package is in a half-installed state\"\n"
                    "These failures are caused by environmental residue, not incorrect commands.\n"
                    "When idempotency is detected, return a \"cleanup_and_retry\" plan with cleanup commands that restore a safe state, followed by one or more retry commands.\n\n"
                    "Cleanup field rules:\n"
                    "The \"cleanup\" field may be an empty list when no cleanup steps are required.\n"
                    "In such cases, you may still use \"cleanup_and_retry\" to provide one or more retry commands in the \"retry\" field.\n\n"
                    "Modified-command rules:\n"
                    "Use \"retry_with_modified_command\" when the failure can be resolved by adjusting the original command rather than performing cleanup.\n"
                    "Modified-command conditions include:\n"
                    "  - missing flags or arguments required for successful execution\n"
                    "  - incorrect package names, service names, or paths\n"
                    "  - commands that need elevated privileges (e.g., adding sudo)\n"
                    "  - dependency installation commands that must be adjusted\n"
                    "  - retrying with safer or more explicit parameters\n"
                    "  - replacing a failing subcommand with a corrected version\n"
                    "When returning \"retry_with_modified_command\", provide exactly one corrected command in the \"retry\" field. Do NOT include cleanup steps.\n"
                ),




                # Need to add an input_schema as well for the latest API
                # IMPORTANT:
                # When sending a structured JSON object in the "input" field, the /v1/responses
                # API requires an "input_schema" describing the exact shape of that object.
                #
                # Without this schema, the API returns HTTP 400 because it cannot validate or
                # interpret the structured fields (stderr, stdout, command, exit_status, etc.).
                #
                # The nesting here is intentional:
                #   input_schema
                #       → type: "json_schema"
                #       → json_schema
                #             → name: "FailureContext"
                #             → schema (actual JSON Schema definition)
                #                   → properties (field definitions)
                #                   → required (minimum fields needed)
                #
                # This allows the model to parse the failure context deterministically and
                # apply the recovery-engine contract correctly.

                "input_schema": {
                        "type": "json_schema",
                        "json_schema": {
                            "name": "FailureContext",
                            "schema": {
                                "$schema": "http://json-schema.org/draft-07/schema#",
                                "type": "object",
                                "properties": {
                                    "stderr": {"type": "string"},
                                    "stdout": {"type": "string"},
                                    "command": {"type": "string"},
                                    "exit_status": {"type": "integer"},
                                    "attempt": {"type": "integer"},
                                    "instance_id": {"type": "string"},
                                    "ip": {"type": "string"},
                                    "tags": {
                                        "type": "array",
                                        "items": {"type": "string"}
                                    },
                                    "os_info": {"type": "string"},
                                    "history": {
                                        "type": "array",
                                        "items": {"type": "string"}
                                    }
                                },
                                "required": ["stderr", "command", "exit_status"],
                                "additionalProperties": False
                            }
                        }
                }, ## End of the input_schema

                # USER PROMPT — unchanged, just moved into "input"
                #"input": json.dumps(context, indent=2)
                "input": context,
                

            }, # end of json block construct. Lots of nesting here!!
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





##### Additional notes about the contract actions and LLM interaction ######


#### **1. Derived fallback is ALWAYS handled in module2f, not by the LLM**
# Derived fallback is an ai_fallback that is not from the native contract fallback action above
# Derived fallback occurs, for example, if cleanup_and_retry has all retry commands that are blank or missing or None
# This will result in install_failed and ai_fallback metadata, but the registry_entry will also have ai_plan_action of cleanup_and_retry
# On the other hand, a native contract fallback will result in install_failed, have ai_fallback metadata, but will have ai_plan_action of
# (native) fallback.

#The LLM only emits:
#
#- `"action": "cleanup_and_retry"`
#- `"action": "retry_with_modified_command"`
#- `"action": "fallback"` (This is the native contract fallback action)
#- `"action": "abort"`
#- `"action": "some_unknown_action"`
#
#The LLM **never** needs to know:
#
#- what happens if retry is `None`
#- what happens if retry is `"   "`
#- what happens if retry is missing
#- what happens if cleanup contains whitespace
#- what happens if cleanup contains garbage
#
#Those are **derived fallback conditions**, and they are **purely code‑driven**.
#
#### **2. The LLM contract does NOT include “whitespace handling”**
#
#And it should not.
#
#The contract is:
#
#- If the LLM wants fallback → it emits `"action": "fallback"`
#- If the LLM wants retry → it emits `"action": "retry_with_modified_command"` with a real command
#- If the LLM wants cleanup_and_retry → it emits lists of real commands
#
#Everything else (missing keys, None, whitespace, malformed lists) is **not part of the LLM contract**.

