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
        #failure scenarios. The payload input block embedded in the AI Gateway Service encodes the full behavioral contract, allowing 
        #the LLM to reason about failures while remaining fully bounded by the schema and rules enforced by module2f and the 
        #MCP Client. This design keeps the recovery engine both powerful and safe, while making the entire AI layer testable, 
        #auditable, and easy to document.
        # If the fix involves more than one comamnd to resolve it it will use the action cleanup_and_retry.

        
        








        # Payload1
        #payload = {
        #    "model": "gpt-4.1",
        #    "temperature": 0,
        #    "max_output_tokens": 256,
        #    "system": (
        #        "You are a recovery engine. "
        #        "Follow the contract and rules provided inside the input JSON. "
        #        "Return ONLY a JSON object."
        #    ),
        #    "input": {
        #        "contract": "test",
        #        "context": context
        #    }
        #}




        ## Payload2
        ## Build payload in a variable so we can inspect it
        ## Remove the frickin system field. That is causing the 400 issue. Use instruction field.
        #payload = {
        #    "model": "gpt-4.1",
        #    "temperature": 0,
        #    "max_output_tokens": 256,
        #    "input": {
        #        "instruction": (
        #            "You are a recovery engine. "
        #            "Follow the contract and rules provided inside the input JSON. "
        #            "Return ONLY a JSON object."
        #        ),
        #        "contract": "test",
        #        "context": context
        #    }
        #}




        ##Payload3 First working prototype with LLM interaction
        #payload = {
        #    "model": "gpt-4.1",
        #    "temperature": 0,
        #    "max_output_tokens": 256,
        #    "input": (
        #        "You are a recovery engine. "
        #        "Follow the contract and rules provided inside the input JSON. "
        #        "Return ONLY a JSON object.\n\n"
        #        "CONTRACT:\n"
        #        "test\n\n"
        #        f"CONTEXT:\n{context}"
        #    )
        #}



        ## Payload 4

        #payload = {
        #    "model": "gpt-4.1",
        #    "temperature": 0,
        #    "max_output_tokens": 256,
        #    "input": (
        #        "You are a recovery engine. "
        #        "Follow the contract and rules provided inside the input JSON. "
        #        "Return ONLY a JSON object.\n\n"
        #        "CONTRACT:\n"
        #        "You must return ONLY a JSON object with this schema:\n\n"
        #        "{\n"
        #        "  \"action\": \"cleanup_and_retry\" | \"retry_with_modified_command\" | \"abort\" | \"fallback\",\n"
        #        "  \"cleanup\": [string],\n"
        #        "  \"retry\": string\n"
        #        "}\n\n"
        #        "Rules:\n"
        #        "- ALWAYS choose one of the allowed actions.\n"
        #        "- NEVER return text outside the JSON.\n"
        #        "- NEVER explain your reasoning.\n"
        #        "- Use \"fallback\" if you cannot produce a valid plan.\n\n"
        #        "Action meanings:\n"
        #        "- cleanup_and_retry: Use when the failure can be fixed by cleanup steps before retrying.\n"
        #        "- retry_with_modified_command: Use when the failure can be fixed by adjusting the command.\n"
        #        "- abort: Use when the failure is unsafe or cannot be recovered.\n"
        #        "- fallback: Use when there is not enough information to choose another action.\n\n"
        #        f"CONTEXT:\n{context}"
        #    )
        #}


        ## Payload 5. NOTE that the CONTEXT is {context} which is provided by the curl test command from within the container during 
        ## whitebox testing. So Payload5 can be used for tests5,6,7 etc until we need to edit the contract.
        #payload = {
        #    "model": "gpt-4.1",
        #    "temperature": 0,
        #    "max_output_tokens": 256,
        #    "input": (
        #        "You are a recovery engine. "
        #        "Follow the contract and rules provided inside the input JSON. "
        #        "Return ONLY a JSON object.\n\n"
        #        "CONTRACT:\n"
        #        "You must return ONLY a JSON object with this schema:\n\n"
        #        "{\n"
        #        "  \"action\": \"cleanup_and_retry\" | \"retry_with_modified_command\" | \"abort\" | \"fallback\",\n"
        #        "  \"cleanup\": [string],\n"
        #        "  \"retry\": string\n"
        #        "}\n\n"
        #        "Rules:\n"
        #        "- ALWAYS choose one of the allowed actions.\n"
        #        "- NEVER return text outside the JSON.\n"
        #        "- NEVER explain your reasoning.\n"
        #        "- Use \"fallback\" if you cannot produce a valid plan.\n\n"
        #        "Fallback rules:\n"
        #        "- When returning \"fallback\", return ONLY:\n"
        #        "  { \"action\": \"fallback\" }\n"
        #        "- Do NOT include \"cleanup\".\n"
        #        "- Do NOT include \"retry\".\n\n"
        #        "Action meanings:\n"
        #        "- cleanup_and_retry: Use when the failure can be fixed by cleanup steps before retrying.\n"
        #        "- retry_with_modified_command: Use when the failure can be fixed by adjusting the command.\n"
        #        "- abort: Use when the failure is unsafe or cannot be recovered.\n"
        #        "- fallback: Use when there is not enough information to choose another action.\n\n"
        #        f"CONTEXT:\n{context}"
        #    )
        #}






        #Payload6 enhancments
        # ================================================================
        # PAYLOAD BLOCK — AI GATEWAY SERVICE
        #
        # This payload defines the *contract* between the AI Gateway Service
        # and the LLM. It is the single most important component of the
        # recovery engine architecture.
        #
        # Key principles:
        # - The contract is STATIC. It does not change between tests.
        # - The context is DYNAMIC. It is injected from the curl request.
        # - The LLM must ALWAYS return a JSON object that conforms to the schema.
        # - The validator enforces the contract and rejects malformed plans.
        #
        # This block is the result of iterative white‑box testing using curl.
        # Each iteration revealed ambiguities or weaknesses in the contract,
        # which were then tightened to produce deterministic behavior.
        #
        # The comments in this block will be used directly in the README
        # chapter: "Developing the AI Gateway Service through iterative
        # white‑box LLM response testing with curl".
        # ================================================================

        payload = {
            "model": "gpt-4.1",
            "temperature": 0,
            "max_output_tokens": 256,

            # The "input" field contains the entire contract, rules, and context.
            # The LLM receives this as a single string and MUST return a JSON object.
            "input": (
                "You are a recovery engine. "
                "Follow the contract and rules provided inside the input JSON. "
                "Return ONLY a JSON object.\n\n"

                # ============================================================
                # CONTRACT — STATIC SPECIFICATION
                # Revision 1: Added the messages requirement for abort and notes as well to the LLM
                # ============================================================
                "CONTRACT:\n"
                "You must return ONLY a JSON object with this schema:\n\n"
                "{\n"
                "  \"action\": \"cleanup_and_retry\" | \"retry_with_modified_command\" | \"abort\" | \"fallback\",\n"
                "  \"cleanup\": [string],\n"
                "  \"retry\": string\n"
                "  \"message\": string\n"
                "}\n\n"
                "Notes:\n"
                "- \"message\" is REQUIRED when action = \"abort\".\n"
                "- \"message\" is OPTIONAL for all other actions.\n"
                "- \"cleanup\" MUST be an array of literal shell commands.\n"
                "- \"retry\" MUST be a literal shell command or an empty string.\n\n"




                # ============================================================
                # CORE RULES
                # ============================================================
                "Rules:\n"
                "- ALWAYS choose one of the allowed actions.\n"
                "- NEVER return text outside the JSON.\n"
                "- NEVER explain your reasoning.\n"
                "- Use \"fallback\" if you cannot produce a valid plan.\n\n"

                # ============================================================
                # RETRY COMMAND RULES — NEWLY ADDED FOR ROBUSTNESS
                # ============================================================
                "Retry command rules:\n"
                "- The \"retry\" field MUST be a literal shell command that can be executed directly.\n"
                "- The retry command MUST NOT reference \"previous command\", \"original command\", or any vague instruction.\n"
                "- The retry command MUST NOT be an English sentence. It MUST be a valid shell command.\n"
                "- The retry command MUST NOT contain placeholders like \"<command>\" or \"<package>\".\n"
                "- The retry command MUST NOT contain commentary or explanation.\n"
                "- The retry command MUST NOT contain multiple commands chained with \"&&\" unless necessary.\n"
                "- The retry command MUST NOT contain dangerous operations (rm -rf /, shutdown, reboot, etc.).\n\n"

                # ============================================================
                # CLEANUP RULES
                # ============================================================
                "Cleanup rules:\n"
                "- The \"cleanup\" field MUST be a list of literal shell commands.\n"
                "- Cleanup commands MUST be safe, minimal, and directly related to resolving the failure.\n"
                "- Cleanup commands MUST NOT include vague instructions or commentary.\n"
                "- Cleanup commands MUST NOT include dangerous operations.\n\n"


                # ============================================================
                # MALFORMED COMMAND RULES (LINUX)
                # Revision 2: Added explicit handling for incomplete but fixable Linux commands. This ENTIRE block is newly added
                # with revision 2. 
                # ============================================================
                "Malformed command rules (Linux):\n"
                "- Treat commands like \"apt-get install\", \"yum install\", \"dnf install\", and \"apk add\" with no package as INCOMPLETE, not unsafe.\n"
                "- If the command is incomplete but the missing argument CANNOT be safely inferred, prefer \"fallback\" over \"abort\".\n"
                "- Do NOT guess a package name based solely on prior examples or patterns in the input.\n"
                "- Only use \"retry_with_modified_command\" when you can safely construct a complete, realistic command.\n"
                "- Incomplete commands MUST NOT trigger \"abort\" unless they are also unsafe or destructive.\n\n"


                # ============================================================
                # FALLBACK RULES
                # ============================================================
                "Fallback rules:\n"
                "- When returning \"fallback\", return ONLY:\n"
                "  { \"action\": \"fallback\" }\n"
                "- Do NOT include \"cleanup\".\n"
                "- Do NOT include \"retry\".\n\n"


                # ============================================================
                # FALLBACK RULES
                # Revision 2: Clarified when to prefer fallback over abort or retry
                # This revsion 2 is in reference to incomplete or ambigous commands (not necessarily malformed; see above)
                # The reference to test-induced bias is important as much of the contract refinement is performed in an interative
                # python schema based test environment where schemas for particular os or platform may focus on a specific package, for
                # example nginx. We do NOT want the LLM to infer that the missing package in a given incomplete command based upon 
                # the test design itself. This does not conform to real-world empirically desired results. It is better to fallback instead
                # of retry_with_modified_command or cleanup_and_retry.
                # ============================================================
                "Fallback rules:\n"
                "- When returning \"fallback\", return ONLY:\n"
                "  { \"action\": \"fallback\" }\n"
                "- Do NOT include \"cleanup\".\n"
                "- Do NOT include \"retry\".\n"
                "- Use \"fallback\" when the command is incomplete or ambiguous and no safe, concrete fix can be inferred.\n"
                "- Use \"fallback\" instead of \"abort\" when the situation is non-destructive but under-specified (e.g., missing package name).\n"
                "- Use \"fallback\" when OS, package manager, or shell context is unclear and any guess would be speculative.\n"
                "- Use \"fallback\" when correcting the command would require unsafe inference or assumptions.\n\n"
                "- NEVER infer missing arguments (such as package names) based solely on patterns in previous test cases or schema examples; avoid test-induced bias.\n\n"




                # ============================================================
                # ACTION MEANINGS
                # ============================================================
                "Action meanings:\n"
                "- cleanup_and_retry: Use when the failure can be fixed by cleanup steps before retrying.\n"
                "- retry_with_modified_command: Use when the failure can be fixed by adjusting the command.\n"
                "- abort: Use when the failure is unsafe or cannot be recovered.\n"
                "- fallback: Use when there is not enough information to choose another action.\n\n"


                # ============================================================
                # ABORT RULES
                # Revision 1:  added the messages requirement after doing LLM testing with various os and platforms
                # ============================================================
                "Abort rules:\n"
                "- Use \"abort\" when the command or system state is unsafe or non-recoverable.\n"
                "- Abort when the plan would risk data loss, node instability, or security exposure.\n"
                "- Abort when the failure suggests corrupted or inconsistent system state.\n"
                "- Abort when the only apparent fixes involve destructive or non-reversible operations.\n"
                "- When returning \"abort\", do NOT include \"cleanup\" or \"retry\".\n\n"
                "- When returning \"abort\", you MUST include a \"message\" field explaining WHY the abort was chosen.\n"
                "- The \"message\" must be a short, factual, non-emotional explanation.\n"
                "- The \"message\" must NOT include reasoning steps, chain-of-thought, or internal deliberation.\n"
                "- The \"message\" must NOT include instructions, commands, or suggestions.\n"
                "- The \"message\" must NOT hallucinate OS capabilities or package managers.\n"
                "- Examples of valid abort messages:\n"
                "    { \"action\": \"abort\", \"message\": \"Destructive command detected: rm -rf /\" }\n"
                "    { \"action\": \"abort\", \"message\": \"Unsupported OS: Cisco IOS does not support package installation.\" }\n"
                "    { \"action\": \"abort\", \"message\": \"Invalid or malformed command; no safe recovery available.\" }\n\n"





                # ============================================================
                # SAFETY CONSTRAINTS
                # ============================================================
                "Safety constraints:\n"
                "- NEVER propose commands that modify or delete /etc/passwd, /etc/shadow, or user home directories.\n"
                "- NEVER propose commands that delete system directories outside package/cache paths (e.g., no \"rm -rf /\", no \"rm -rf /usr\", etc.).\n"
                "- Prefer minimal, targeted cleanup under /var/lib, /var/cache, or other known safe system paths.\n\n"



                # ============================================================
                # ADDITIONAL SAFETY CONSTRAINTS
                # ============================================================
                "Additional safety constraints:\n"
                "- NEVER propose commands that pipe remote content into a shell (e.g., no \"curl ... | sh\").\n"
                "- NEVER propose commands that disable or mask system services (e.g., no \"systemctl disable\", no \"systemctl mask\").\n"
                "- NEVER propose commands that modify kernel, bootloader, or low-level system configuration (e.g., no \"update-grub\", no \"grub-install\", no kernel package installation).\n"
                "- NEVER propose commands that modify package manager configuration files or sources lists.\n\n"

                # ============================================================
                # CLEANUP SEQUENCE RULES
                # ============================================================
                "Cleanup sequence rules:\n"
                "- Cleanup steps MUST be ordered from least invasive to most invasive.\n"
                "- Cleanup steps MUST be idempotent (safe to run multiple times).\n"
                "- Cleanup steps MUST NOT exceed 3 commands.\n"
                "- Cleanup steps MUST NOT include commentary or explanation.\n\n"




                # ============================================================
                # CONTEXT — DYNAMIC INPUT FROM CURL
                # ============================================================
                f"CONTEXT:\n{context}"
            )
        }


        # Print the exact payload before sending
        print("\n==================== PAYLOAD SENT TO OPENAI ====================")
        print(payload)
        print("===============================================================\n")

        # Make the request
        response = requests.post(
            LLM_API,
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=15
        )

        # Print raw response text
        print("\n==================== RAW RESPONSE FROM OPENAI ==================")
        print(response.text)
        print("===============================================================\n")


        ####### ORIGINAL VALIDATOR CODE #######
        ###### This is the plan validator. The AI Gateway Service has to validate the plan from the LLM before sending back to the 
        ###### MCP Client (module2f)
        ## If HTTP status is not 2xx, raise exception and print the error using except block below.
        #response.raise_for_status()
        #plan = response.json()
        ## --------------------------------------------------------
        ## Validate LLM plan schema
        ## --------------------------------------------------------
        #allowed_actions = {
        #    "cleanup_and_retry",
        #    "retry_with_modified_command",
        #    "abort",
        #    "fallback",
        #    }

        ## Must be a dict
        #if not isinstance(plan, dict):
        #    return {"error": "Invalid plan format", "action": "fallback"}

        #action = plan.get("action")

        ## Validate action
        #if action not in allowed_actions:
        #    return {"error": "Invalid or missing action", "action": "fallback"}

        ## Validate cleanup
        #if "cleanup" in plan and not isinstance(plan["cleanup"], list):
        #    return {"error": "Invalid cleanup field", "action": "fallback"}

        ## Validate retry
        #if "retry" in plan and not isinstance(plan["retry"], str):
        #    return {"error": "Invalid retry field", "action": "fallback"}

        ## If we reach here, plan is valid and return to the LLM
        #return plan
        ##return response.json()



        #### UPDATED plan validator. `response.json()` is the **entire Responses API envelope**, not the plan
        #### The code below has been refactored so that the validator: 
        #- extracts the inner JSON plan  
        #- parses it  
        #- validates it  
        #- returns it cleanly  
        # This will make the logic in the validator work properly relative to teh inner JSON plan


        ##### This is the plan validator. The AI Gateway Service has to validate the plan from the LLM before sending back to the 
        ##### MCP Client (module2f)
        ##### This is referred to as the outgoing validator
        # If HTTP status is not 2xx, raise exception and print the error using except block below.
        response.raise_for_status()
        raw = response.json()

        # --------------------------------------------------------
        # Extract inner JSON plan from Responses API envelope
        # --------------------------------------------------------
        text = raw["output"][0]["content"][0]["text"]
        plan = json.loads(text)

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

        # If we reach here, plan is valid and returned to MCPClient/module2f
        return plan



    #### This is the except block for the entire try block above. This will protect module2f, the calling and receiving function 
    #### from a crash anywhere inside the try block above.
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

