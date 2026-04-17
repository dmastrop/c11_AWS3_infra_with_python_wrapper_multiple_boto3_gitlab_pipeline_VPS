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
# Must use this URL for LLM API endpoint for 4.1. The 4.1-pro model is not supported with this API.
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
            #"model": "gpt-4.1",
            "model": "gpt-5.4",
            "temperature": 0,
            "max_output_tokens": 256,

            # The "input" field contains the entire contract, rules, and context.
            # The LLM receives this as a single string and MUST return a JSON object.
            "input": (
                "You are a recovery engine. "
                "Follow the contract and rules provided inside the input JSON. "
                "Return ONLY a JSON object.\n\n"



                ##### HIGH LEVEL ORGANIZATION ####
                #Global rules
                #CONTEXT
                #Linux-generic malformed rules
                #OS-specific domain blocks (domain primitives)




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
                # RETRY FIELD SEMANTICS
                # Revision 4: Clarified per-action retry shape (string vs list)
                # This revision aligns the Contract with the module2f code itself, which can support multiple commands for the retry
                # command but only with the cleanup_and_retry contract action and not the retry_with_modified_command contract action
                # The cleanup_and_retry has specific use cases and those will be clarified as well in this CONTRACT with Revision 4
                # See CLEANUP_AND_RETRY_SEMANTICS further below (also part of Revsion 4)
                # Module2f already will mark the cleanup_and_retry action as failed if any one of the commands in a retry list fails.
                # ============================================================
                "Retry field semantics (Revision 4):\n"
                "- For \"retry_with_modified_command\", the \"retry\" field MUST be exactly one corrected command (a single string).\n"
                "- For \"cleanup_and_retry\", the \"retry\" field MAY be either:\n"
                "    * a single command (string), OR\n"
                "    * a list of commands for multi-step recovery.\n"
                "- When \"retry\" is a list, commands are executed sequentially in the order provided.\n"
                "- If ANY retry command fails (non-zero exit status or non-empty stderr), the entire cleanup_and_retry action is considered failed immediately.\n"
                "- Only if ALL retry commands succeed is the cleanup_and_retry action considered successful.\n\n"



                # ============================================================
                # CLEANUP RULES
                # ============================================================
                "Cleanup rules:\n"
                "- The \"cleanup\" field MUST be a list of literal shell commands.\n"
                "- Cleanup commands MUST be safe, minimal, and directly related to resolving the failure.\n"
                "- Cleanup commands MUST NOT include vague instructions or commentary.\n"
                "- Cleanup commands MUST NOT include dangerous operations.\n\n"


                # ============================================================
                # CLEANUP_AND_RETRY SEMANTICS
                # Revision 4: Restored original multi-step cleanup_and_retry behavior
                # ============================================================
                "Cleanup-and-retry rules (Revision 4):\n"
                "- Use \"cleanup_and_retry\" when the failure can be resolved by removing temporary files, stale locks, partial installations, or other artifacts blocking success.\n"
                "- Typical cleanup-and-retry conditions include:\n"
                "  - leftover PID files or lock files\n"
                "  - partially installed packages or corrupted temp directories\n"
                "  - stale processes that must be terminated before retrying\n"
                "  - insufficient disk space that can be reclaimed safely\n"
                "  - any reversible condition where cleanup restores a safe state.\n"
                "- When returning \"cleanup_and_retry\", provide:\n"
                "  - a list of cleanup commands in the \"cleanup\" field (which MAY be empty), and\n"
                "  - one or more retry commands in the \"retry\" field.\n"
                "- For \"cleanup_and_retry\", the \"retry\" field MAY be a single string or a list of commands.\n"
                "- When multiple retry commands are provided, they are executed sequentially.\n"
                "- If ANY retry command fails (non-zero exit status or non-empty stderr), the entire cleanup_and_retry action is considered failed immediately.\n"
                "- Only if ALL retry commands succeed is the action considered successful.\n\n"



                # ============================================================
                # IDEMPOTENCY RULES
                # Revision 4: Idempotency-related failures MUST use cleanup_and_retry
                # ============================================================
                "Idempotency rules (Revision 4):\n"
                "- Idempotency-related failures MUST use \"cleanup_and_retry\".\n"
                "- Idempotency conditions include messages such as:\n"
                "  - \"already installed\"\n"
                "  - \"already exists\"\n"
                "  - \"nothing to do\"\n"
                "  - \"resource busy\"\n"
                "  - \"lock is held by PID ...\"\n"
                "  - \"directory not empty\"\n"
                "  - \"service already running\"\n"
                "  - \"package is in a half-installed state\".\n"
                "- These failures are caused by environmental residue, not incorrect commands.\n"
                "- When idempotency is detected, return a \"cleanup_and_retry\" plan with cleanup commands that restore a safe state, followed by one or more retry commands.\n\n"



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




                ## ============================================================
                ## ACTION MEANINGS
                ## ============================================================
                #"Action meanings:\n"
                #"- cleanup_and_retry: Use when the failure can be fixed by cleanup steps before retrying.\n"
                #"- retry_with_modified_command: Use when the failure can be fixed by adjusting the command.\n"
                #"- abort: Use when the failure is unsafe or cannot be recovered.\n"
                #"- fallback: Use when there is not enough information to choose another action.\n\n"




                # ============================================================
                # ACTION MEANINGS Revision 4 addendum.This is a rewrite of the original ACTION MEANINGS to align to the 
                # multiple command support for retry in the cleanup_and_retry command action
                # ============================================================
                "Action meanings:\n"
                "- cleanup_and_retry: Use for environmental or state-related failures that can be fixed by cleanup and/or multi-step recovery before retrying.\n"
                "  Examples: idempotency residue, lock files, half-installed packages, stale processes, privilege or mode setup sequences.\n"
                "- retry_with_modified_command: Use for simple, single-command corrections where adjusting the original command is sufficient.\n"
                "  Examples: fixing a package name, adding a missing flag, choosing the correct package manager, correcting a mistyped command.\n"
                "- abort: Use when the failure is unsafe or cannot be recovered without risk of data loss, instability, or security exposure.\n"
                "- fallback: Use when there is not enough safe, concrete information to choose another action without guessing.\n\n"




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




                ##### DOMAIN SPECIFIC PRIMITIVES ######
                ##### NOTE: create semantic boundaries with clear demarcation of "these rules only apply to x OS" to prevent
                ##### rule leakage between different OSes and platforms, etc.



                # ============================================================
                # MALFORMED COMMAND RULES (LINUX)
                # Revision 2: Added explicit handling for incomplete but fixable Linux commands. This ENTIRE block is newly added
                # with revision 2. 
                # ============================================================
                # NOTE these primitives apply to all Linux OSes: Ubuntu Debian CentOS RHEL Fedora Alpine BusyBox
                # There are domain primitives for each one of these OSes further below

                "These rules apply ONLY to Linux-family OSes: Ubuntu, Debian, CentOS, RHEL, Fedora, Alpine, BusyBox.\n"

                "Malformed command rules (Linux):\n"
                "- Treat commands like \"apt-get install\", \"yum install\", \"dnf install\", and \"apk add\" with no package as INCOMPLETE, not unsafe.\n"
                "- If the command is incomplete but the missing argument CANNOT be safely inferred, prefer \"fallback\" over \"abort\".\n"
                "- Do NOT guess a package name based solely on prior examples or patterns in the input.\n"
                "- Only use \"retry_with_modified_command\" when you can safely construct a complete, realistic command.\n"
                "- Incomplete commands MUST NOT trigger \"abort\" unless they are also unsafe or destructive.\n\n"








                # ============================================================
                # UBUNTU (APT) DOMAIN RULES — Applies ONLY when os_name = "Ubuntu"
                # ============================================================
                "These rules apply ONLY when os_name = \"Ubuntu\".\n"

                # ------------------------------------------------------------
                # Literal precedence meta-rule (Revision 6.3)
                # ------------------------------------------------------------
                "- Literal‑match rules take precedence over semantic or general rules.\n"
                "  If stderr contains an EXACT phrase referenced by any rule, the LLM MUST apply that rule\n"
                "  even if earlier rules appear semantically similar.\n"
                "  Only when no literal phrase matches may the LLM fall back to general or earlier rules.\n\n"

                # ------------------------------------------------------------
                # Ubuntu (APT) Domain Primitives (Minimal Required Knowledge)  This is Revision 5 a new block.
                # ------------------------------------------------------------
                "Ubuntu APT domain primitives:\n"
                "- Ubuntu uses 'apt' and 'apt-get' as its package managers.\n"
                "- The command 'apt-get update' refreshes package indexes.\n"
                "- The command 'apt-get install <pkg>' installs packages.\n"
                "- The flag '-y' auto-confirms installation.\n"
                "- If a package cannot be located (E: Unable to locate package),\n"
                "  the LLM MUST retry with:\n"
                "    * apt-get update\n"
                "    * apt-get install -y <pkg>\n"
                "- If the command is missing arguments (e.g., 'apt-get install'),\n"
                "  treat it as malformed and use retry_with_modified_command.\n"
                "- If the command uses a package manager that does not match Ubuntu (yum, dnf, apk),\n"
                "  the LLM MUST rewrite the command using the correct Ubuntu package manager ('apt-get') and retry.\n"
                "- If the command is destructive (rm -rf /), the LLM MUST abort.\n"
                "- If the command is unrecognized (exit_status 127), fallback is allowed.\n"
                "- Network failures during 'apt-get update' (e.g., DNS errors)\n"
                "  MUST be handled with fallback.\n\n"

                ##### Revision 6 addtions to the ubuntu domain primitives  #####
                "- If stderr suggests running 'dpkg --configure -a', the LLM MUST return\n"
                "  a cleanup_and_retry action with the following retry sequence:\n"
                "    * dpkg --configure -a\n"
                "    * apt-get install -y <pkg>\n"
               
                ##### Revision 6.2
                "- If stderr CONTAINS the EXACT phrase 'held broken packages', the LLM MUST NOT run 'apt --fix-broken install'.\n"
                "  This condition is non-deterministic and MUST use fallback.\n"

                "- If stderr suggests running 'apt --fix-broken install', the LLM MUST return\n"
                "  a cleanup_and_retry action with the following retry sequence:\n"
                "    * apt --fix-broken install -y\n"
                "    * apt-get install -y <pkg>\n"

                ##### Revision 6.2
                "- If stderr CONTAINS the EXACT phrase 'Hash Sum mismatch', the LLM MUST NOT use fallback.\n"
                "  It MUST return a cleanup_and_retry action with the following retry sequence:\n"
                "    * rm -rf /var/lib/apt/lists/partial/*\n"
                "    * rm -rf /var/cache/apt/archives/partial/*\n"
                "    * apt-get update -y\n"
                "    * apt-get install -y <pkg>\n"


                ###### INSERT NEW DOMAIN PRIMITIVES HERE #########




                ###################################################

                # ============================================================
                # CISCO IOS DOMAIN RULES — Applies ONLY when os_name = "Cisco IOS"
                # ============================================================
                "These rules apply ONLY when os_name = \"Cisco IOS\".\n"

                # ============================================================
                # CISCO IOS RULES
                # Revision 3: Added full Cisco IOS command families, correction rules,
                # malformed rules, safe/unsafe rules, fallback logic, retry logic,
                # and abort logic. This ENTIRE block is newly added with Revision 3.
                # ============================================================
                "Cisco IOS rules:\n"
                "- Cisco IOS is a network device operating system with its own CLI, not a Linux shell.\n"
                "- Cisco IOS commands MUST NOT be treated as Linux commands.\n"
                "- Cisco IOS does NOT support apt, apt-get, yum, dnf, apk, brew, or any Linux package manager.\n"
                "- Cisco IOS does NOT support bash, zsh, sh, PowerShell, or macOS shells.\n"
                "- Cisco IOS commands MUST be interpreted using IOS semantics only.\n\n"

                # ------------------------------------------------------------
                # VALID IOS COMMAND FAMILIES
                # ------------------------------------------------------------
                "Valid Cisco IOS command families:\n"
                "- 'show' commands (safe):\n"
                "    show ip interface brief\n"
                "    show running-config\n"
                "    show version\n"
                "    show ip route\n"
                "- 'configure terminal' (safe but privileged)\n"
                "- 'interface' configuration commands (not used in tests but valid)\n"
                "- 'enable' mode commands (not used in tests but valid)\n\n"

                # ------------------------------------------------------------
                # IOS MALFORMED COMMAND RULES. Preferred retry_with_modified_command or fallback contract actions
                # ------------------------------------------------------------
                "Malformed Cisco IOS command rules:\n"
                "- The stderr pattern \"% Invalid input detected at '^' marker.\" indicates:\n"
                "    * mistyped command, OR\n"
                "    * incomplete command, OR\n"
                "    * wrong mode (not in enable/config mode), OR\n"
                "    * ambiguous command.\n"
                "- This MUST NOT trigger 'abort' unless the command is destructive.\n"
                "- For malformed IOS commands, prefer 'retry_with_modified_command' or 'fallback'.\n\n"

                # ------------------------------------------------------------
                # IOS COMMAND CORRECTION RULES
                # ------------------------------------------------------------
                "Cisco IOS command correction rules:\n"
                "- Correct 'show route everything' → 'show ip route'.\n"
                "- Correct 'show route all' → 'show ip route'.\n"
                "- Correct 'show ip int br' → 'show ip interface brief'.\n"
                "- Correct 'show run' → 'show running-config'.\n"
                "- Correct 'show ver' → 'show version'.\n"
                "- If the command is a valid IOS command but failed due to mode, retry the SAME command.\n"
                "- If the command is ambiguous or incomplete and cannot be safely corrected, use 'fallback'.\n\n"

                # ------------------------------------------------------------
                # IOS SAFE COMMAND RULES
                # ------------------------------------------------------------
                "Cisco IOS safe commands:\n"
                "- All 'show' commands are safe and MUST NOT trigger 'abort'.\n"
                "- 'configure terminal' is safe (but privileged) and MUST NOT trigger 'abort'.\n"
                "- Safe commands that fail should use 'retry_with_modified_command' or 'fallback'.\n\n"

                # ------------------------------------------------------------
                # IOS UNSAFE COMMAND RULES
                # ------------------------------------------------------------
                "Cisco IOS unsafe commands:\n"
                "- 'reload' (reboots the device)\n"
                "- 'write erase' (erases configuration)\n"
                "- 'erase startup-config'\n"
                "- 'format flash:'\n"
                "- Any command that modifies system storage or deletes configuration.\n"
                "- Unsafe commands MUST trigger 'abort' with a clear message.\n\n"

                # ------------------------------------------------------------
                # IOS FALLBACK LOGIC
                # ------------------------------------------------------------
                "Cisco IOS fallback rules:\n"
                "- Use 'fallback' when the command is malformed AND no safe correction exists.\n"
                "- Use 'fallback' when the command is ambiguous.\n"
                "- Use 'fallback' when the command requires privileged mode and correction is unclear.\n"
                "- Use 'fallback' when the command is incomplete and cannot be safely inferred.\n\n"

                # ------------------------------------------------------------
                # IOS RETRY LOGIC
                # ------------------------------------------------------------
                "Cisco IOS retry rules:\n"
                "- Use 'retry_with_modified_command' when a malformed IOS command can be safely corrected.\n"
                "- Use 'retry_with_modified_command' when the command is valid but failed due to mode.\n"
                "- The 'retry' field MUST contain a valid IOS command, not a Linux command.\n"
                "- NEVER propose Linux commands (apt, yum, dnf, apk, bash, etc.).\n\n"

                # ------------------------------------------------------------
                # IOS ABORT LOGIC
                # ------------------------------------------------------------
                "Cisco IOS abort rules:\n"
                "- Abort ONLY when the command is destructive or unsupported.\n"
                "- Abort when the user attempts Linux package installation on IOS.\n"
                "- Abort when the user attempts Linux shell commands on IOS.\n"
                "- Abort when the command is unsafe (reload, write erase, erase startup-config, etc.).\n"
                "- Abort MUST include a clear 'message' explaining the reason.\n\n"

                # ------------------------------------------------------------
                # IOS ABORT MESSAGE EXAMPLES
                # ------------------------------------------------------------
                "Examples of valid Cisco IOS abort messages:\n"
                "    { \"action\": \"abort\", \"message\": \"Unsupported OS: Cisco IOS does not support Linux package managers.\" }\n"
                "    { \"action\": \"abort\", \"message\": \"Unsupported OS: Cisco IOS does not support shell commands.\" }\n"
                "    { \"action\": \"abort\", \"message\": \"Unsafe command detected: write erase\" }\n"
                "    { \"action\": \"abort\", \"message\": \"Unsafe command detected: reload\" }\n\n"

                # ============================================================
                # CISCO IOS RULES — REVISION 3.2 PATCH
                # Revision 3.2: Clarified multi-step privilege escalation using cleanup_and_retry.
                # NOTE: Revision 3.2 requires Revision 4 which is a refactoring of the CONTRACT to allign with the multiple
                # Command support in module2f with the cleanup_and_retry contract action (NOT the retry_with_modified_command
                # contract action).
                # ============================================================
                "Cisco IOS additional rules (Revision 3.2):\n"
                "- For Cisco IOS, multi-step privilege escalation (e.g., \"enable\" followed by \"configure terminal\") MUST be expressed using \"cleanup_and_retry\" with a retry list.\n"
                "- Example:\n"
                "    { \"action\": \"cleanup_and_retry\", \"cleanup\": [], \"retry\": [\"enable\", \"configure terminal\"] }.\n"
                "- Do NOT attempt to express multi-step privilege escalation using \"retry_with_modified_command\"; that action is reserved for single-command corrections.\n\n"

                # ------------------------------------------------------------
                # IOS PRIVILEGE MODE KNOWLEDGE (Required for accurate reasoning)
                # With Revision 3.3 (see below)
                # ------------------------------------------------------------
                "Cisco IOS privilege mode semantics:\n"
                "- Cisco IOS has two primary command modes relevant to this contract:\n"
                "    * User EXEC mode (prompt ends with '>') — limited read-only access.\n"
                "    * Privileged EXEC mode (prompt ends with '#') — full administrative access.\n"
                "- The command 'enable' transitions from User EXEC mode to Privileged EXEC mode.\n"
                "- The command 'configure terminal' ALWAYS requires Privileged EXEC mode.\n"
                "- If 'configure terminal' is executed while NOT in Privileged EXEC mode, IOS returns:\n"
                "    '% Invalid input detected at '^' marker.'\n"
                "- Therefore, any failure of 'configure terminal' MUST be treated as a privilege-mode failure.\n\n"


                # ============================================================
                # CISCO IOS RULES — REVISION 3.3
                # Privilege-mode failures MUST use cleanup_and_retry
                # ============================================================
                "Cisco IOS privilege-mode rules (Revision 3.3):\n"
                "- If a command fails because the device is NOT in privileged mode (e.g., '% Invalid input' for 'configure terminal'),\n"
                "  the LLM MUST use \"cleanup_and_retry\" and MUST provide a retry list that includes:\n"
                "    1. \"enable\"\n"
                "    2. the original intended command (e.g., \"configure terminal\").\n"
                "- This rule OVERRIDES malformed-command rules.\n"
                "- This rule OVERRIDES retry_with_modified_command rules.\n"
                "- NEVER use retry_with_modified_command for privilege-mode escalation.\n\n"


                # ------------------------------------------------------------
                # Cisco IOS Privileged-Only Commands (Domain Knowledge Block)
                # Revision 3.4
                # ------------------------------------------------------------
                "Cisco IOS privileged-only commands:\n"
                "- The following commands ALWAYS require Privileged EXEC mode (Router#):\n"
                "    * configure terminal\n"
                "    * show running-config\n"
                "    * show startup-config\n"
                "    * write memory\n"
                "    * copy running-config startup-config\n"
                "    * copy startup-config running-config\n"
                "    * erase startup-config\n"
                "    * reload\n"
                "- If any of these commands fail with '% Invalid input detected at '^' marker.',\n"
                "  the LLM MUST treat the failure as a privilege-mode failure.\n"
                "- For privilege-mode failures, the LLM MUST use 'cleanup_and_retry' with the retry list:\n"
                "    1. enable\n"
                "    2. the original intended command\n"
                "- These rules OVERRIDE malformed-command rules.\n"
                "- These rules OVERRIDE retry_with_modified_command rules.\n"
                "- NEVER use retry_with_modified_command for privilege-mode escalation.\n\n"






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


        # ============================================================
        # OUTGOING PLAN VALIDATOR — REVISION 3.2 + REVISION 4 ALIGNMENT (see below)
        # The former code is deprectated.
        #
        # This validator enforces the CONTRACT rules before sending the
        # LLM-generated plan to the MCP Client (module2f).
        #
        # These changes are REQUIRED to support:
        #   - Revision 3.2 (Cisco IOS multi-step privilege escalation)
        #   - Revision 4  (cleanup_and_retry multi-command semantics,
        #                  idempotency rules, and action meaning updates)
        #
        # Module2f ALREADY supports:
        #   - retry as a string OR list[str] for cleanup_and_retry
        #   - retry as ONLY a string for retry_with_modified_command
        #   - strict abort message requirements
        #
        # This validator now enforces:
        #
        #   1. retry_with_modified_command:
        #        - retry MUST be a single string
        #
        #   2. cleanup_and_retry:
        #        - retry MAY be a string OR list[str]
        #        - cleanup MUST be a list
        #
        #   3. abort:
        #        - message is REQUIRED
        #
        #   4. non-abort actions:
        #        - message MUST NOT appear
        #
        # These changes ensure the gateway accepts the richer, more
        # accurate plans produced after Revision 3.2 and Revision 4,
        # enabling full end-to-end pipeline testing in Phase 4a.1.3.
        # ============================================================

        
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

        # --------------------------------------------------------
        # Validate cleanup (must always be a list when present)
        # --------------------------------------------------------
        cleanup = plan.get("cleanup")
        if cleanup is not None and not isinstance(cleanup, list):
            return {"error": "Invalid cleanup field", "action": "fallback"}

        # --------------------------------------------------------
        # Validate retry (rules differ by action retry_with_modified_command vs. cleanup_and_retry
        # This permits contract Revision 3.2 and Revision 4 changes to plan to be propagated through this outgoing validator 
        # and to the MCPClient of module2f
        # --------------------------------------------------------
        retry = plan.get("retry")

        if action == "retry_with_modified_command":
            # MUST be a single string
            if not isinstance(retry, str):
                return {"error": "Invalid retry field for retry_with_modified_command", "action": "fallback"}

        elif action == "cleanup_and_retry":
            # MAY be string OR list[str]
            if not (
                isinstance(retry, str) or
                (isinstance(retry, list) and all(isinstance(cmd, str) for cmd in retry))
            ):
                return {"error": "Invalid retry field for cleanup_and_retry", "action": "fallback"}

        elif action in ("fallback", "abort"):
            # retry MUST NOT appear
            if retry not in (None, "", []):
                return {"error": "Retry field not allowed for this action", "action": "fallback"}

        # --------------------------------------------------------
        # Validate message field
        # --------------------------------------------------------
        message = plan.get("message")

        if action == "abort":
            # message REQUIRED
            if not isinstance(message, str) or not message.strip():
                return {"error": "Abort requires message", "action": "fallback"}

        else:
            # message MUST NOT appear for non-abort actions
            if message is not None:
                return {"error": "Message not allowed for non-abort action", "action": "fallback"}

        # --------------------------------------------------------
        # If we reach here, plan is valid and returned to module2f
        # --------------------------------------------------------
        return plan



        ##### Deprecated code for the code above that aligns with contract Revision 3.2 and Revision 4
        ## --------------------------------------------------------
        ## Validate LLM plan schema
        ## --------------------------------------------------------
        #allowed_actions = {
        #    "cleanup_and_retry",
        #    "retry_with_modified_command",
        #    "abort",
        #    "fallback",
        #}

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

        ## If we reach here, plan is valid and returned to MCPClient/module2f
        #return plan



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

