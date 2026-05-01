#!/usr/bin/env python3

"""
================================================================================
LLM CONTRACT STRESS TESTER — HIGH‑LEVEL DATA FLOW
================================================================================

This system is split into two major components:

1. stress_tester.py
2. curl_harness/harness.py

They work together to generate a full LLM payload, send it to the AI Gateway,
and capture the LLM's response.

-----------------------------------------
1. WHAT THE SCHEMA FILES CONTAIN
-----------------------------------------
The JSON schema files in context_generator/schemas/ contain ONLY the raw test
cases. Each entry includes:

    command
    stdout
    stderr
    exit_status
    attempt
    instance_id
    ip
    tags
    history

These are NOT full payloads. They do NOT include:

    schema_version
    os_info
    the "context": { ... } wrapper

Those must be added dynamically.

-----------------------------------------
2. WHAT stress_tester.py DOES
-----------------------------------------
stress_tester.py is responsible for:

    - loading a schema JSON file
    - selecting one context entry
    - injecting schema_version
    - injecting os_info (derived from schema metadata)
    - wrapping everything inside:
          {
            "schema_version": "...",
            "context": { ... }
          }
    - producing a FINAL Python dict payload
    - calling harness.send_payload(payload_dict)

stress_tester.py ALWAYS works with Python dicts, NOT JSON strings.

-----------------------------------------
3. WHAT harness.py DOES
-----------------------------------------
harness.py is a TRANSPORT LAYER ONLY.

It does NOT:
    - modify the payload
    - inject os_info
    - inject schema_version
    - wrap context
    - validate anything

It ONLY:
    - receives a fully‑assembled Python dict payload from stress_tester.py
    - converts dict → JSON string
    - writes JSON → temporary file
    - executes curl with "-d @tempfile.json"
    - captures raw stdout from curl (the LLM response)
    - returns that raw response string back to stress_tester.py

-----------------------------------------
4. WHY THE SEPARATION MATTERS
-----------------------------------------
This separation keeps the architecture clean:

    stress_tester.py = payload builder + orchestrator
    harness.py       = transport layer (curl wrapper)

This allows:
    - easy debugging
    - easy replacement of curl with Python requests later
    - clean logging
    - clean retries
    - clean artifact storage
    - clean validator integration

-----------------------------------------
5. SUMMARY
-----------------------------------------
The flow is:

    schema.json → dict → (stress_tester injects fields) → final dict payload
    → harness converts dict→JSON → curl → gateway → LLM → response
    → harness returns raw response → stress_tester prints/validates/scores

================================================================================
"""

"""
STRESS_TESTER.PY — PURPOSE

This module is the orchestrator.

It is responsible for:
    - loading schema files
    - selecting a context entry
    - injecting schema_version
    - injecting os_info (derived from schema metadata)
    - wrapping everything inside a "context" block
    - producing the FINAL Python dict payload
    - calling harness.send_payload(payload_dict)
    - printing the raw LLM response

This module ALWAYS works with Python dicts.
It NEVER sends JSON directly — that is harness.py's job.
"""


#### invocation is done from the docker deploy container during a gitlab pipeline run
#### The docker deploy container is running python 3.11.9 which is fully compatible with this code
#### The invocation is done by doing this:
#### docker exec -it <container_id> /bin/bash
#### Then once inside go into the the LLM_contract_stress_tester directory and run this:

#### python3 stress_tester.py --os ubuntu_apt --index 0   

#### This will use the ubuntu_apt.json schema and it will index the first context in that schema, context[0] and 
#### this will be used by the stress_tester.py as the substrate for the payload (in dict form) that will be fed into the
#### harness.py and converted to json before harness.py runs the curl command to the AI Gateway Service. Once teh 
#### gateway contacts the LLM and gets the plan response, the harness.py will return this result to the stress_tester.py
#### where stress_tester.py can create artifacts, reporting, and scoring for the test based upon the plan result that was returned
#### from the LLM.


import argparse
from context_generator.loaders import load_schema
from curl_harness.harness import send_payload


def build_payload(schema: dict, context: dict) -> dict:
    """
    Build the FINAL payload dict that will be sent to harness.send_payload().

    This is where we inject:
        - schema_version
        - os_info
        - the "context" wrapper
    """

    # Extract OS info from schema metadata
    # REMOVE the kernel from os_info. The module2f code for the AI/MCP hook _invoke_ai_hook does not use kernel in the context
    # block that is sent to the LLM . So the stress tester has to mirror that for whitebox testing. Regresssion test all 
    # schemas that were done with kernel for LLM re-training to the contract rules that we have now. 
    os_info = {
        "name": schema.get("os_name"),
        "version": schema.get("os_version"),
        #"kernel": schema.get("kernel"),
    }

    # Build the final payload dict
    payload = {
        "schema_version": "1.0",
        "context": {
            **context,      # unpack the raw context fields
            "os_info": os_info
        }
    }

    return payload


def main():
    # Parse CLI arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--os", required=True, help="Schema base name (e.g. ubuntu_apt)")
    parser.add_argument("--index", type=int, default=0, help="Which context index to run")
    args = parser.parse_args()

    # Load the schema JSON file
    schema = load_schema(args.os)

    # Extract the list of contexts
    contexts = schema.get("contexts", [])
    if not contexts:
        raise ValueError(f"No contexts found in schema {args.os}")

    # Select the context by index
    if args.index >= len(contexts):
        raise IndexError(f"Context index {args.index} out of range for schema {args.os}")

    context = contexts[args.index]

    # Build the final payload dict
    payload = build_payload(schema, context)

    # Send payload to gateway via harness
    response = send_payload(payload)

    # Print raw LLM response
    print("\n=== RAW LLM RESPONSE ===")
    print(response)
    print("========================\n")

    # Run validator v1 (see ../validator/validator.py code)
    validation = validate_response(schema, context, response)

    print("\n=== VALIDATION RESULT ===")
    print(f"OS: {validation['os_name']} {validation['os_version']}")
    print(f"Command: {validation['command']}")
    print(f"Status: {validation['status']}")
    if validation["errors"]:
        print("Errors:")
        for err in validation["errors"]:
            print(f"  - {err}")
    print("========================\n")

if __name__ == "__main__":
    main()

