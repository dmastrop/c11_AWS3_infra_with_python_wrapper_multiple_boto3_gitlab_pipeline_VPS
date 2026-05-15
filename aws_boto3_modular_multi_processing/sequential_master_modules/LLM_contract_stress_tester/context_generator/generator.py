# context_generator/generator.py

def generate_contexts(schema: dict) -> list:
    """
    Expand a schema into a list of executable contexts for the validator.

    Each context MUST include:
        - command
        - stderr
        - exit_status
        - os_name
        - os_version

    The stress tester uses schema metadata for LLM payloads,
    but the validator uses per-context metadata. This function
    injects that metadata so semantics files can operate correctly.
    
    It is important to note the differences between the two. The validator semantics logic requires knowledge of os_name
    and os_version and the only way to get that information to the validator semantics logic is to inject the os_name and 
    os_version directly into the RAW context (this is referred to as an augmented context in the documentation). 
   
    The stress tester itself uses the schema metadata and incorporates that into the payload using build_payload directly prior
    to sending to the LLM via the AI Gateway Service.

    In addition the validator.py uses the schema metadata to select the proper validator function (that applies the semantics
    logic to the test result). But this still does not get the os_name and os_version to the semantic function validator logic.
    The only way to do that is to directly inject into the RAW context and that is what we are doing here in generator.py
    with this generate_context function. This function will insert the os_name and os_info into all the contexts of a given
    schema (json file).

    NOTE: This is not done in real-life, this is only for the stress tester and ONLY for the validator portion of the 
    stress tester. In real life the os_info is used which is the os_name/os_version, and it is obtained from real life
    nodes (threads), incorporated into the registry_entry.tags field for that thread/node and then extracted out 
    in the AI/MCP hook and inserted into the payload (as os_infor) and sent to the AI Gateway Service which forwards to the LLM.
    The LLM is smart enough to get the os_name and os_version from the os_info construct. This has already been well tested.

    """

    contexts = []

    os_name = schema.get("os_name", "")
    os_version = schema.get("os_version", "")

    for entry in schema.get("contexts", []):
        ctx = dict(entry)  # shallow copy of command/stderr/exit_status
        ctx["os_name"] = os_name
        ctx["os_version"] = os_version
        contexts.append(ctx)

    return contexts

