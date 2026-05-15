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

