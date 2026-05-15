import json
import os

# NEW: import the generator that injects os_name/os_version into each context
from .generator import generate_contexts

SCHEMAS_DIR = os.path.join(
    os.path.dirname(__file__),
    "schemas"
)

def list_available_schemas():
    """
    Return a list of schema base names (without .json) in the schemas directory.
    """
    files = []
    for name in os.listdir(SCHEMAS_DIR):
        if name.endswith(".json"):
            files.append(os.path.splitext(name)[0])
    return sorted(files)


def load_schema(schema_name):
    """
    Load a schema JSON file by base name (e.g. 'ubuntu_apt') and return the full dict.

    IMPORTANT:
    ----------
    The raw schema contains:
        - os_name
        - os_version
        - contexts[] (raw test cases)

    But the raw contexts DO NOT contain os_name/os_version.
    The semantics validator requires os_name/os_version INSIDE each context.

    Therefore we must call generate_contexts(schema) to inject these fields.
    This is ONLY for the stress tester. Real life does NOT do this.
    
    See the extensive documenatation on this design in the README. 
    See the comments in the generator.py for more detail on this as well.

    """

    filename = f"{schema_name}.json"
    path = os.path.join(SCHEMAS_DIR, filename)

    if not os.path.exists(path):
        raise FileNotFoundError(f"Schema file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # NEW: inject os_name/os_version into each context for the semantics validator
    schema["contexts"] = generate_contexts(schema)

    return schema


def get_contexts_from_schema(schema_name):
    """
    Convenience helper: load schema and return its 'contexts' list.

    NOTE:
    -----
    Because load_schema() now injects os_name/os_version into each context,
    this function will automatically return the augmented contexts.
    """
    schema = load_schema(schema_name)
    contexts = schema.get("contexts", [])
    if not isinstance(contexts, list):
        raise ValueError(f"'contexts' must be a list in schema {schema_name}")
    return contexts





#### Old version 1 code is below. This is prior to engaging the generator.py code using the generate_contexts function to 
#### inject os_name and os_version into the RAW stress tester contexts.

#import json
#import os
#
#SCHEMAS_DIR = os.path.join(
#    os.path.dirname(__file__),
#    "schemas"
#)
#
#def list_available_schemas():
#    """
#    Return a list of schema base names (without .json) in the schemas directory.
#    """
#    files = []
#    for name in os.listdir(SCHEMAS_DIR):
#        if name.endswith(".json"):
#            files.append(os.path.splitext(name)[0])
#    return sorted(files)
#
#
#def load_schema(schema_name):
#    """
#    Load a schema JSON file by base name (e.g. 'ubuntu_apt') and return the full dict.
#    """
#    filename = f"{schema_name}.json"
#    path = os.path.join(SCHEMAS_DIR, filename)
#
#    if not os.path.exists(path):
#        raise FileNotFoundError(f"Schema file not found: {path}")
#
#    with open(path, "r", encoding="utf-8") as f:
#        data = json.load(f)
#
#    return data
#
#
#def get_contexts_from_schema(schema_name):
#    """
#    Convenience helper: load schema and return its 'contexts' list.
#    """
#    schema = load_schema(schema_name)
#    contexts = schema.get("contexts", [])
#    if not isinstance(contexts, list):
#        raise ValueError(f"'contexts' must be a list in schema {schema_name}")
#    return contexts

