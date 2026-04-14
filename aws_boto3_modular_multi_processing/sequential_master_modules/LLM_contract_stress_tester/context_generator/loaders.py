import json
import os

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
    """
    filename = f"{schema_name}.json"
    path = os.path.join(SCHEMAS_DIR, filename)

    if not os.path.exists(path):
        raise FileNotFoundError(f"Schema file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data


def get_contexts_from_schema(schema_name):
    """
    Convenience helper: load schema and return its 'contexts' list.
    """
    schema = load_schema(schema_name)
    contexts = schema.get("contexts", [])
    if not isinstance(contexts, list):
        raise ValueError(f"'contexts' must be a list in schema {schema_name}")
    return contexts

