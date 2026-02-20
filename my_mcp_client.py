"""
This is a TEST-ONLY stub for pytest.

The real MCP client implementation lives inside:
    sequential_master_modules/my_mcp_client.py
and is used by the master script during normal execution.

This stub exists solely so that pytest can import module2/module2f
without requiring the full MCP client or any external dependencies.

IMPORTANT:
- The master script does NOT use this file.
- Multiprocessing spawn mode does NOT use this file.
- This file is ONLY imported when pytest runs.
"""

class MCPClient:
    def __init__(self, *args, **kwargs):
        # No-op constructor for test isolation
        pass

    def send(self, *args, **kwargs):
        # Return a harmless, deterministic stub response
        return {
            "status": "ok",
            "message": "stubbed MCPClient.send()"
        }

