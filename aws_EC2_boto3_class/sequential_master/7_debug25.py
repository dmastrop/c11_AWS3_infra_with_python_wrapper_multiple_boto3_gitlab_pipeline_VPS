
import logging

# Set up logging
try:
    logging.basicConfig(level=logging.DEBUG)  # Change to DEBUG level
    logger = logging.getLogger(__name__)
    print("Logging setup successful")
except Exception as e:
    print(f"Logging setup failed: {e}")

# Confirm script execution
print("Script started")  # This should print

# Debug statement
try:
    logger.debug("This is a debug message")
    print("Debug statement executed")
except Exception as e:
    print(f"Failed to execute debug statement: {e}")

