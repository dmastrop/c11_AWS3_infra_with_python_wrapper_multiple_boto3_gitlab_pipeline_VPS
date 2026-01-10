python3 - << 'EOF'
import importlib.util
import sys
import os

# Add the parent directory to sys.path so that sequential_master_modules becomes importable.
sys.path.append(os.path.dirname(os.getcwd()))



module_path = "module2_install_tomcat_patch8_99.py"
module_name = "module2_install_tomcat_patch8_99"

spec = importlib.util.spec_from_file_location(module_name, module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
spec.loader.exec_module(module)

print("Imported:", module)
print("Has tomcat_worker_wrapper:", hasattr(module, "tomcat_worker_wrapper"))
EOF

