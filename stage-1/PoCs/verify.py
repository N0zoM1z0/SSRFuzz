# Root path is /dsk/hdd/home/llmft/Paper/SSRFuzz/stage-1
# i need to
# 1. replace the $web3_i like parameter with the specific value $ssrf_test
# 2. after replacing, i'll use os to execute the php code
# 3. check the CBServer result, if "VULN" or "NO"

import os
import re
import subprocess

def write_specific_values(file_path):
    # write <?php in the first line of file_path
    with open(file_path, 'r', encoding='utf-8') as file:
        original_content = file.read()
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write("<?php\n")
        # file.write("$ssrf_test = \"http://localhost:8000/ssrftest\";\n")
        file.write(original_content)
        file.write("?>\n")
    
def replace_parameters_with_value(file_path, value="\"http://localhost:8000/ssrftest\""):
    """
    Replace all $web3_i parameters in the PHP code with the specified value.
    
    :param file_path: Path to the PHP file.
    :param value: The value to replace the parameters with.
    """
    
    # Replace all occurrences of $web3_i with the specified value
    
    write_specific_values(file_path)
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    updated_content = re.sub(r'\$web3_\d+', value, content)
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(updated_content)

def execute_php_code(file_path):
    """
    Execute the PHP code in the specified file and return the output.
    
    :param file_path: Path to the PHP file.
    :return: Output of the PHP execution.
    """
    try:
        result = subprocess.run(['php', file_path], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing PHP code: {e}")
        return None
def check_callback_server_result():
    """
    Check the result from the callback server.
    
    :return: "VULN" if vulnerable, "NO" if not vulnerable.
    """
    try:
        response = subprocess.run(['curl', 'http://localhost:8000/ssrftest'], capture_output=True, text=True, check=True)
        return response.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error checking callback server: {e}")
        return None
def verify_php_code(file_path):
    """
    Verify the PHP code by replacing parameters, executing it, and checking the callback server.
    
    :param file_path: Path to the PHP file.
    :return: "VULN" if vulnerable, "NO" if not vulnerable.
    """
    # Step 1: Replace parameters with $ssrf_test
    replace_parameters_with_value(file_path)
    
    # Step 2: Execute the PHP code
    php_output = execute_php_code(file_path)
    if php_output is None:
        return "Error executing PHP code"
    
    # Step 3: Check the callback server result
    callback_result = check_callback_server_result()
    
    return callback_result

if __name__ == "__main__":
    # Walkthrough the root path to find function_*.php files
    root_path = "/dsk/hdd/home/llmft/Paper/SSRFuzz/stage-1"
    for root, dirs, files in os.walk(root_path):
        for file in files:
            if file.startswith("function_") and file.endswith(".php"):
                file_path = os.path.join(root, file)
                print(f"Verifying {file_path} ...")
                result = verify_php_code(file_path)
                print(f"Result for {file_path}: {result}")
    print("Verification completed.")
# Note: Ensure that the callback server is running before executing this script.