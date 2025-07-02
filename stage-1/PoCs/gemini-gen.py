# using extract.py to get the description of the function
# and generate the gemini prompt to generate the code for the function

import sys
import os
# from extract import extract_function_html # unused import, but kept for reference
from google import genai
from tqdm import tqdm

client = genai.Client(api_key="AIzaSyBJbKTNWs2JcLErkpvXw7cOpKNbzUOsV1w")

# walk through ../php-chunked-xhtml/ and find the function.xxxx.html file
# return the list of files
def find_function_html_files(directory):
    """Finds all function.xxxx.html files in the specified directory."""
    function_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            # print(f"Checking file: {file}")  # Debugging line to see which files are being checked
            if file.startswith("function.") and file.endswith(".html"):
                function_files.append(os.path.join(root, file))
    return function_files

def generate_php_code_from_html():
    """Generates a simple PHP code snippet from the provided HTML content of a PHP function documentation page."""
    file_list = find_function_html_files("/dsk/hdd/home/llmft/Paper/SSRFuzz/stage-1/php-chunked-xhtml/")
    if not file_list:
        print("No function.xxxx.html files found in ../php-chunked-xhtml/")
        sys.exit(1)
    print(f"Found {len(file_list)} function.xxxx.html files in ../php-chunked-xhtml/")  
    # and now for loop to generate the code for each file
    for file in tqdm(file_list):
        with open(file, 'r', encoding='utf-8') as f:
            html_content = f.read()

        function_description = html_content.strip()
        prompt = f"""
        You are an expert-level PHP code generation assistant. Your sole purpose is to analyze the provided HTML content, which is a documentation page for a single PHP function from the official PHP manual, and generate a simple, self-contained PHP code example for that specific function.

        **Your Task:**
        From the HTML I provide, generate a minimalist and syntactically correct PHP code snippet that demonstrates the primary usage of the function described in the document.

        **Rules and Constraints:**

        1.  **Analyze the HTML:** Carefully parse the provided HTML to identify the core components of the function:
            * The exact function name (e.g., from the `<h1 class="refname">` tag).
            * The function's signature, including parameters and their types (from the `<div class="methodsynopsis">` section).
            * The function's purpose (from the description).

        2.  **Code Simplicity:** The generated code must be as simple as possible.
            * Do not include any complex logic, classes (unless necessary to demonstrate the function), or external dependencies.
            * The goal is to create a basic "Hello World" style example for the function.
            * Declare any necessary variables with simple, placeholder values right before the function call.

        3.  **Function Call Accuracy:** This is the most critical rule.
            * The function name in your generated code must be an **exact match** to the one in the documentation.
            * The number, order, and basic types of arguments passed to the function must correctly correspond to its definition found in the HTML.

        4.  **Syntactic Correctness:** The code must be a complete, runnable PHP script.
            * It must start with `<?php`.
            * It must be free of any PHP syntax errors.

        5.  **Strict Output Format:**
            * Your entire response must **ONLY** be the raw PHP code block.
            * **DO NOT** include any explanations, introductory phrases (like "Here is the code:"), comments, or Markdown formatting (e.g., ```php).
            * The response must begin directly with `<?php` and end with `?>`.

        **Example Scenario:**
        If I provide the HTML for `strlen()`, a correct response would be:
        <?php
        $length = strlen($my_string1);
        echo $length;
        ?>
        Notice that, all parameters should be the name like $my_string1, $my_string2, etc. This is very important.
        The parms name must be $web3_1, $web3_2, etc. CANNOT be other names.!!!
        DO NOT assign the exact value to the variable, just declare it.
        Now, process the following HTML content and generate the code.
        {function_description}
        """

        response = client.models.generate_content(
            model="gemini-2.5-flash", contents=prompt
        )
        print(response.text)
        # extract the xxx(function.xxx.html) i want xxx exactly
        function_name = file.split('/')[-1].replace('function.', '').replace('.html', '')
        # save the response to a file named function_name.php
        output_file = f"function_{function_name}.php"
        with open(output_file, 'w', encoding='utf-8') as out_f:
            # we should remove the first line and the last line
            sanitized_code = response.text.strip().split('\n')[1:-1]
            out_f.write('\n'.join(sanitized_code))
           
        
    
if __name__ == "__main__":
    generate_php_code_from_html()  # Call the function to start the process