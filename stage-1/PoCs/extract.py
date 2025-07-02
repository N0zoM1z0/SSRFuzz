# This python script extracts the function.xxxx.html file from ../php-chunked-xhtml/ and pass it to the gemini-gen.py

import os
import shutil
import sys

def extract_function_html(source_dir, target_file):
    """
    Extracts the function.xxxx.html file from the source directory and copies it to the target file.
    
    :param source_dir: Directory where the function.xxxx.html file is located.
    :param target_file: Path to the target file where the HTML content will be copied.
    """
    # Find the function.xxxx.html file in the source directory
    for filename in os.listdir(source_dir):
        if filename.startswith("function.") and filename.endswith(".html"):
            source_file = os.path.join(source_dir, filename)
            shutil.copy(source_file, target_file)
            print(f"Extracted {source_file} to {target_file}")
            return
    
    print("No function.xxxx.html file found in the specified directory.")