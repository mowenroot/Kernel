import os
import shutil
import subprocess
import re
from html import unescape

# Function to clean HTML from labels
def clean_label(html_label):
    # Removing HTML tags and converting HTML entities
    clean_text = re.sub(r'<[^>]+>', '', html_label)
    return unescape(clean_text)
    
def change_folder_owner(chscript, folder_path, new_owner):
    #try:
        # Construct the command to change ownership
        command = [chscript, folder_path]
        # Execute the command
        subprocess.run(command, check=True)
        print(f"Changed ownership of {folder_path} to {new_owner}.")
        
def get_all_files(directory, extensions):
    files = []
    for root, dirs, filenames in os.walk(directory):
        for filename in filenames:
            if any(filename.endswith(ext) for ext in extensions):
                files.append(os.path.join(root, filename))
    return files

import os
def copy_file_to_tmp_get_definition(file_path, tmp_dir):
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
    marco_definition = []
    with open(file_path, 'r') as src_file, open(f"{tmp_dir}/{os.path.basename(file_path)}", 'w') as dest_file:
        lines = src_file.readlines()
        for line in lines:
            if line.strip().startswith('#ifdef'):
                marco_definition.append(line.strip().split()[1])
            if line.strip().startswith('#ifndef'):
                marco_definition.append(line.strip().split()[1])
            if line.strip().startswith('#define'):
                marco_definition.append(line.strip().split()[1])
            #     line = line.replace('#', '//#')
            # elif line.strip().startswith('#endif'):
            #     line = line.replace('#', '//#')
            dest_file.write(line)
    return list(set(marco_definition))

# def run_joern_commands(tmp_dir, output_file):
#     try:
#         subprocess.run(["joern-parse", tmp_dir], check=True)
#         subprocess.run(["joern-export", tmp_dir, "--out", output_file], check=True)
#     except subprocess.CalledProcessError as e:
#         print(f"Error running joern commands: {e}")



# if __name__ == "__main__":
#     source_dir = "path_to_your_source_directory"
#     tmp_dir = "path_to_tmp_directory"
#     output_dir = "path_to_output_directory"
    
#     process_files(source_dir, tmp_dir, output_dir)