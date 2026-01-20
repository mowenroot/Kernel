from tree_sitter import Language
import os
# Get the current file's directory
current_file_directory = os.path.dirname(os.path.abspath(__file__))
# Get the parent directory of the current file's directory
parent_directory = os.path.dirname(current_file_directory)
# Get the absolute path of the parent directory
parent_directory_abspath = os.path.abspath(parent_directory)

CPP_LANGUAGE = Language(f'{parent_directory_abspath}/codetext/parser/tree-sitter/cpp.so', 'cpp')
