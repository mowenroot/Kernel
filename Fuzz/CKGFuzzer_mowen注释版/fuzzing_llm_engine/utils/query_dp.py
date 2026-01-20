from loguru import logger
import subprocess
from . import _get_command_string
import os
from configs.codeql_config import CODEQL_PATH

def add_codeql_to_path():
    codeql_path = CODEQL_PATH
    current_path = os.environ.get('PATH', '')
    # print(f"Current PATH: {current_path}")
    # Check if CodeQL path is already in PATH1
    if codeql_path not in current_path:
        # Adding CodeQL to PATH
        os.environ['PATH'] += os.pathsep + codeql_path
        print(f"CodeQL has been added to PATH. New PATH: {os.environ['PATH']}")
    else:
        print("CodeQL is already in the PATH.")
add_codeql_to_path()


def run_command(command):
    logger.info(f'Running: %s {_get_command_string(command)}' )
    try:
        subprocess.run(command, check=True)
        #logger.info('Running: remove duplication from the csv file.')
        # subprocess.run(["sort", "--parallel", "5","-u", f"{output_file.replace('.bqrs', '.csv')}", "-o", f"{output_file.replace('.bqrs', '.csv')}"], shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run the query: {e}")
        return ""
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return ""
    

def run_converted_csv(output_file) -> str:
    # codeql bqrs decode --format=csv ./find_api.bqrs  --output=find_api.csv
    csv_file = output_file.replace('.bqrs', '.csv')
    command = [ "codeql", "bqrs", "decode", "--format=csv", output_file, f"--output={output_file.replace('.bqrs', '.csv')}" ]
    logger.info(f'Running: %s {_get_command_string(command)}' )
    try:
        subprocess.run(command, check=True)
        return csv_file
        #logger.info('Running: remove duplication from the csv file.')
        # subprocess.run(["sort", "--parallel", "5","-u", f"{output_file.replace('.bqrs', '.csv')}", "-o", f"{output_file.replace('.bqrs', '.csv')}"], shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run the query: {e}")
        return csv_file
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return csv_file

def run_query(query_script, output_file, database_db: str, additional_options=None) -> str:
    """
    Run the provided query on the database and return the results.

    Args:
        query (str): Query to be run on the database.
        database_db (str): Path to the database.

    Returns:
        str: Results of the query.
    """
    # Construct the command to run the query
    logger.info(f"CodeQL Path: {os.environ['PATH']}")
    command =[ "codeql", "query", "run", query_script, "-d", database_db, f"--output={output_file}" ]
    #command =[ "/home/mawei/Desktop/work1/wei/fuzzing_llm/fuzzing_os/oss-fuzz-modified/docker_shared/codeql/codeql", "--license" ]
    if additional_options:
        command += ["--additional_options", additional_options]
    logger.info(f'Running: %s {_get_command_string(command)}' )
    print(" ".join(command))
    try:
        subprocess.run(command, check=True, text=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run the query: {e}")
        return ""
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return ""