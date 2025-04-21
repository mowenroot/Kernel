from loguru import logger
import sys
import subprocess
import os
# from helper import _add_oss_fuzz_ci_if_needed, _env_to_docker_args
from . import _get_command_string

def _env_to_docker_args(env_list):
  """Turns envirnoment variable list into docker arguments."""
  return sum([['-e', v] for v in env_list], [])

def _add_oss_fuzz_ci_if_needed(env):
  """Adds value of |OSS_FUZZ_CI| environment variable to |env| if it is set."""
  oss_fuzz_ci = os.getenv('OSS_FUZZ_CI')
  if oss_fuzz_ci:
    env.append('OSS_FUZZ_CI=' + oss_fuzz_ci)
       
def get_fuzzing_parameters_for_building(  # pylint: disable=too-many-arguments,too-many-locals,too-many-branches
    project,
    engine,
    sanitizer,
    architecture,
    env_to_add):
  env = [
      'FUZZING_ENGINE=' + engine,
      'SANITIZER=' + sanitizer,
      'ARCHITECTURE=' + architecture,
      'PROJECT_NAME=' + project.name,
      'HELPER=True',
  ]

  _add_oss_fuzz_ci_if_needed(env)

  if project.language:
    env.append('FUZZING_LANGUAGE=' + project.language)

  if env_to_add:
    env += env_to_add

  command = _env_to_docker_args(env)
  return command

  


def print_and_capture_output(process):
    output = []
    for line in iter(process.stdout.readline, ''):
        print(line, end='')
        output.append(line)
    return ''.join(output)
  
def docker_run(run_args, print_output=True, architecture='x86_64'):
  """Calls `docker run`."""
  platform = 'linux/arm64' if architecture == 'aarch64' else 'linux/amd64'
  command = [
      'docker', 'run', '--rm', '--privileged', '--shm-size=2g', '--platform',
      platform
  ]
  # Support environments with a TTY.
  if sys.stdin.isatty():
    command.append('-i')

  command.extend(run_args)

  logger.info(f'Running: {_get_command_string(command)}.')


  # Execute the command and capture output
  process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
  output = []

  # Read output from stdout in real-time and print it
  while True:
      line = process.stdout.readline()
      if not line:
          break
      print(line, end='')  # Print to console
      output.append(line)  # Save to list for return

  # Wait for the process to finish and get the exit status
  process.wait()
  if process.returncode == 0:
      return ''.join(output), True  # Return all captured output and True for success
  else:
      return ''.join(output), False  # Return all captured output and False for failure
    

def check_image_exists(image_name):
    try:
        # Attempt to get the Docker image
        result = subprocess.run(['docker', 'image', 'inspect', image_name], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                text=True)

        if result.returncode == 0:
            print(f"Image {image_name} exists.")
            return True
        else:
            print(f"Image {image_name} does not exist.")
            return False
    except Exception as e:
        print(f"Failed to check image due to error: {e}")
        return False


def create_image(project_name):
    try:
        # Attempt to get the Docker image
        print(f"!!!!!!!!!! {os.getcwd()}")
        result = subprocess.run(['python', 'infra/helper.py', 'build_image', project_name], 
                                 capture_output=False, text=True, check=True)

        if result.returncode == 0:
            print(f"Image {project_name} created. {result.output}")
            return True
        else:
            print(f"Image {project_name} failed to create. {result.output}")
            return False
    except Exception as e:
        print(f"Failed to create the image due to error: {e}")
        return False