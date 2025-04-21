#!/usr/bin/env python
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""Helper script for OSS-Fuzz users. Can do common tasks like building
projects/fuzzers, running them etc."""

from __future__ import print_function
from multiprocessing.dummy import Pool as ThreadPool
import argparse
import datetime
import errno
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

import os
print(os.getcwd())
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import constants

# 上两级目录 fuzzing_llm_engine
OSS_FUZZ_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BUILD_DIR = os.path.join(OSS_FUZZ_DIR, 'build')

BASE_RUNNER_IMAGE = 'gcr.io/oss-fuzz-base/base-runner'

BASE_IMAGES = {
    'generic': [
        'gcr.io/oss-fuzz-base/base-image',
        'gcr.io/oss-fuzz-base/base-clang',
        'gcr.io/oss-fuzz-base/base-builder',
        BASE_RUNNER_IMAGE,
        'gcr.io/oss-fuzz-base/base-runner-debug',
    ],
    'go': ['gcr.io/oss-fuzz-base/base-builder-go'],
    'javascript': ['gcr.io/oss-fuzz-base/base-builder-javascript'],
    'jvm': ['gcr.io/oss-fuzz-base/base-builder-jvm'],
    'python': ['gcr.io/oss-fuzz-base/base-builder-python'],
    'rust': ['gcr.io/oss-fuzz-base/base-builder-rust'],
    'swift': ['gcr.io/oss-fuzz-base/base-builder-swift'],
}

VALID_PROJECT_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')
MAX_PROJECT_NAME_LENGTH = 26

CORPUS_URL_FORMAT = (
    'gs://{project_name}-corpus.clusterfuzz-external.appspot.com/libFuzzer/'
    '{fuzz_target}/')
CORPUS_BACKUP_URL_FORMAT = (
    'gs://{project_name}-backup.clusterfuzz-external.appspot.com/corpus/'
    'libFuzzer/{fuzz_target}/')

HTTPS_CORPUS_BACKUP_URL_FORMAT = (
    'https://storage.googleapis.com/{project_name}-backup.clusterfuzz-external'
    '.appspot.com/corpus/libFuzzer/{fuzz_target}/public.zip')

LANGUAGE_REGEX = re.compile(r'[^\s]+')
PROJECT_LANGUAGE_REGEX = re.compile(r'\s*language\s*:\s*([^\s]+)')

WORKDIR_REGEX = re.compile(r'\s*WORKDIR\s*([^\s]+)')
# Regex to match special chars in project name.
SPECIAL_CHARS_REGEX = re.compile('[^a-zA-Z0-9_-]')

LANGUAGE_TO_BASE_BUILDER_IMAGE = {
    'c': 'base-builder',
    'c++': 'base-builder',
    'go': 'base-builder-go',
    'javascript': 'base-builder-javascript',
    'jvm': 'base-builder-jvm',
    'python': 'base-builder-python',
    'rust': 'base-builder-rust',
    'swift': 'base-builder-swift'
}
ARM_BUILDER_NAME = 'oss-fuzz-buildx-builder'

CLUSTERFUZZLITE_ENGINE = 'libfuzzer'
CLUSTERFUZZLITE_ARCHITECTURE = 'x86_64'
CLUSTERFUZZLITE_FILESTORE_DIR = 'filestore'
CLUSTERFUZZLITE_DOCKER_IMAGE = 'gcr.io/oss-fuzz-base/cifuzz-run-fuzzers'
LLM_WORK_DIR="/generated_fuzzer"
logger = logging.getLogger(__name__)

if sys.version_info[0] >= 3:
  raw_input = input  # pylint: disable=invalid-name

# pylint: disable=too-many-lines


def remove_unwanted_files(directory):
    """Remove files except those starting with crash, oom, leak, timeout, or undefined."""
    '''
    删除指定目录下的文件
    
    遍历目录中的所有文件，删除不符合以下条件的文件：
      文件名以 'crash', 'oom', 'leak', 'timeout', 'undefined', "input_file", "output_file" 开头
      文件名包含 "fuzz_driver" 子字符串。

    参数：
    directory : 要从中删除文件的目录路径。

    返回：被删除的文件数量。

    '''
    removed_count = 0
    for filename in os.listdir(directory):
        if not (filename.startswith(('crash', 'oom', 'leak', 'timeout', 'undefined', "input_file", "output_file")) or "fuzz_driver" in filename):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path):
                try:
                    os.remove(file_path)
                    removed_count += 1
                except OSError as e:
                    logger.error(f"Error removing file {file_path}: {e}")
    return removed_count


class Project:
  """Class representing a project that is in OSS-Fuzz or an external project
  (ClusterFuzzLite user)."""

  def __init__(
      self,
      project_name_or_path,
      is_external=False,
      build_integration_path=constants.DEFAULT_EXTERNAL_BUILD_INTEGRATION_PATH):
    self.is_external = is_external
    if self.is_external:
      self.path = os.path.abspath(project_name_or_path)
      self.name = os.path.basename(self.path)
      self.build_integration_path = os.path.join(self.path,
                                                 build_integration_path)
    else:
      self.name = project_name_or_path
      self.path = os.path.join(OSS_FUZZ_DIR, 'projects', self.name)
      self.build_integration_path = self.path

  @property
  def dockerfile_path(self):
    """Returns path to the project Dockerfile."""
    return os.path.join(self.build_integration_path, 'Dockerfile')

  @property
  def language(self):
    """Returns project language."""
    project_yaml_path = os.path.join(self.build_integration_path,
                                     'project.yaml')
    if not os.path.exists(project_yaml_path):
      logger.warning('No project.yaml. Assuming c++.')
      return constants.DEFAULT_LANGUAGE

    with open(project_yaml_path) as file_handle:
      content = file_handle.read()
      for line in content.splitlines():
        match = PROJECT_LANGUAGE_REGEX.match(line)
        if match:
          return match.group(1)

    logger.warning('Language not specified in project.yaml. Assuming c++.')
    return constants.DEFAULT_LANGUAGE

  @property
  def out(self):
    """Returns the out dir for the project. Creates it if needed."""
    return _get_out_dir(self.name)

  @property
  def work(self):
    """Returns the out dir for the project. Creates it if needed."""
    return _get_project_build_subdir(self.name, 'work')

  @property
  def corpus(self):
    """Returns the out dir for the project. Creates it if needed."""
    return _get_project_build_subdir(self.name, 'corpus')

def start_docker_daemon(args):
  """Builds fuzzers."""
  """ 构建用于模糊测试的 fuzzer 镜像"""
  if args.engine == 'centipede' and args.sanitizer != 'none':
    # Centipede 需要两个不同的二进制文件：
    # 1. 一个未加 sanitization 的原始 binary（供 Centipede 主程序使用）
    # 2. 一个加了 sanitizer 的 binary（放到子目录中，供调试或其他用途）
    # Centipede always requires separate binaries for sanitizers:
    # An unsanitized binary, which Centipede requires for fuzzing.
    # A sanitized binary, placed in the child directory.
    sanitized_binary_directories = (
        ('none', ''),
        (args.sanitizer, f'__centipede_{args.sanitizer}'),
    )
  else:
    # Generally, a fuzzer only needs one sanitized binary in the default dir.
    sanitized_binary_directories = ((args.sanitizer, ''),)
  # print(args.mount_path)
  
  # 调用内部构建实现函数 `start_docker_check_compilation_impl` 来实际构建 binary。
  # 对所有构建目标（每种 sanitizer + 子目录），都进行构建，如果全部成功，返回 True。

  return all(
      start_docker_check_compilation_impl(args.project,
                        #  args.clean,
                         args.engine,
                         sanitizer,
                         args.architecture,
                         args.e,
                         args.source_path,
                         args.fuzzing_llm_dir,
                         mount_path=args.mount_path,
                         child_dir=child_dir)
      for sanitizer, child_dir in sanitized_binary_directories)

# 启动 Docker 
def docker_start(run_args, print_output=True, architecture='x86_64'):
  """Calls `docker run`."""
  """
  参数:
    run_args: 传递给 `docker run` 的其他参数（例如镜像名、挂载路径等）。
    print_output: 是否输出运行过程的 stdout/stderr 日志。
    architecture: 选择容器运行平台
  """
  # 默认使用 amd64 , 如果平台架构 == aarch64 使用 arm64
  platform = 'linux/arm64' if architecture == 'aarch64' else 'linux/amd64'
  command = [
      'docker', 'run', '--privileged', '--shm-size=2g', '--platform',
      platform
  ]
  # Support environments with a TTY.
  # if sys.stdin.isatty():
  #   command.append('-i')

  command.extend(run_args)

  logger.info(f'Running: \n {_get_command_string(command)}')
  stdout = None
  if not print_output:
    stdout = open(os.devnull, 'w')

  try:
    subprocess.check_call(command, stdout=stdout, stderr=subprocess.STDOUT)
  except subprocess.CalledProcessError:
    return False

  return True

def extract_code(s):
    pattern = r'```(?:c|cpp|c\+\+)\s(.*?)```'
    match = re.search(pattern, s, re.DOTALL)  
    if match:
        return match.group(1)
    else:
        return "No code found"


def docker_exec_command(run_args, project_name, print_output=True):
  """Calls `docker run`."""
  command = [
      'docker', 'exec', '-u', 'root','-it', project_name+"_check" ]
  command.extend(run_args)
  #logger.info(' '.join(command))
  logger.debug(f"mowen ->  {' '.join(command)}")
  try:
    process = subprocess.check_output(command, stderr=subprocess.STDOUT)
    process_str = process.decode('utf-8', errors='replace')
    return process_str
  except subprocess.CalledProcessError as e:
    if print_output:
      return e.output.decode('utf-8', errors='replace')

def extract_errors(log):
    errors = []
    error_pattern = re.compile(r"^.*error:.*$", re.MULTILINE)
    note_warning_pattern = re.compile(r"^.*(note|warning):.*$", re.MULTILINE)
    current_error = []

    lines = log.split('\n')
    
    for line in lines:
        if error_pattern.match(line):
            if current_error:
                errors.append("\n".join(current_error))
            current_error = [line]
        elif note_warning_pattern.match(line):
            continue
        elif current_error:
            current_error.append(line)
    
    if current_error:
        errors.append("\n".join(current_error))
    
    return "\n\n".join(errors)

def docker_pull(image):
  """Call `docker pull`."""
  command = ['docker', 'pull', image]
  logger.info(f'Running: {_get_command_string(command)}')

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    logger.error('Docker pull failed.')
    return False

  return True



def build_image(args):
  """Builds docker image."""
  if args.pull and args.no_pull:
    logger.error('Incompatible arguments --pull and --no-pull.')
    return False

  if args.pull:
    pull = True
  elif args.no_pull:
    pull = False
  else:
    y_or_n = raw_input('Pull latest base images (compiler/runtime)? (y/N): ')
    pull = y_or_n.lower() == 'y'

  if pull:
    logger.info('Pulling latest base images...')
  else:
    logger.info('Using cached base images...')

  # If build_image is called explicitly, don't use cache.
  if build_image_impl(args.project,
                      cache=args.cache,
                      pull=pull,
                      architecture=args.architecture):
    return True

  return False


def pull_images(language=None):
  """Pulls base images used to build projects in language lang (or all if lang
  is None)."""
  for base_image_lang, base_images in BASE_IMAGES.items():
    if (language is None or base_image_lang == 'generic' or
        base_image_lang == language):
      for base_image in base_images:
        if not docker_pull(base_image):
          return False

  return True


from loguru import logger

def check_compilation(args):
    fuzz_driver_file = args.fuzz_driver_file #  fuzz driver 文件路径
    project_name = args.project.name
    fuzz_driver_file = fuzz_driver_file.rsplit('.', 1)[0] # 去掉 fuzz driver 文件名的扩展名 : example_fuzzer.cpp → example_fuzzer
    command = ['bash', f'/{LLM_WORK_DIR}/fuzz_driver/{project_name}/scripts/check_compilation.sh', project_name, fuzz_driver_file]
    logger.debug(f"mowen_check_compilation:\n {' '.join(command)}")
    result = docker_exec_command(command, project_name)
    if len(result) > 5000:
        result = extract_errors(result)
    return result


def start_docker_check_compilation_impl( # pylint: disable=too-many-arguments,too-many-locals,too-many-branches
    project,                             # 项目信息（包含路径、名称等）
    engine,                              # 模糊测试引擎（如 libfuzzer、centipede）
    sanitizer,                           # 使用的 sanitizer 类型（如 address、undefined）
    architecture,                        # CPU 架构（x86_64、aarch64 等）
    env_to_add,                          # 额外的环境变量
    source_path,                         # 源码路径（用于挂载进容器）
    generation_fuzzing_driver_folder,    # 存放生成型 fuzz 驱动的目录
    mount_path=None,                     # 挂载点路径（容器中的路径）
    child_dir='',                        # 构建输出的子目录
    build_project_image=True             # 是否构建项目镜像
  ):

  """Builds fuzzers."""
  # 构建 Docker 镜像
  if build_project_image and not build_image_impl(project,
                                                  architecture=architecture):
    return False
  # 确保 sanitizer 是字符串
  if isinstance(sanitizer, list):

        sanitizer_str = ','.join(sanitizer)
  else:
  
        sanitizer_str = sanitizer

  project_out = os.path.join(project.out, child_dir)
  env = [
      'FUZZING_ENGINE=' + engine,
      'SANITIZER=' + sanitizer_str,
      'ARCHITECTURE=' + architecture,
      'PROJECT_NAME=' + project.name,
      'HELPER=True',
  ]
  # 如果当前环境是 CI，会加上 OSS_FUZZ_CI 标志
  _add_oss_fuzz_ci_if_needed(env) 

  if project.language:
    env.append('FUZZING_LANGUAGE=' + project.language)

  if env_to_add:
    env += env_to_add
  # 设置环境遍历 需要前置 -e 
  # 形如 -> ['-e', 'FUZZING_ENGINE=libfuzzer', '-e', 'SANITIZER=address', ...]
  command = _env_to_docker_args(env)
  if source_path:
    # 从 Dockerfile 中获取工作目录
    workdir = _workdir_from_dockerfile(project)
    # 设置 挂载路径 -> ['-v', '{source_path}:{mount_path}']
    if mount_path:
      command += [
          '-v',
          '%s:%s' % (_get_absolute_path(source_path), mount_path),
      ]
    else:
      # OSS-Fuzz 的 /src 通常是由远程下载构建
      if workdir == '/src':
        logger.error('Cannot use local checkout with "WORKDIR: /src".')
        return False

      command += [
          '-v',
          '%s:%s' % (_get_absolute_path(source_path), workdir),
      ]

  # Check if the gcr.io/oss-fuzz/{project.name} image exists

  # 如果本地存在构建好的 gcr.io/oss-fuzz/{project.name} 镜像，就用它
  # 否则使用本地的 {project.name}_base_image。

  # 查看名为 'gcr.io/oss-fuzz/{project.name}' 的 Docker 镜像的详细元信息
  if subprocess.run(['docker', 'image', 'inspect', f'gcr.io/oss-fuzz/{project.name}'], 
                    capture_output=True).returncode == 0:
    image_name = f'gcr.io/oss-fuzz/{project.name}'
  else:
    # If not, use the {project.name}_base_image
    image_name = f'{project.name}_base_image'

  command += [
     '--name', project.name+"_check", '-v', f'{project_out}:/out', '-v', f'{project.work}:/work', '-v', f'{generation_fuzzing_driver_folder}:{LLM_WORK_DIR}',
    '-dit', image_name, '/bin/bash'
  ]

  # if sys.stdin.isatty():
  #   command.insert(-1, '-d')
  # 启动 Docker 
  result = docker_start(command, architecture=architecture)
  # with open("/home/mawei/Desktop/work1/wei/fuzzing_llm/fuzzing_os/oss-fuzz-modified/build_fuzzers.txt", "a") as f:
  #     f.write(print_docker_run(command,
  #              architecture=architecture) +"\n")

  if not result:
    logger.error('Building fuzzers failed.')
    return False
  # 进入 Docker , 执行 compile 命令 ,编译项目 -> /src/<project>/build.sh
  compile_command =["compile"]
  result=docker_exec_command(compile_command,project.name)
  logger.info(result)

  return True



def coverage(args):
  """Generates code coverage using clang source based code coverage."""
  if args.corpus_dir and not args.fuzz_target:
    logger.error(
        '--corpus-dir requires specifying a particular fuzz target using '
        '--fuzz-target')
    return False

  if not check_project_exists(args.project):
    return False

  if args.project.language not in constants.LANGUAGES_WITH_COVERAGE_SUPPORT:
    logger.error(
        'Project is written in %s, coverage for it is not supported yet.',
        args.project.language)
    return False

  # if (not args.no_corpus_download and not args.corpus_dir and
  #     not args.project.is_external):
  #   if not download_corpora(args):
  #     return False

  env = [
      'FUZZING_ENGINE=libfuzzer',
      'HELPER=True',
      'FUZZING_LANGUAGE=%s' % args.project.language,
      'PROJECT=%s' % args.project.name,
      'SANITIZER=coverage',
      'COVERAGE_EXTRA_ARGS=%s' % ' '.join(args.extra_args),
      'ARCHITECTURE=' + args.architecture,
  ]

  if not args.no_serve:
    env.append(f'HTTP_PORT={args.port}')

  run_args = _env_to_docker_args(env)
  # 指定 Docker port
  if args.port and not args.no_serve:
    run_args.extend([
        '-p',
        '%s:%s' % (args.port, args.port),
    ])
  # 映射 种子目录
  if args.corpus_dir:
    if not os.path.exists(args.corpus_dir):
      logger.error('The path provided in --corpus-dir argument does not '
                   'exist.')
      return False
    corpus_dir = os.path.realpath(args.corpus_dir)
    run_args.extend(['-v', '%s:/corpus/%s' % (corpus_dir, args.fuzz_target)])
  else:
    run_args.extend(['-v', '%s:/corpus' % args.project.corpus])
  # 映射 fuzz driver 目录
  run_args.extend([ 
    "-v", 
    f"{args.fuzzing_llm_dir}:/generated_fuzzer"
  ])
  # 映射 输出目录，-t 分配伪终端
  run_args.extend([
      '-v',
      '%s:/out' % args.project.out,
      # "-v",
      # f"{args.fuzzing_llm_dir}source_code/{args.project.name}:/out/src/{args.project.name}",
      # "-v", 
      # f"/home/mawei/Desktop/work1/wei/fuzzing_llm/fuzzing_os/oss-fuzz-modified/docker_shared/:/fuzz_driver"
      '-t',
      BASE_RUNNER_IMAGE,
  ])
  
  coverage_cmds = [ ]
  coverage_cmds.append('coverage')
  if args.fuzz_target:
    coverage_cmds.append(args.fuzz_target)

  coverage_cmds = " ".join( coverage_cmds )
  # command += ["/bin/bash", "-c", "bash /fuzz_driver/entrancy.sh && compile"] 
  # command += [ "-v", f"/home/mawei/Desktop/work1/wei/fuzzing_llm/fuzzing_os/oss-fuzz-modified/docker_shared/:/fuzz_driver" ]
  run_args.extend(
    # [
    #   "/bin/bash",
    #   "-c",
    #   f"bash /generated_fuzzer/fuzz_driver/{args.project.name}/scripts/entrancy.sh  {args.fuzz_driver_file} {args.project.name} && {coverage_cmds}"
    # ]
     [
      "/bin/bash",
      "-c",
      f"{coverage_cmds}"
    ]
  )
  logger.info(f"Coverage docker command: {run_args}")
  result = docker_run(run_args, architecture=args.architecture)
  if result:
    logger.info('Successfully generated clang code coverage report.')
  else:
    logger.error('Failed to generate clang code coverage report.')

  return result


def main():  # pylint: disable=too-many-branches,too-many-return-statements
  """Gets subcommand from program arguments and does it. Returns 0 on success 1
  on error."""
  logging.basicConfig(level=logging.INFO)
  parser = get_parser()
  args = parse_args(parser)

  # Need to do this before chdir.
  # TODO(https://github.com/google/oss-fuzz/issues/6758): Get rid of chdir.
  if hasattr(args, 'testcase_path'):
    args.testcase_path = _get_absolute_path(args.testcase_path)
  # Note: this has to happen after parse_args above as parse_args needs to know
  # the original CWD for external projects.
  # 更改当前工作目录为 OSS-Fuzz 的主目录
  os.chdir(OSS_FUZZ_DIR)
  if not os.path.exists(BUILD_DIR):
    os.mkdir(BUILD_DIR)

  # We have different default values for `sanitizer` depending on the `engine`.
  # Some commands do not have `sanitizer` argument, so `hasattr` is necessary.
  if hasattr(args, 'sanitizer') and not args.sanitizer:
    if args.project.language == 'javascript':
      args.sanitizer = 'none'
    else:
      args.sanitizer = constants.DEFAULT_SANITIZER
  # 编译检查
  if args.command == 'check_compilation':
    result = check_compilation(args)
  # 启动为编译检查准备的 docker
  elif args.command == 'start_docker_check_compilation':
    result = start_docker_daemon(args)
  else:
    # Print help string if no arguments provided.
    parser.print_help()
    result = False
  return bool_to_retcode(result)


def bool_to_retcode(boolean):
  """Returns 0 if |boolean| is Truthy, 0 is the standard return code for a
  successful process execution. Returns 1 otherwise, indicating the process
  failed."""
  return 0 if boolean else 1


def parse_args(parser, args=None):
  """Parses |args| using |parser| and returns parsed args. Also changes
  |args.build_integration_path| to have correct default behavior."""
  # Use default argument None for args so that in production, argparse does its
  # normal behavior, but unittesting is easier.
  parsed_args = parser.parse_args(args)
  project = getattr(parsed_args, 'project', None)
  if not project:
    return parsed_args

  # Use hacky method for extracting attributes so that ShellTest works.
  # TODO(metzman): Fix this.
  is_external = getattr(parsed_args, 'external', False)
  parsed_args.project = Project(parsed_args.project, is_external)
  return parsed_args


def _add_external_project_args(parser):
  parser.add_argument(
      '--external',
      help='Is project external?',
      default=False,
      action='store_true',
  )


def get_parser():  # pylint: disable=too-many-statements,too-many-locals
  """Returns an argparse parser."""
  parser = argparse.ArgumentParser('helper.py', description='oss-fuzz helpers')
  subparsers = parser.add_subparsers(dest='command')

  generate_parser = subparsers.add_parser(
      'generate', help='Generate files for new project.')
  generate_parser.add_argument('project')
  # generate_parser.add_argument('--fuzzing_llm_dir', 
  #                              type=str,
  #                              default=None,
  #                              required=True,
  #                              help="Fuzzing LLM data and script shared folder, entrancy.sh"
  #                              )
  generate_parser.add_argument('--language',
                               default=constants.DEFAULT_LANGUAGE,
                               choices=LANGUAGE_TO_BASE_BUILDER_IMAGE.keys(),
                               help='Project language.')
  
  _add_external_project_args(generate_parser)

  build_image_parser = subparsers.add_parser('build_image',
                                             help='Build an image.')
  build_image_parser.add_argument('project')
  build_image_parser.add_argument('--pull',
                                  action='store_true',
                                  help='Pull latest base image.')
  _add_architecture_args(build_image_parser)
  build_image_parser.add_argument('--cache',
                                  action='store_true',
                                  default=False,
                                  help='Use docker cache when building image.')
  build_image_parser.add_argument('--no-pull',
                                  action='store_true',
                                  help='Do not pull latest base image.')
  _add_external_project_args(build_image_parser)
  
  start_docker_check_compilation_parser = subparsers.add_parser(
      'start_docker_check_compilation', help='start fuzzer docker for a project.')
  _add_architecture_args(start_docker_check_compilation_parser)
  _add_engine_args(start_docker_check_compilation_parser)
  _add_sanitizer_args(start_docker_check_compilation_parser)
  _add_environment_args(start_docker_check_compilation_parser)
  _add_external_project_args(start_docker_check_compilation_parser)
  start_docker_check_compilation_parser.add_argument('project')
  start_docker_check_compilation_parser.add_argument('source_path',
                                    help='path of local source',
                                    nargs='?')
  start_docker_check_compilation_parser.add_argument('--mount_path',
                                    dest='mount_path',
                                    help='path to mount local source in '
                                    '(defaults to WORKDIR)')
  start_docker_check_compilation_parser.add_argument('--clean',
                                    dest='clean',
                                    action='store_true',
                                    help='clean existing artifacts.')
  start_docker_check_compilation_parser.add_argument('--no-clean',
                                    dest='clean',
                                    action='store_false',
                                    help='do not clean existing artifacts '
                                    '(default).')
  start_docker_check_compilation_parser.add_argument('--fuzzing_llm_dir', 
                               type=str,
                               default=None,
                               required=True,
                               help="Fuzzing LLM data and script shared folder, entrancy.sh"
                               )
  start_docker_check_compilation_parser.set_defaults(clean=False)
    

  check_compilation_parser = subparsers.add_parser(
      'check_compilation', help='Check the compilation of fuzz driver.')  
  check_compilation_parser.add_argument('project')
  check_compilation_parser.add_argument('--fuzz_driver_file', required=True, help='Path to the fuzz driver')
  
  # build_fuzzer_file
  build_fuzzer_file_parser = subparsers.add_parser(
      'build_fuzzer_file', help='Build the fuzz driver.')  
  build_fuzzer_file_parser.add_argument('project')
  build_fuzzer_file_parser.add_argument('--fuzz_driver_file', required=True, help='Path to the fuzz driver')
  
  build_fuzzers_parser = subparsers.add_parser(
      'build_fuzzers', help='Build fuzzers for a project.')
  _add_architecture_args(build_fuzzers_parser)
  _add_engine_args(build_fuzzers_parser)
  _add_sanitizer_args(build_fuzzers_parser)
  _add_environment_args(build_fuzzers_parser)
  _add_external_project_args(build_fuzzers_parser)
  build_fuzzers_parser.add_argument('project')
  build_fuzzers_parser.add_argument('source_path',
                                    help='path of local source',
                                    nargs='?')
  build_fuzzers_parser.add_argument('--mount_path',
                                    dest='mount_path',
                                    help='path to mount local source in '
                                    '(defaults to WORKDIR)') # fuzz_driver_file
  build_fuzzers_parser.add_argument('--fuzz_driver_file',
                                    dest='fuzz_driver_file',
                                    default=None,
                                    help='build target file name'
                                    '(defaults to None)') # fuzz_driver_file
  build_fuzzers_parser.add_argument('--clean',
                                    dest='clean',
                                    action='store_true',
                                    help='clean existing artifacts.')
  build_fuzzers_parser.add_argument('--no-clean',
                                    dest='clean',
                                    action='store_false',
                                    help='do not clean existing artifacts '
                                    '(default).')
  build_fuzzers_parser.add_argument(
      '--fuzzing_llm_dir', help='fuzzing docker shared dir'
  )
  build_fuzzers_parser.set_defaults(clean=False)

  fuzzbench_build_fuzzers_parser = subparsers.add_parser(
      'fuzzbench_build_fuzzers')
  _add_architecture_args(fuzzbench_build_fuzzers_parser)
  fuzzbench_build_fuzzers_parser.add_argument('--engine')
  _add_sanitizer_args(fuzzbench_build_fuzzers_parser)
  _add_environment_args(fuzzbench_build_fuzzers_parser)
  _add_external_project_args(fuzzbench_build_fuzzers_parser)
  fuzzbench_build_fuzzers_parser.add_argument('project')
  check_build_parser = subparsers.add_parser(
      'check_build', help='Checks that fuzzers execute without errors.')
  _add_architecture_args(check_build_parser)
  _add_engine_args(check_build_parser, choices=constants.ENGINES)
  _add_sanitizer_args(check_build_parser, choices=constants.SANITIZERS)
  _add_environment_args(check_build_parser)
  check_build_parser.add_argument('project',
                                  help='name of the project or path (external)')
  check_build_parser.add_argument('fuzzer_name',
                                  help='name of the fuzzer',
                                  nargs='?')
  _add_external_project_args(check_build_parser)

  run_fuzzer_parser = subparsers.add_parser(
      'run_fuzzer', help='Run a fuzzer in the emulated fuzzing environment.')
  _add_architecture_args(run_fuzzer_parser)
  _add_engine_args(run_fuzzer_parser)
  _add_sanitizer_args(run_fuzzer_parser)
  _add_environment_args(run_fuzzer_parser)
  _add_external_project_args(run_fuzzer_parser)
  run_fuzzer_parser.add_argument(
      '--corpus-dir', help='directory to store corpus for the fuzz target')
  run_fuzzer_parser.add_argument(
      '--timeout', default="60s", help='time setting of timeout command in linux, e.g., 10s means 10 seconds, 2min means 2 minutes')
  run_fuzzer_parser.add_argument(
      '--fuzz_driver_file', help='fuzz driver file name'
  )
  run_fuzzer_parser.add_argument(
      '--fuzzing_llm_dir', help='fuzzing docker shared dir'
  )
  run_fuzzer_parser.add_argument('project',
                                 help='name of the project or path (external)')
  run_fuzzer_parser.add_argument('fuzzer_name', help='name of the fuzzer')
  run_fuzzer_parser.add_argument('fuzzer_args',
                                 help='arguments to pass to the fuzzer',
                                 nargs='*')
  

  fuzzbench_run_fuzzer_parser = subparsers.add_parser('fuzzbench_run_fuzzer')
  _add_architecture_args(fuzzbench_run_fuzzer_parser)
  fuzzbench_run_fuzzer_parser.add_argument('--engine')
  _add_sanitizer_args(fuzzbench_run_fuzzer_parser)
  _add_environment_args(fuzzbench_run_fuzzer_parser)
  _add_external_project_args(fuzzbench_run_fuzzer_parser)
  fuzzbench_run_fuzzer_parser.add_argument(
      '--corpus-dir', help='directory to store corpus for the fuzz target')
  fuzzbench_run_fuzzer_parser.add_argument(
      'project', help='name of the project or path (external)')
  fuzzbench_run_fuzzer_parser.add_argument('fuzzer_name',
                                           help='name of the fuzzer')
  fuzzbench_run_fuzzer_parser.add_argument(
      'fuzzer_args', help='arguments to pass to the fuzzer', nargs='*')

  fuzzbench_measure_parser = subparsers.add_parser('fuzzbench_measure')
  fuzzbench_measure_parser.add_argument(
      'project', help='name of the project or path (external)')
  fuzzbench_measure_parser.add_argument('engine_name',
                                        help='name of the fuzzer')
  fuzzbench_measure_parser.add_argument('fuzz_target_name',
                                        help='name of the fuzzer')

  coverage_parser = subparsers.add_parser(
      'coverage', help='Generate code coverage report for the project.')
  coverage_parser.add_argument('--no-corpus-download',
                               action='store_true',
                               help='do not download corpus backup from '
                               'OSS-Fuzz; use corpus located in '
                               'build/corpus/<project>/<fuzz_target>/')
  coverage_parser.add_argument('--no_serve',
                               action='store_true',
                               help='do not serve a local HTTP server.')
  coverage_parser.add_argument('--port',
                               default='8008',
                               help='specify port for'
                               ' a local HTTP server rendering coverage report')
  coverage_parser.add_argument('--fuzz-target',
                               help='specify name of a fuzz '
                               'target to be run for generating coverage '
                               'report')
  coverage_parser.add_argument('--corpus-dir',
                               help='specify location of corpus'
                               ' to be used (requires --fuzz-target argument)')
  coverage_parser.add_argument('--public',
                               action='store_true',
                               help='if set, will download public '
                               'corpus using wget')
  coverage_parser.add_argument('project',
                               help='name of the project or path (external)')
  coverage_parser.add_argument('--fuzzing_llm_dir', 
                               help='fuzzing docker shared dir'
  )
  coverage_parser.add_argument(
      '--fuzz_driver_file', help='fuzz driver file name'
  )
  coverage_parser.add_argument('extra_args',
                               help='additional arguments to '
                               'pass to llvm-cov utility.',
                               nargs='*')
  _add_external_project_args(coverage_parser)
  _add_architecture_args(coverage_parser)

  introspector_parser = subparsers.add_parser(
      'introspector',
      help='Run a complete end-to-end run of '
      'fuzz introspector. This involves (1) '
      'building the fuzzers with ASAN; (2) '
      'running all fuzzers; (3) building '
      'fuzzers with coverge; (4) extracting '
      'coverage; (5) building fuzzers using '
      'introspector')
  introspector_parser.add_argument('project', help='name of the project')
  introspector_parser.add_argument('--seconds',
                                   help='number of seconds to run fuzzers',
                                   default=10)
  introspector_parser.add_argument('source_path',
                                   help='path of local source',
                                   nargs='?')
  introspector_parser.add_argument(
      '--public-corpora',
      help='if specified, will use public corpora for code coverage',
      default=False,
      action='store_true')
  introspector_parser.add_argument(
      '--private-corpora',
      help='if specified, will use private corpora',
      default=False,
      action='store_true')

  download_corpora_parser = subparsers.add_parser(
      'download_corpora', help='Download all corpora for a project.')
  download_corpora_parser.add_argument('--fuzz-target',
                                       nargs='+',
                                       help='specify name of a fuzz target')
  download_corpora_parser.add_argument('--public',
                                       action='store_true',
                                       help='if set, will download public '
                                       'corpus using wget')
  download_corpora_parser.add_argument(
      'project', help='name of the project or path (external)')

  reproduce_parser = subparsers.add_parser('reproduce',
                                           help='Reproduce a crash.')
  reproduce_parser.add_argument('--valgrind',
                                action='store_true',
                                help='run with valgrind')
  reproduce_parser.add_argument('project',
                                help='name of the project or path (external)')
  reproduce_parser.add_argument('fuzzer_name', help='name of the fuzzer')
  reproduce_parser.add_argument('testcase_path', help='path of local testcase')
  reproduce_parser.add_argument('fuzzer_args',
                                help='arguments to pass to the fuzzer',
                                nargs='*')
  _add_environment_args(reproduce_parser)
  _add_external_project_args(reproduce_parser)
  _add_architecture_args(reproduce_parser)

  shell_parser = subparsers.add_parser(
      'shell', help='Run /bin/bash within the builder container.')
  shell_parser.add_argument('project',
                            help='name of the project or path (external)')
  shell_parser.add_argument('source_path',
                            help='path of local source',
                            nargs='?')
  _add_architecture_args(shell_parser)
  _add_engine_args(shell_parser)
  _add_sanitizer_args(shell_parser)
  _add_environment_args(shell_parser)
  _add_external_project_args(shell_parser)

  run_clusterfuzzlite_parser = subparsers.add_parser(
      'run_clusterfuzzlite', help='Run ClusterFuzzLite on a project.')
  _add_sanitizer_args(run_clusterfuzzlite_parser)
  _add_environment_args(run_clusterfuzzlite_parser)
  run_clusterfuzzlite_parser.add_argument('project')
  run_clusterfuzzlite_parser.add_argument('--clean',
                                          dest='clean',
                                          action='store_true',
                                          help='clean existing artifacts.')
  run_clusterfuzzlite_parser.add_argument(
      '--no-clean',
      dest='clean',
      action='store_false',
      help='do not clean existing artifacts '
      '(default).')
  run_clusterfuzzlite_parser.add_argument('--branch',
                                          default='master',
                                          required=True)
  _add_external_project_args(run_clusterfuzzlite_parser)
  run_clusterfuzzlite_parser.set_defaults(clean=False)

  subparsers.add_parser('pull_images', help='Pull base images.')
  return parser


def is_base_image(image_name):
  """Checks if the image name is a base image."""
  return os.path.exists(os.path.join('infra', 'base-images', image_name))


def check_project_exists(project):
  """Checks if a project exists."""
  if os.path.exists(project.path):
    return True

  if project.is_external:
    descriptive_project_name = project.path
  else:
    descriptive_project_name = project.name

  logger.error('"%s" does not exist.', descriptive_project_name)
  return False


def _check_fuzzer_exists(project, fuzzer_name, architecture='x86_64'):
  """Checks if a fuzzer exists."""
  platform = 'linux/arm64' if architecture == 'aarch64' else 'linux/amd64'
  command = ['docker', 'run', '--rm', '--platform', platform]
  command.extend(['-v', '%s:/out' % project.out])
  command.append(BASE_RUNNER_IMAGE)

  command.extend(['/bin/bash', '-c', 'test -f /out/%s' % fuzzer_name])

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    logger.error(f'{fuzzer_name} does not seem to exist. Please run build_fuzzers first.')
    return False

  return True



def _get_absolute_path(path):
  '''获得完整的绝对路径'''
  """Returns absolute path with user expansion."""
  # expanduser -> 路径中的 ~（波浪号）展开成当前用户的主目录
  return os.path.abspath(os.path.expanduser(path))


def _get_command_string(command):
  """Returns a shell escaped command string."""
  return ' '.join(shlex.quote(part) for part in command)


def _get_project_build_subdir(project, subdir_name):
  """Creates the |subdir_name| subdirectory of the |project| subdirectory in
  |BUILD_DIR| and returns its path."""
  directory = os.path.join(BUILD_DIR, subdir_name, project)
  os.makedirs(directory, exist_ok=True)

  return directory


def _get_out_dir(project=''):
  """Creates and returns path to /out directory for the given project (if
  specified)."""
  return _get_project_build_subdir(project, 'out')


def _add_architecture_args(parser, choices=None):
  """Adds common architecture args."""
  if choices is None:
    choices = constants.ARCHITECTURES
  parser.add_argument('--architecture',
                      default=constants.DEFAULT_ARCHITECTURE,
                      choices=choices)


def _add_engine_args(parser, choices=None):
  """Adds common engine args."""
  if choices is None:
    choices = constants.ENGINES
  parser.add_argument('--engine',
                      default=constants.DEFAULT_ENGINE,
                      choices=choices)


def _add_sanitizer_args(parser, choices=None):
  """Adds common sanitizer args."""
  if choices is None:
    choices = constants.SANITIZERS
  parser.add_argument('--sanitizer',
                      default=None,
                      choices=choices,
                      help='the default is "address"')


def _add_environment_args(parser):
  """Adds common environment args."""
  parser.add_argument('-e',
                      action='append',
                      help="set environment variable e.g. VAR=value")

# 构建 Docker 镜像
def build_image_impl(project, cache=True, pull=False, architecture='x86_64'):
  """Builds image."""
  image_name = project.name
  # 判断 image_name 是否为 基础镜像
  if is_base_image(image_name):
    image_project = 'oss-fuzz-base'
    docker_build_dir = os.path.join(OSS_FUZZ_DIR, 'infra', 'base-images',
                                    image_name)
    dockerfile_path = os.path.join(docker_build_dir, 'Dockerfile')
  else:
    # 检查 project 路径是否存在
    if not check_project_exists(project):
      return False
    dockerfile_path = project.dockerfile_path
    docker_build_dir = project.path
    image_project = 'oss-fuzz'
  # 拉取不同语言所需要的  docker image
  if pull and not pull_images(project.language):
    return False

  build_args = []
  image_name = 'gcr.io/%s/%s' % (image_project, image_name)
  # 检查 gcr.io/image_project/image_name 容器是否存在
  # Check if the image exists
  if subprocess.call(['docker', 'image', 'inspect', image_name], 
                     stdout=subprocess.DEVNULL, 
                     stderr=subprocess.DEVNULL) != 0:
    # If the image doesn't exist, try the alternative name
    image_name = '%s_base_image' % (image_name)
  
  
  if architecture == 'aarch64':
    build_args += [
        'buildx',
        'build',
        '--platform',
        'linux/arm64',
        '--progress',
        'plain',
        '--load',
    ]
  if not cache:
    build_args.append('--no-cache')

  build_args += ['-t', image_name, '--file', dockerfile_path]
  build_args.append(docker_build_dir)

  if architecture == 'aarch64':
    command = ['docker'] + build_args
    subprocess.check_call(command)
    return True
  # 拉取 Docker 镜像
  return docker_build(build_args)


def _env_to_docker_args(env_list):
  '''docker env 转换'''
  """Turns envirnoment variable list into docker arguments."""
  return sum([['-e', v] for v in env_list], [])

# 从 Dockerfile 的多行文本中获取最后一个 WORKDIR 指令设置的路径。
def workdir_from_lines(lines, default='/src'):
  """Gets the WORKDIR from the given lines."""
  # 从后往前找，以获取最后一个 WORKDIR 指令
  for line in reversed(lines):  # reversed to get last WORKDIR.
    match = re.match(WORKDIR_REGEX, line)
    if match:
      workdir = match.group(1) # 提取出 WORKDIR 的路径
      workdir = workdir.replace('$SRC', '/src')  # 将变量 $SRC 替换成真实路径 '/src'

      if not os.path.isabs(workdir): # 如果路径不是绝对路径
        workdir = os.path.join('/src', workdir) # 拼接成以 /src 为根的路径

      return os.path.normpath(workdir)

  return default


def _workdir_from_dockerfile(project):
  """
  从给定项目的 Dockerfile 中读取 WORKDIR 的路径。
  参数:
    project: 一个包含 Dockerfile 路径的项目对象（必须有 .dockerfile_path 属性）
  返回:
    从 Dockerfile 中解析出的 WORKDIR 路径，默认是 `/src/{project.name}`
  """
  """Parses WORKDIR from the Dockerfile for the given project."""
  with open(project.dockerfile_path) as file_handle:
    lines = file_handle.readlines()

  return workdir_from_lines(lines, default=os.path.join('/src', project.name))


def prepare_aarch64_emulation():
  """Run some necessary commands to use buildx to build AArch64 targets using
  QEMU emulation on an x86_64 host."""
  subprocess.check_call(
      ['docker', 'buildx', 'create', '--name', ARM_BUILDER_NAME])
  subprocess.check_call(['docker', 'buildx', 'use', ARM_BUILDER_NAME])


def docker_run(run_args, print_output=True, architecture='x86_64'):
  '''启动 Docker'''
  """Calls `docker run`."""
  platform = 'linux/arm64' if architecture == 'aarch64' else 'linux/amd64'
  command = [
      'docker', 'run', '--rm', '--privileged', '--shm-size=2g', '--platform',
      platform
  ]
  # Support environments with a TTY.
  # 如果输入是来自终端（tty），则添加 '-i' 参数以使得 stdin 处于交互模式。
  if sys.stdin.isatty():
    command.append('-i')

  command.extend(run_args)
  # logger.info(' '.join(command))

  logger.info(f'Running: \n{_get_command_string(command)}.')
  # stdout = None
  # if not print_output:
  #   stdout = open(os.devnull, 'w')


  try:
      logger.debug(f'Start Fuzzer')
      process = subprocess.check_output(command, stderr=subprocess.STDOUT)
      process_str = process.decode('utf-8', errors='ignore')
      return process_str
  except subprocess.CalledProcessError as e:
      if print_output:
        return e.output.decode('utf-8', errors='ignore')
      
  # try:
  #   subprocess.check_call(command, stdout=stdout, stderr=subprocess.STDOUT)
  # except subprocess.CalledProcessError:
  #   return False

  # return True
      

def build_fuzzer_file(args):
    # 清楚不需要的文件
    remove_unwanted_files(args.project.out)
    logger.info(f"Removed unwanted files from {args.project.out}")
    fuzz_driver_file = args.fuzz_driver_file
    project_name = args.project.name
    command = ["/bin/bash", "-c", f"bash {LLM_WORK_DIR}/fuzz_driver/{project_name}/scripts/entrancy.sh {fuzz_driver_file} {project_name} && compile"]  
    #logger.info(' '.join(command))
    # 执行构建入口sh -> entrancy.sh
    result = docker_exec_command(command, project_name)
    if len(result) > 5000:
      result = extract_errors(result)
    return result
    
     
def build_fuzzers_impl(  args, # pylint: disable=too-many-arguments,too-many-locals,too-many-branches
    project,
    clean,
    engine,
    sanitizer,
    architecture,
    env_to_add,
    source_path,
    mount_path=None,
    child_dir='',
    build_project_image=True):
  """Builds fuzzers."""
  # 构建项目镜像
  if build_project_image and not build_image_impl(project,
                                                  architecture=architecture):
    return False

  project_out = os.path.join(project.out, child_dir)
  # 清理 out 、work 目录 
  if clean:
    logger.info('Cleaning existing build artifacts.')

    # Clean old and possibly conflicting artifacts in project's out directory.
    docker_run([
        '-v', f'{project_out}:/out', '-t', f'gcr.io/oss-fuzz/{project.name}',
        '/bin/bash', '-c', 'rm -rf /out/*'
    ],
               architecture=architecture)

    docker_run([
        '-v',
        '%s:/work' % project.work, '-t',
        'gcr.io/oss-fuzz/%s' % project.name, '/bin/bash', '-c', 'rm -rf /work/*'
    ],
               architecture=architecture)

  else:
    logger.info('Keeping existing build artifacts as-is (if any).')
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
  # 添加传进来的 env
  if env_to_add:
    env += env_to_add
  
  command = _env_to_docker_args(env)
  logger.info(f"source_path -> {source_path}")
  # 设置映射文件夹
  if source_path:
    workdir = _workdir_from_dockerfile(project)
    if mount_path:
      command += [
          '-v',
          '%s:%s' % (_get_absolute_path(source_path), mount_path),
      ]
    else:
      if workdir == '/src':
        logger.error('Cannot use local checkout with "WORKDIR: /src".')
        return False

      command += [
          '-v',
          '%s:%s' % (_get_absolute_path(source_path), workdir),
      ]
  # 查看 gcr.io/oss-fuzz/{project.name} 容器 是否存在，如果存在则拉取 gcr.io/oss-fuzz/{project.name}
  if subprocess.run(['docker', 'image', 'inspect', f'gcr.io/oss-fuzz/{project.name}'], 
                    capture_output=True).returncode == 0:
    image_name = f'gcr.io/oss-fuzz/{project.name}'
  else:
    # 如果不存在则拉取名为  {project.name}_base_image 的基础镜像
    # If not, use the {project.name}_base_image
    image_name = f'{project.name}_base_image'
  
  # if args.fuzzing_llm_dir is None:
  # 默认要挂载的 映射文件夹
  command += [ "-v", f"{args.fuzzing_llm_dir}:/generated_fuzzer" ]
  command += [
      '-v', f'{project_out}:/out', '-v', f'{project.work}:/work',
      image_name
  ]
  # 判断 tty
  if sys.stdin.isatty():
    command.insert(-1, '-t')
  # 编译
  command += ["/bin/bash", "-c", f"bash {LLM_WORK_DIR}/fuzz_driver/{project.name}/scripts/entrancy.sh {args.fuzz_driver_file} {project.name} && compile"]    
  result = docker_run(command, architecture=architecture)
  if not result:
    logger.error('Building fuzzers failed.')
    return False

  return True


def docker_build(build_args):
  """Calls `docker build`."""
  command = ['docker', 'build']
  command.extend(build_args)
  logger.info(f'Running: {_get_command_string(command)} .')

  try:
    subprocess.check_call(command)
  except subprocess.CalledProcessError:
    logger.error('Docker build failed.')
    return False

  return True


def _add_oss_fuzz_ci_if_needed(env):
  '''检查环境变量 'OSS_FUZZ_CI' 是否存在，如果存在，则将其值添加到 env 列表中。'''
  """Adds value of |OSS_FUZZ_CI| environment variable to |env| if it is set."""
  oss_fuzz_ci = os.getenv('OSS_FUZZ_CI')
  if oss_fuzz_ci:
    env.append('OSS_FUZZ_CI=' + oss_fuzz_ci)

def build_fuzzers(args):
  """Builds fuzzers."""
  if args.engine == 'centipede' and args.sanitizer != 'none':
    # Centipede always requires separate binaries for sanitizers:
    # An unsanitized binary, which Centipede requires for fuzzing.
    # A sanitized binary, placed in the child directory.
    sanitized_binary_directories = (
        ('none', ''),
        (args.sanitizer, f'__centipede_{args.sanitizer}'),
    )
  else:
    # Generally, a fuzzer only needs one sanitized binary in the default dir.
    sanitized_binary_directories = ((args.sanitizer, ''),)

  return all(
      build_fuzzers_impl(args, args.project,
                         args.clean,
                         args.engine,
                         sanitizer,
                         args.architecture,
                         args.e,
                         args.source_path,
                         mount_path=args.mount_path,
                         child_dir=child_dir)
      for sanitizer, child_dir in sanitized_binary_directories)


def run_fuzzer(args):
  """Runs a fuzzer in the container."""
  if not check_project_exists(args.project):
    return False

  if not _check_fuzzer_exists(args.project, args.fuzzer_name):
    return False
 

  if isinstance(args.sanitizer, list):
      sanitizer = ','.join(args.sanitizer)
  else:
      sanitizer = args.sanitizer

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + sanitizer,
      'RUN_FUZZER_MODE=interactive',
      'FUZZING_LANGUAGE=c++',
      'HELPER=True',
  ]

  if args.e:
    env += args.e

  if args.corpus_dir:
    if not os.path.exists(args.corpus_dir):
      logger.error('The path provided in --corpus-dir argument does not exist')
      return False
    corpus_dir = os.path.realpath(args.corpus_dir)
    
    env.append(f"CORPUS_DIR=/tmp/{args.fuzzer_name}_corpus")
    
    run_args = _env_to_docker_args(env)
    run_args.extend([
        '-v',
        '{corpus_dir}:/tmp/{fuzzer}_corpus'.format(corpus_dir=corpus_dir,
                                                   fuzzer=args.fuzzer_name)
    ])
  else:
    run_args = _env_to_docker_args(env)
    
  # command += ["/bin/bash", "-c", "bash /fuzz_driver/entrancy.sh && compile"] 
  # command += [ "-v", f"/home/mawei/Desktop/work1/wei/fuzzing_llm/fuzzing_os/oss-fuzz-modified/docker_shared/:/fuzz_driver" ]
  fuzzing_args = " ".join(args.fuzzer_args)
  run_args.extend([
      '-v',
      f"{args.fuzzing_llm_dir}:{LLM_WORK_DIR}",
      '-v',
      '%s:/out' % args.project.out,
      '-t',
      BASE_RUNNER_IMAGE,
      "/bin/bash",
      "-c",
      # f"bash {LLM_WORK_DIR}/fuzz_driver/{args.project.name}/scripts/entrancy.sh {args.fuzz_driver_file} {args.project.name} && 
      # f"run_fuzzer {args.fuzzer_name} {fuzzing_args}"
      # "&&",
      f'timeout {args.timeout} run_fuzzer {args.fuzzer_name} {fuzzing_args}'
  ] #+ args.fuzzer_args)
  )



  return docker_run(run_args, architecture=args.architecture)



def start_coverage_docker(args):
  """
  start docker for coverage.
  """
  if args.corpus_dir and not args.fuzz_target:
    logger.error(
        '--corpus-dir requires specifying a particular fuzz target using '
        '--fuzz-target')
    return False

  if not check_project_exists(args.project):
    return False

  if args.project.language not in constants.LANGUAGES_WITH_COVERAGE_SUPPORT:
    logger.error(
        'Project is written in %s, coverage for it is not supported yet.',
        args.project.language)
    return False

  # if (not args.no_corpus_download and not args.corpus_dir and
  #     not args.project.is_external):
  #   if not download_corpora(args):
  #     return False

  env = [
      'FUZZING_ENGINE=libfuzzer',
      'HELPER=True',
      'FUZZING_LANGUAGE=%s' % args.project.language,
      'PROJECT=%s' % args.project.name,
      'SANITIZER=coverage',
      'COVERAGE_EXTRA_ARGS=%s' % ' '.join(args.extra_args),
      'ARCHITECTURE=' + args.architecture,
  ]

  if not args.no_serve:
    env.append(f'HTTP_PORT={args.port}')

  run_args = _env_to_docker_args(env)
  run_args += ['--name', args.project.name+"_build"]
  if args.port:
    run_args.extend([
        '-p',
        '%s:%s' % (args.port, args.port),
    ])

  if args.corpus_dir:
    if not os.path.exists(args.corpus_dir):
      logger.error('The path provided in --corpus-dir argument does not '
                   'exist.')
      return False
    corpus_dir = os.path.realpath(args.corpus_dir)
    run_args.extend(['-v', '%s:/corpus/%s' % (corpus_dir, args.fuzz_target)])
  else:
    run_args.extend(['-v', '%s:/corpus' % args.project.corpus])
  
  run_args.extend([ 
    "-v", 
    f"{args.fuzzing_llm_dir}:/fuzz_driver" 
  ])
  
  run_args.extend([
      '-v',
      '%s:/out' % args.project.out,
      '-dit',
      BASE_RUNNER_IMAGE,
  ])
  
  run_args.append( "/bin/bash" )

  result = docker_run(run_args, architecture=args.architecture)
  if result:
    logger.info('Successfully generated clang code coverage report.')
  else:
    logger.error('Failed to generate clang code coverage report.')

  return result

def check_build(args):
  """Checks that fuzzers in the container execute without errors."""
  if not check_project_exists(args.project):
    return False

  if (args.fuzzer_name and not _check_fuzzer_exists(
      args.project, args.fuzzer_name, args.architecture)):
    return False

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + args.sanitizer,
      'ARCHITECTURE=' + args.architecture,
      'FUZZING_LANGUAGE=' + args.project.language,
      'HELPER=True',
  ]
  _add_oss_fuzz_ci_if_needed(env)
  if args.e:
    env += args.e

  run_args = _env_to_docker_args(env) + [
      '-v', f'{args.project.out}:/out', '-t', BASE_RUNNER_IMAGE
  ]

  if args.fuzzer_name:
    run_args += ['test_one.py', args.fuzzer_name]
  else:
    run_args.append('test_all.py')

  result = docker_run(run_args, architecture=args.architecture)
  if result:
    logger.info('Check build passed.')
  else:
    logger.error('Check build failed.')

  return result

def shell(args):
  """Runs a shell within a docker image."""
  if not build_image_impl(args.project):
    return False

  env = [
      'FUZZING_ENGINE=' + args.engine,
      'SANITIZER=' + args.sanitizer,
      'ARCHITECTURE=' + args.architecture,
      'HELPER=True',
  ]

  if args.project.name != 'base-runner-debug':
    env.append('FUZZING_LANGUAGE=' + args.project.language)

  if args.e:
    env += args.e

  if is_base_image(args.project.name):
    image_project = 'oss-fuzz-base'
    out_dir = _get_out_dir()
  else:
    image_project = 'oss-fuzz'
    out_dir = args.project.out

  run_args = _env_to_docker_args(env)
  if args.source_path:
    workdir = _workdir_from_dockerfile(args.project)
    run_args.extend([
        '-v',
        '%s:%s' % (_get_absolute_path(args.source_path), workdir),
    ])

  run_args.extend([
      '-v',
      '%s:/out' % out_dir, '-v',
      '%s:/work' % args.project.work, '-t',
      'gcr.io/%s/%s' % (image_project, args.project.name), '/bin/bash'
  ])

  docker_run(run_args, architecture=args.architecture)
  return True


def run(llm_args):  # pylint: disable=too-many-branches,too-many-return-statements
  """Gets subcommand from program arguments and does it. Returns 0 on success 1
  on error."""
  logging.basicConfig(level=logging.INFO)
  parser = get_parser()
  args = parse_args(parser, args=llm_args)

  # Need to do this before chdir.
  # TODO(https://github.com/google/oss-fuzz/issues/6758): Get rid of chdir.
  if hasattr(args, 'testcase_path'):
    args.testcase_path = _get_absolute_path(args.testcase_path)
  # Note: this has to happen after parse_args above as parse_args needs to know
  # the original CWD for external projects.
  os.chdir(OSS_FUZZ_DIR)
  if not os.path.exists(BUILD_DIR):
    os.mkdir(BUILD_DIR)

  # We have different default values for `sanitizer` depending on the `engine`.
  # Some commands do not have `sanitizer` argument, so `hasattr` is necessary.
  if hasattr(args, 'sanitizer') and not args.sanitizer:
    if args.project.language == 'javascript':
      args.sanitizer = 'none'
    else:
      args.sanitizer = constants.DEFAULT_SANITIZER

  if args.command == 'build_image':
    result = build_image(args)
  elif args.command == 'build_fuzzers':
    # 构建覆盖率
    result = build_fuzzers(args)
  elif args.command == 'check_build':
    result = check_build(args)
  elif args.command == 'run_fuzzer':
    # 开始 fuzz
    result = run_fuzzer(args)
  elif args.command == 'coverage':
    result = coverage(args)
  elif args.command == 'shell':
    result = shell(args)
  elif args.command == 'pull_images':
    result = pull_images()
  elif args.command == 'start_coverage_docker':
    result = start_coverage_docker(args)
  elif args.command == "build_fuzzer_file":
    # 构建单个 fuzzer 文件
    result = build_fuzzer_file(args)
  elif args.command == 'check_compilation':
    # 检查编译
    result = check_compilation(args)
  elif args.command == 'start_docker_check_compilation':
    # 启动准备检查编译的 docker
    result = start_docker_daemon(args)
  else:
    # Print help string if no arguments provided.
    parser.print_help()
    result = False
  
  # if isinstance(result, str):
  #    if len(result.strip()) == 0:
  #      return "no error is captured from the terminal output"
  
  return result # bool_to_retcode(result)



if __name__ == '__main__':
  sys.exit(main())
