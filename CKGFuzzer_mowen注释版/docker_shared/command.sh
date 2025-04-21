# After use docker to create the db, we need to switch to the host machine to run the query. We need change the owner of the db folder.
```
sudo visudo
$USER ALL=(ALL) NOPASSWD: /path/to/your_script.py
source ~/.bashrc
```

# https://github.com/github/codeql/discussions/10109

# download codeql 
wget https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.17.0/codeql-bundle-linux64.tar.gz
# uncompressed
tar -xzvf codeql-bundle-linux64.tar.gz

# create database
## codeql database create  <database> --language=cpp --command=<./bash_script>  --source-root=<dir>
`codeql database create c-ares-cpp --language=cpp --command="./build_codeql.sh"  --source-root="c-ares"`

# Run in docker
# need prepare qlpack.yml
```
name: cpp-queries
version: 0.0.0
libraryPathDependencies: codeql/cpp-all
```

docker run --rm --privileged --shm-size=2g --platform linux/amd64 -i -v /home/mawei/Desktop/work1/wei/fuzzing_llm/fuzzing_os/oss-fuzz-modified/docker_shared:/src/fuzzing_os -t gcr.io/oss-fuzz/c-ares /bin/bash  -c /src/fuzzing_os/codeql/codeql database create /src/fuzzing_os/codeqldb/c-ares --language=cpp --command="/src/fuzzing_os/build_c_ares.sh"  --source-root=c-ares
```
docker run --rm -t -i -v $(pwd):/src/fuzzing_os  gcr.io/oss-fuzz/c-ares /bin/bash
export PATH=/src/fuzzing_os/codeql:$PATH
codeql query run /src/fuzzing_os/find_API.ql -d /src/fuzzing_os/c-ares-cpp --output=/src/fuzzing_os/find_api.bqrs
codeql bqrs decode --format=csv ./find_api.bqrs  --output=find_api.csv
codeql database analyze /src/c-ares/c-ares codeql/cpp-queries:codeql-suites/cpp-security-extended.qls --format=sarifv2.1.0 --output=cpp-results.sarif --download
```

`codeql database analyze docker_shared/codeqldb/c-ares codeql/cpp-queries:codeql-suites/cpp-code-scanning.qls --format=sarifv2.1.0 --output=cpp-results.sarif --download`

```
The default query suite of the standard CodeQL query packs are codeql-suites/<lang>-code-scanning.qls. Several other useful query suites can also be found in the codeql-suites directory of each pack. For example, the codeql/cpp-queries pack contains the following query suites:

cpp-code-scanning.qls - Standard Code Scanning queries for C++. The default query suite for this pack.

cpp-security-extended.qls - Queries from the default cpp-code-scanning.qls suite for C++, plus lower severity and precision queries.

cpp-security-and-quality.qls - Queries from cpp-security-extended.qls, plus maintainability and reliability queries.
```

# Extract API
```find_API.ql
import cpp
import semmle.code.cpp.Print // Import the required module for getIdentityString
/**
 * @name Extract function start and end line
 * @description Extracts the start and end line of the function body given the function name.
 * @kind problem
 * @problem.severity warning
 * @id cpp/extract-function-start-end-line
 */
from Function f
select f, getIdentityString(f), f.getADeclarationEntry().getBlock().getLocation()
```

# Exctract Caller and Callee
```/**
 * @kind graph
 */

import cpp
import semmle.code.cpp.pointsto.CallGraph

from Function caller, FunctionCall callee, Function root
where
  root.hasName("ares__expand_name_validated")
  and allCalls(caller, callee.getTarget())
  and allCalls*(root, caller)
  and callee.getLocation().getFile() = root.getFile()
select caller, callee.getTarget()
```

# TODO
- change bazel tool, https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/bazel_build_fuzz_tests
- according to the bazel doc of CodeQL, https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/preparing-your-code-for-codeql-analysis#specifying-build-commands
```
# Navigate to the Bazel workspace.

# Before building, remove cached objects
# and stop all running Bazel server processes.
bazel clean --expunge

# Build using the following Bazel flags, to help CodeQL detect the build:
# `--spawn_strategy=local`: build locally, instead of using a distributed build
# `--nouse_action_cache`: turn off build caching, which might prevent recompilation of source code
# `--noremote_accept_cached`, `--noremote_upload_local_results`: avoid using a remote cache
codeql database create new-database --language=<language> \
--command='bazel build --spawn_strategy=local --nouse_action_cache --noremote_accept_cached --noremote_upload_local_results //path/to/package:target'

# After building, stop all running Bazel server processes.
# This ensures future build commands start in a clean Bazel server process
# without CodeQL attached.
bazel shutdown
```

