#!/bin/sh

PROJECT=$1
if [ -z "$PROJECT" ]; then
    echo "Please provide a project name"
    exit 1
fi

set -x

SHARED_LLM_DIR=$(realpath ./docker_shared)
SAVED_DIR=$(realpath ./fuzzing_llm_engine/external_database/$PROJECT/codebase)

cd fuzzing_llm_engine/repo
echo $PWD

python3 repo.py \
    --project_name $PROJECT \
    --shared_llm_dir $SHARED_LLM_DIR \
    --saved_dir $SAVED_DIR \
    --src_api \
    --call_graph \
    --language cpp