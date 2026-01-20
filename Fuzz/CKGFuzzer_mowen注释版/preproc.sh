#!/bin/sh

PROJECT=$1
if [ -z "$PROJECT" ]; then
    echo "Please provide a project name"
    exit 1
fi

set -x
FILE_PATH=$(realpath ./fuzzing_llm_engine/external_database/$PROJECT)

cd fuzzing_llm_engine/repo
echo $PWD

python3 preproc.py \
    --project_name $PROJECT \
    --src_api_file_path $FILE_PATH