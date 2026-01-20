#!/bin/sh

PROJECT=$1
if [ -z "$PROJECT" ]; then
    echo "Please provide a project name"
    exit 1
fi

set -x
FILE_PATH=$(realpath ./fuzzing_llm_engine/external_database/$PROJECT/config.yaml)

cd fuzzing_llm_engine
echo $PWD

python3 fuzzing.py \
    --yaml $FILE_PATH \
    --gen_driver \
    --summary_api \
    --check_compilation \
    --gen_input \
    --skip_gen_driver \
    --skip_summary_api \
    --skip_check_compilation \
    --skip_gen_input