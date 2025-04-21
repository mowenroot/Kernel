set -x 
dbbase="/home/mowen/CKGFuzzer_mowen/docker_shared/codeqldb/c-ares_0"
outputfile="/home/mowen/CKGFuzzer_mowen/fuzzing_llm_engine/external_database/c-ares/codebase/call_graph/_src_c-ares_src_lib_ares_android.c@jni_get_class_call_graph.bqrs"
codeql query run call_graph_0.ql --database="$dbbase" --output="$outputfile"