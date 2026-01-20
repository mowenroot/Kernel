"""Set of constants."""
# COPY FROM llamaindex /home/mawei/.conda/envs/torch/lib/python3.10/site-packages/llama_index/core/constants.py
DEFAULT_TEMPERATURE = 0.1
DEFAULT_CONTEXT_WINDOW = 3900  # tokens
DEFAULT_NUM_OUTPUTS = 256  # tokens
DEFAULT_NUM_INPUT_FILES = 10  # files

DEFAULT_EMBED_BATCH_SIZE = 10

DEFAULT_CHUNK_SIZE = 1024  # tokens
DEFAULT_CHUNK_OVERLAP = 20  # tokens
DEFAULT_SIMILARITY_TOP_K = 2
DEFAULT_IMAGE_SIMILARITY_TOP_K = 2

# NOTE: for text-embedding-ada-002
DEFAULT_EMBEDDING_DIM = 1536

# context window size for llm predictor
COHERE_CONTEXT_WINDOW = 2048
AI21_J2_CONTEXT_WINDOW = 8192
