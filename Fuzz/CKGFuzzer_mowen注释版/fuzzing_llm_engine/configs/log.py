from loguru import logger
def setup_logger( filename: str = "fuzzing_agent_engine.log"):
    log_filename = filename
    logger.add(log_filename,  backtrace=True, diagnose=True)
    return logger
