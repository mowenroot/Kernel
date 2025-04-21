import cpp

predicate isRelevantFunction(Location loc) {
    loc.getFile().getAbsolutePath().matches("/src/%")
}

from GlobalVariable v, Location loc
where loc = v.getADeclarationLocation() and isRelevantFunction(loc)
select v as var, v.getName() as var_name, v.getType() as var_type, v.getFile() as file_name, v.getLocation().getStartLine() as def_start_line,  v.getLocation().getEndLine() as def_end_line
