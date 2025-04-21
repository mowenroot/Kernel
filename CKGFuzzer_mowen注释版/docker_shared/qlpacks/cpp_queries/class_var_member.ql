import cpp

predicate isRelevantFunction(Field f) {
    f.getFile().getAbsolutePath().matches("/src/%")
}

from Field f
where isRelevantFunction(f)
select f as field, f.getFile() as file_name, f.getASpecifier() as specifier, f.getName() as field_name, f.getType() as field_type, f.getLocation().getStartLine() as def_start_line,  f.getLocation().getEndLine() as def_end_line
