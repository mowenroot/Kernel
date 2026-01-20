import cpp
import semmle.code.cpp.Print // Import the required module for getIdentityString

predicate isRelevantFunction(Location loc) {
    loc.getFile().getAbsolutePath().matches("/src/%")
}

string isConstructed(Function f){
    f.isConstructedFrom(f) and result = "True" 
    or
    ( not f.isConstructedFrom(f) ) and result = "False"
}

string isSpe(Function f){
    f.isSpecialization() and result = "True"
    or
    ( not f.isSpecialization()  ) and result = "False"
}

string isComGen(Function f){
    f.isCompilerGenerated() and result = "True"
    or
    (not f.isCompilerGenerated() ) and result = "False"
}

from Function f, Location loc
where 
    loc = f.getADeclarationEntry().getBlock().getLocation() and isRelevantFunction(loc)
select f as fn_name, isComGen(f) as isCompied, isConstructed(f) as isconstructed, isSpe(f) as isspecialization,f.getFullSignature() as signature, f.getParameterString() as parameter_string, f.getType() as return_type, f.getUnspecifiedType() as return_type_inferred, loc.getFile() as fn_file_path, f.getDefinitionLocation().getFile() as def_file_path, f.getDefinitionLocation().getStartLine() as def_start_line, f.getDefinitionLocation().getEndLine() as def_end_line, loc.getStartLine() as body_start_line, loc.getEndLine() as body_end_line