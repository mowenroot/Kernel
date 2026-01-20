import cpp
import semmle.code.cpp.Print // Import the required module for getIdentityString

/**
 * @name Extract function start and end line
 * @description Extracts the start and end line of the function body given the function name,
 * excluding functions from the standard library.
 * @kind problem
 * @problem.severity warning
 * @id cpp/extract-function-start-end-line
 */
// from Function f, Location loc
// where loc = f.getADeclarationEntry().getBlock().getLocation()
//   and not loc.getFile().getAbsolutePath().matches("%/usr/include/%") and not loc.getFile().getAbsolutePath().matches("%/usr/local/include/%")
//   and loc.getFile().getAbsolutePath().matches("/src/%") // Modify this pattern as needed
// select f,  getIdentityString(f), f.getQualifiedName(), loc.getFile(), loc.getStartLine(), loc.getEndLine()

//from Function f, Location loc
//where loc = f.getADeclarationEntry().getBlock().getLocation()  and loc.getFile().getAbsolutePath().matches("/src/%")
//select f, getIdentityString(f), f.getFullSignature(), loc.getFile(), loc.getStartLine(), loc.getEndLine()


predicate isRelevantFunction(TemplateFunction f, Location loc) {
    loc.getFile().getAbsolutePath().matches("/src/%")
}

from TemplateFunction f, Location loc
where 
    loc = f.getADeclarationEntry().getBlock().getLocation() and isRelevantFunction(f, loc) and f.isSpecialization()
select f as fn_name, f.getASpecialization() as template_specialization, f.getAPrimaryQlClass() as primay_class,f.getFullSignature() as signature, f.getParameterString() as parameter_string, f.getType() as return_type, f.getUnspecifiedType() as return_type_inferred, loc.getFile() as fn_file_path, f.getDefinitionLocation().getFile() as def_file_path, f.getDefinitionLocation().getStartLine() as def_start_line, f.getDefinitionLocation().getEndLine() as def_end_line, loc.getStartLine() as body_start_line, loc.getEndLine() as body_end_line

