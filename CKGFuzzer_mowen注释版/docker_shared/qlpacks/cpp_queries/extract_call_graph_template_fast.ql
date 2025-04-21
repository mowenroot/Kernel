import cpp
import semmle.code.cpp.ir.dataflow.DataFlow

// Configuration for function pointer calls
class Conf extends DataFlow::Configuration {
  Conf() { this = "Conf" }

  override predicate isSource(DataFlow::Node source) { source.asExpr() instanceof FunctionAccess }

  override predicate isSink(DataFlow::Node sink) { sink.asExpr() = any(ExprCall call).getExpr() }
}

// Direct function calls
predicate directCall(Function caller, Function callee) {
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = caller and
    fc.getTarget() = callee
  )
}

// Virtual method calls
predicate virtualCall(Function caller, Function callee) {
  exists(Call vc |
    vc.getEnclosingFunction() = caller and
    vc.getTarget() = callee and
    exists(MemberFunction mf |  
      mf = callee and
      exists(MemberFunction base |
        base = mf.getAnOverriddenFunction*() and
        base.isVirtual()
      )
    )
  )
}

// Function pointer calls
predicate functionPointerCall(Function caller, Function callee) {
  exists(FunctionAccess funcAccess, DataFlow::Node sink |
    any(Conf conf).hasFlow(DataFlow::exprNode(funcAccess), sink) and
    sink.getEnclosingCallable() = caller and
    callee = funcAccess.getTarget()
  )
}

// Combined edge predicate
predicate edges(Function caller, Function callee) {
  directCall(caller, callee) or
  virtualCall(caller, callee) or
  functionPointerCall(caller, callee)
}

// Reachability predicate (includes transitive calls)
predicate reachableWithDepth(Function src, Function dest, int depth) {
  depth = 1 and edges(src, dest)
  or
  depth in [2..5] and 
  exists(Function mid |
    edges(src, mid) and
    reachableWithDepth(mid, dest, depth - 1)
  )
}

// Entry point predicate
predicate isEntryPoint(Function f) {
  f.hasName("main") or
  f.hasName("ENTRY_FNC") or
  exists(Function func |
    func = f and
    (
      exists(Class c | 
        c.getAMember() = func and 
        func.getName() = c.getName()
      ) or
      not exists(Class c | c.getAMember() = func)
    )
  )
}

// Main query
from Function start, Function end, Location start_loc, Location end_loc
where
  isEntryPoint(start) and
  reachableWithDepth(start, end, 1) and
  start_loc = start.getLocation() and
  end_loc = end.getLocation()
select
  start as caller,
  end as callee,
  start.getFile() as caller_src,
  end.getFile() as callee_src,
  start_loc.getStartLine() as start_body_start_line,
  start_loc.getEndLine() as start_body_end_line,
  end_loc.getStartLine() as end_body_start_line,
  end_loc.getEndLine() as end_body_end_line,
  start.getFullSignature() as caller_signature,
  start.getParameterString() as caller_parameter_string,
  start.getType() as caller_return_type,
  start.getUnspecifiedType() as caller_return_type_inferred,
  end.getFullSignature() as callee_signature,
  end.getParameterString() as callee_parameter_string,
  end.getType() as callee_return_type,
  end.getUnspecifiedType() as callee_return_type_inferred