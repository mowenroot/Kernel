/**
* @kind path-problem
*/

import semmle.code.cpp.dataflow.new.DataFlow
import Flow::PathGraph

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr().(Call).getTarget().hasName("user_input")
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getTarget().hasName("sink") and
      sink.asExpr() = call.getAnArgument()
    )
  }
}

module Flow = DataFlow::Global<Config>;

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Flow from user input to sink!"