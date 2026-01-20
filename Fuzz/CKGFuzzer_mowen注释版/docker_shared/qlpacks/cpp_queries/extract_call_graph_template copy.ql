import cpp // 引入 C++ 语言支持模块，提供对 C++ AST、类型、函数等的支持。
import semmle.code.cpp.ir.dataflow.DataFlow // 引入 DataFlow 模块，用于静态分析数据流（如变量赋值、函数指针传递等）。


// Configuration for function pointer calls
// 函数指针调用的数据流配置类，用于找出源（source）和汇（sink）节点。
class Conf extends DataFlow::Configuration {
  // 配置类的构造函数，给这个配置类一个名称。
  Conf() { this = "Conf" }

  // 设置数据流的起点（source）是 FunctionAccess，即取到一个函数指针。
  override predicate isSource(DataFlow::Node source) { source.asExpr() instanceof FunctionAccess }

  // 数据流的终点（sink）是某个函数调用（ExprCall）的位置，说明最终调用了这个指针。
  override predicate isSink(DataFlow::Node sink) { sink.asExpr() = any(ExprCall call).getExpr() }
}

// Direct function calls
// 显式函数调用
// 检查一个函数 caller 是否直接调用了另一个函数 callee
predicate directCall(Function caller, Function callee) {
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = caller and
    fc.getTarget() = callee
  )
}

// Virtual method calls
// 虚函数调用
// 判断是否存在通过虚函数机制的调用
predicate virtualCall(Function caller, Function callee) {
  exists(Call vc |
    vc.getEnclosingFunction() = caller and
    vc.getTarget() = callee and
    exists(MemberFunction mf |  
      mf = callee and
      exists(MemberFunction base |
        base = mf.getAnOverriddenFunction*() and
        base.isVirtual() 
        // base.isVirtual() : 存在一个虚函数基类
        // mf.getAnOverriddenFunction*()  : 该函数是某个虚函数的 override。
      )
    )
  )
}

// Function pointer calls
// 是否通过函数指针 caller 调用了 callee
predicate functionPointerCall(Function caller, Function callee) {

  // 函数指针的获取是通过 FunctionAccess 节点进行的，该节点表示对函数指针的访问。
  // callee = funcAccess.getTarget()  : 通过函数指针 funcAccess 实际调用了 callee
  exists(FunctionAccess funcAccess, DataFlow::Node sink |
    any(Conf conf).hasFlow(DataFlow::exprNode(funcAccess), sink) and
    sink.getEnclosingCallable() = caller and
    callee = funcAccess.getTarget()
  )

}

// Combined edge predicate
// 统一视为调用边 : 直接调用、虚函数调用、函数指针调用
predicate edges(Function caller, Function callee) {
  directCall(caller, callee) or
  virtualCall(caller, callee) or
  functionPointerCall(caller, callee)
}

// Reachability predicate (includes transitive calls)
// 判断函数 src 是否传递可达 dest，形成一个调用链图（Call Graph）
//  因为边的可达性，这里分为两种情况：一跳边即可达、通过中间函数 mid 递归可达
predicate reachable(Function src, Function dest) {
  edges(src, dest)
  or
  exists(Function mid |
    edges(src, mid) and
    reachable(mid, dest)
  )
}

// Entry point predicate
// 入口点判断（main/构造函数等）,这里 ENTRY_FNC 在实际提取中会被替换为实际函数名
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
// 查询入口点 start 到 end 的调用链
// isEntryPoint(start) : 判断 start 是否是入口点
// reachable(start, end) : 判断 start 是否传递可达 end
// start_loc = start.getLocation() : 获取 start 的位置信息
// end_loc = end.getLocation() : 获取 end 的位置信息

from Function start, Function end, Location start_loc, Location end_loc
where
  isEntryPoint(start) and
  reachable(start, end) and
  start_loc = start.getLocation() and
  end_loc = end.getLocation()
select
  start as caller,  //调用者
  end as callee,  //被调用者
  start.getFile() as caller_src,  //获取 start 的文件名
  end.getFile() as callee_src,  //获取 end 的文件名
  start_loc.getStartLine() as start_body_start_line,  //调用者函数体起始行
  start_loc.getEndLine() as start_body_end_line,  //调用者函数体结束行
  end_loc.getStartLine() as end_body_start_line,  //被调用者函数体起始行
  end_loc.getEndLine() as end_body_end_line,  //被调用者函数体结束行
  start.getFullSignature() as caller_signature, //调用者签名
  start.getParameterString() as caller_parameter_string,  //调用者参数
  start.getType() as caller_return_type,  //调用者返回类型
  start.getUnspecifiedType() as caller_return_type_inferred,  //调用者返回类型（未指定）
  end.getFullSignature() as callee_signature, //被调用者签名
  end.getParameterString() as callee_parameter_string,  //被调用者参数
  end.getType() as callee_return_type,  //被调用者返回类型
  end.getUnspecifiedType() as callee_return_type_inferred //被调用者返回类型（未指定）