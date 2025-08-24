import python
import semmle.code.python.dataflow.TaintTracking

class SqlSink extends MethodAccess {
  SqlSink() {
    this.getMethod().getName() = "execute"
  }
}

class TaintConfig extends TaintTracking::Configuration {
  TaintConfig() { this = "SQL Injection Config" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr().toString().matches("request.GET.get%")
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof SqlSink
  }
}

from TaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select source, sink, "Untrusted input flows into SQL execution."
