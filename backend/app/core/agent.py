import uuid
from typing import Any
from datetime import datetime
from app.schemas import UnifiedInvestigationResult, AgentState
from app.core.planner import generate_plan
from app.core.executor import execute_tool
from app.core.validator import validate_evidence
from app.core.reporter import generate_report

class DFIRAgent:
    def __init__(self, target_type: str, target_value: str, file_content: bytes = None):
        self.state = AgentState(
            scan_id=str(uuid.uuid4()),
            target_type=target_type,
            target_value=target_value
        )
        self.file_content = file_content # Hold raw data if it's a file
        
    def _log(self, action: str, details: str):
        self.state.execution_log.append({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": action,
            "details": details
        })

    def run(self) -> UnifiedInvestigationResult:
        self._log("Initialize", f"Started agent for {self.state.target_type}: {self.state.target_value}")
        
        # 1. Planner
        self._log("Planning", "Generating investigation plan...")
        self.state.plan = generate_plan(self.state.target_type, self.state.target_value)
        self._log("Plan Generated", f"Planned {len(self.state.plan)} steps.")
        
        # 2. Executor
        for step in self.state.plan:
            self._log("Execution", f"Running tool: {step.tool_name}")
            try:
                # pass file_content if needed
                if self.file_content and step.tool_name in ["run_yara", "compute_hashes", "find_strings", "detect_file_type", "compute_entropy", "extract_iocs"]:
                    step.tool_args["content"] = self.file_content
                    
                result = execute_tool(step.tool_name, step.tool_args)
                self.state.evidence_collected[step.tool_name] = result
                self._log("Execution Success", f"Completed {step.tool_name}")
            except Exception as e:
                self._log("Execution Error", f"Tool {step.tool_name} failed: {str(e)}")
                self.state.evidence_collected[step.tool_name] = {"error": str(e)}
        
        # 3. Validator
        self._log("Validation", "Checking evidence for consistency...")
        validation_result = validate_evidence(self.state)
        self.state.validation_status = "validated" if validation_result.get("is_consistent") else "inconsistent"
        self._log("Validation Complete", f"Status: {self.state.validation_status}")
        
        # 4. Reporter
        self._log("Reporting", "Synthesizing final forensic report...")
        report = generate_report(self.state)
        report.execution_log = self.state.execution_log
        self._log("Complete", "Report generated successfully.")
        
        return report
