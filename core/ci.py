import sys
from typing import Dict, Any, List
from rich.console import Console

console = Console()

class CIHandler:
    def __init__(self, fail_on: str = "HIGH", format: str = "text"):
        self.fail_on = fail_on.upper()
        self.format = format.lower()
        self.risk_levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0, "ACCEPTED": 0}
        self.threshold = self.risk_levels.get(self.fail_on, 3) # Default to HIGH

    def evaluate(self, report: Dict[str, Any], diff: Dict[str, Any] = None) -> None:
        """
        Evaluates the report and exits with 1 if failure conditions are met.
        """
        failure_reasons = []
        findings = report.get("findings", {})
        
        # 1. Check for Auth Leaks (Always Fail)
        if findings.get("auth", {}).get("leaked"):
            failure_reasons.append("Auth Leak Detected")
            self._print_error("Auth Leak Detected: Public access to users table!", "CRITICAL")

        # 2. Check RLS Issues
        rls_issues = findings.get("rls", [])
        for r in rls_issues:
            risk = r.get("risk", "SAFE")
            if self.risk_levels.get(risk, 0) >= self.threshold:
                failure_reasons.append(f"RLS Issue: {r['table']} ({risk})")
                self._print_error(f"RLS Risk in {r['table']}: {risk}", risk)

        # 3. Check RPC Issues
        rpc_issues = findings.get("rpc", [])
        for r in rpc_issues:
            risk = r.get("risk", "SAFE")
            if self.risk_levels.get(risk, 0) >= self.threshold:
                failure_reasons.append(f"RPC Issue: {r['name']} ({risk})")
                self._print_error(f"RPC Risk in {r['name']}: {risk}", risk)

        # 4. Check Diff Regressions (if provided)
        if diff:
            new_rls = diff.get("rls", {}).get("new", [])
            if new_rls:
                failure_reasons.append(f"{len(new_rls)} New RLS Regressions")
                for r in new_rls:
                    self._print_error(f"Regression: New RLS issue in {r['table']}", r.get('risk', 'UNKNOWN'))

        if failure_reasons:
            if self.format == "text":
                console.print(f"\n[bold red]❌ CI Failure: {len(failure_reasons)} issues found.[/]")
            sys.exit(1)
        else:
            if self.format == "text":
                console.print("\n[bold green]✔ CI Passed: No issues found meeting failure criteria.[/]")
            sys.exit(0)

    def _print_error(self, message: str, level: str):
        if self.format == "github":
            # GitHub Actions Annotation Format
            # ::error file={name},line={line},endLine={endLine},title={title}::{message}
            print(f"::error title=SSF {level}::{message}")
        else:
            console.print(f"[red][!] {message}[/]")
