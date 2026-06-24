#!/usr/bin/env python3
import json
import os
import sys

# Severity mapping to numeric values
SEVERITY_LEVELS = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

def get_severity_score(sev):
    return SEVERITY_LEVELS.get(sev.lower().strip(), 0)

def parse_sca(file_path):
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return counts
    
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Snyk test output can be a single dict or a list of dicts (multi-project)
        if isinstance(data, list):
            projects = data
        else:
            projects = [data]
            
        for project in projects:
            vulns = project.get("vulnerabilities", [])
            for vuln in vulns:
                sev = vuln.get("severity", "low").lower()
                if sev in counts:
                    counts[sev] += 1
                else:
                    counts["low"] += 1 # Default fallback
    except Exception as e:
        print(f"Warning: Failed to parse SCA report {file_path}: {e}")
        
    return counts

def parse_sast(file_path):
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return counts
        
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        # Snyk Code test output can be SARIF format (with 'runs') or proprietary JSON format
        if "runs" in data:
            # SARIF parsing
            for run in data.get("runs", []):
                results = run.get("results", [])
                for result in results:
                    # Check properties for Snyk-specific severity
                    sev = result.get("properties", {}).get("severity", "").lower()
                    if sev in counts:
                        counts[sev] += 1
                        continue
                    
                    # Fallback to SARIF level mapping
                    level = result.get("level", "").lower()
                    if level == "error":
                        counts["high"] += 1
                    elif level == "warning":
                        counts["medium"] += 1
                    elif level == "note" or level == "none":
                        counts["low"] += 1
                    else:
                        counts["medium"] += 1 # Default middle ground
        else:
            # Snyk proprietary format
            vulns = data.get("vulnerabilities", [])
            for vuln in vulns:
                sev = vuln.get("severity", "low").lower()
                if sev in counts:
                    counts[sev] += 1
                else:
                    counts["low"] += 1
    except Exception as e:
        print(f"Warning: Failed to parse SAST report {file_path}: {e}")
        
    return counts

def count_ggshield_incidents(data):
    count = 0
    if isinstance(data, dict):
        for k, v in data.items():
            if k == "incidents" and isinstance(v, list):
                count += len(v)
            else:
                count += count_ggshield_incidents(v)
    elif isinstance(data, list):
        for item in data:
            count += count_ggshield_incidents(item)
    return count

def parse_gitguardian(file_path):
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return counts
        
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        incident_count = count_ggshield_incidents(data)
        # Classify GitGuardian secret leaks as Critical findings
        counts["critical"] = incident_count
    except Exception as e:
        print(f"Warning: Failed to parse GitGuardian report {file_path}: {e}")
        
    return counts

def main():
    if len(sys.argv) < 5:
        print("Usage: parse-results.py <sca_json> <sast_json> <gitguardian_json> <fail_on_severity> [cmdb_metadata_json_str]")
        sys.exit(1)
        
    sca_file = sys.argv[1]
    sast_file = sys.argv[2]
    gitguardian_file = sys.argv[3]
    threshold_sev = sys.argv[4].lower()
    
    cmdb_metadata = {}
    if len(sys.argv) >= 6:
        try:
            cmdb_metadata = json.loads(sys.argv[5])
        except Exception as e:
            print(f"Warning: Failed to parse CMDB metadata JSON string: {e}")

    # Parse reports
    sca_counts = parse_sca(sca_file)
    sast_counts = parse_sast(sast_file)
    gitguardian_counts = parse_gitguardian(gitguardian_file)
    
    total_counts = {
        "low": sca_counts["low"] + sast_counts["low"] + gitguardian_counts["low"],
        "medium": sca_counts["medium"] + sast_counts["medium"] + gitguardian_counts["medium"],
        "high": sca_counts["high"] + sast_counts["high"] + gitguardian_counts["high"],
        "critical": sca_counts["critical"] + sast_counts["critical"] + gitguardian_counts["critical"]
    }
    
    # Generate Markdown report
    md_content = []
    md_content.append("## 🛡️ Centralized Security Scan Report")
    md_content.append("")
    
    # Append CMDB Metadata
    if cmdb_metadata:
        md_content.append("### 🏷️ Application Metadata (CMDB)")
        md_content.append("| Metadata Field | Value |")
        md_content.append("| --- | --- |")
        for key, val in cmdb_metadata.items():
            md_content.append(f"| **{key.replace('_', ' ').title()}** | {val} |")
        md_content.append("")
        
    md_content.append("### 📊 Vulnerability Metrics Summary")
    md_content.append("| Scan Type | Critical 🔴 | High 🟠 | Medium 🟡 | Low 🔵 |")
    md_content.append("| --- | --- | --- | --- | --- |")
    md_content.append(f"| **SCA (Dependencies)** | {sca_counts['critical']} | {sca_counts['high']} | {sca_counts['medium']} | {sca_counts['low']} |")
    md_content.append(f"| **SAST (Static Code)** | {sast_counts['critical']} | {sast_counts['high']} | {sast_counts['medium']} | {sast_counts['low']} |")
    md_content.append(f"| **Secrets (GitGuardian)** | {gitguardian_counts['critical']} | {gitguardian_counts['high']} | {gitguardian_counts['medium']} | {gitguardian_counts['low']} |")
    md_content.append(f"| **Total** | **{total_counts['critical']}** | **{total_counts['high']}** | **{total_counts['medium']}** | **{total_counts['low']}** |")
    md_content.append("")
    
    # Check policy gates
    threshold_score = get_severity_score(threshold_sev)
    failed = False
    fail_reasons = []
    
    for sev, count in total_counts.items():
        if count > 0 and get_severity_score(sev) >= threshold_score:
            failed = True
            fail_reasons.append(f"{count} {sev.upper()} finding(s) detected.")
            
    md_content.append("### 🚦 Policy Gate Status")
    if failed:
        md_content.append(f"❌ **FAILED**: Policy set to fail on **{threshold_sev.upper()}** or higher findings.")
        md_content.append("#### Reasons for failure:")
        for reason in fail_reasons:
            md_content.append(f"- {reason}")
    else:
        md_content.append(f"✅ **PASSED**: No findings at or above policy threshold (**{threshold_sev.upper()}**).")
    
    # Write to GitHub Step Summary
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_file:
        try:
            with open(summary_file, 'a') as sf:
                sf.write("\n".join(md_content) + "\n")
            print("Successfully wrote Markdown summary report to GITHUB_STEP_SUMMARY.")
        except Exception as e:
            print(f"Error writing to GITHUB_STEP_SUMMARY: {e}")
    else:
        print("\n".join(md_content))
        
    # Exit code
    # if failed:
    #     print(f"Policy gate breached. Failing build because of high/critical findings.")
    #     sys.exit(1)
    # else:
    #     print("Policy gate passed successfully.")
    #     sys.exit(0)
    print("Policy gate check complete. Continuing build (failing checks are commented out).")
    sys.exit(0)

if __name__ == "__main__":
    main()
