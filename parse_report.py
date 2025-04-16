import json

def parse_trivy_report(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)

    summary = []

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity")
            if severity in ["CRITICAL", "HIGH"]:
                summary.append({
                    "Target": result.get("Target"),
                    "Package": vuln.get("PkgName"),
                    "Severity": severity,
                    "Vulnerability ID": vuln.get("VulnerabilityID"),
                    "Installed Version": vuln.get("InstalledVersion"),
                    "Fixed Version": vuln.get("FixedVersion", "N/A"),
                    "Title": vuln.get("Title", ""),
                    "Description": vuln.get("Description", "")[:150] + "..."
                })

    return summary

if __name__ == "__main__":
    report_file = "report.json"
    findings = parse_trivy_report(report_file)

    print(f"\nFound {len(findings)} CRITICAL/HIGH vulnerabilities:\n")
    for i, item in enumerate(findings, 1):
        print(f"{i}. [{item['Severity']}] {item['Vulnerability ID']} in {item['Package']} "
              f"(Installed: {item['Installed Version']}, Fixed: {item['Fixed Version']})")
        print(f"   → {item['Title']}")
        print(f"   → {item['Target']}")
        print()
