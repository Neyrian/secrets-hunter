import argparse
import os
import shutil
import tempfile
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from git import Repo
from rules import scan_line

# Magic hash representing an absolute empty tree state in Git
GIT_EMPTY_TREE_SHA = "4b825dc642cb6eb9a030e54bf8d69288fbee4904"

# ----------------------------------------------------------------------
# 1. THREAD-SAFE ANALYSIS WORKERS
# ----------------------------------------------------------------------

def worker_scan_file(file_path: str, display_name: str = None):
    """
    Worker function executed by threads to scan a single file.
    Returns a list of findings.
    """
    if not display_name:
        display_name = file_path
        
    local_findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                findings = scan_line(line, line_num)
                for finding in findings:
                    finding["location"] = display_name
                    local_findings.append(finding)
    except Exception:
        pass
    return local_findings


def worker_scan_commit(commit_hash: str, parent_hash: str, repo_path: str):
    """
    Worker function executed by threads to analyze a single commit diff.
    Supports standard diffs and initial/root commit tracking.
    """
    local_findings = []
    try:
        repo = Repo(repo_path)
        commit = repo.commit(commit_hash)
        
        # If no parent exists, diff against Git's absolute empty tree state
        if parent_hash == GIT_EMPTY_TREE_SHA:
            empty_tree = repo.tree(GIT_EMPTY_TREE_SHA)
            diffs = empty_tree.diff(commit.tree, create_patch=True)
        else:
            parent = repo.commit(parent_hash)
            diffs = parent.diff(commit, create_patch=True)
        
        for diff in diffs:
            if diff.diff:
                patch_lines = diff.diff.decode('utf-8', errors='ignore').splitlines()
                for line_num, line in enumerate(patch_lines, 1):
                    if line.startswith('+') and not line.startswith('+++'):
                        actual_code_line = line[1:]
                        findings = scan_line(actual_code_line, line_num)
                        
                        for finding in findings:
                            finding["commit"] = commit_hash[:8]
                            finding["author"] = str(commit.author)
                            finding["msg"] = commit.message.strip().split('\n')[0]
                            finding["location"] = diff.b_path if diff.b_path else "unknown"
                            local_findings.append(finding)
    except Exception:
        pass
    return local_findings

# ----------------------------------------------------------------------
# 2. MULTI-THREADED ORCHESTRATION ENGINES
# ----------------------------------------------------------------------

def scan_directory_multithreaded(directory_path: str, max_threads: int):
    """Discovers all local files, scans them concurrently, and returns all findings."""
    print(f"[*] Initializing multi-threaded local scan (Threads: {max_threads})...")
    file_list = []
    
    for root, _, files in os.walk(directory_path):
        if ".git" in root: 
            continue
        for file in files:
            file_list.append(os.path.join(root, file))
            
    print(f"[*] Found {len(file_list)} files. Distributing jobs...")
    
    master_findings = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(worker_scan_file, f): f for f in file_list}
        for future in as_completed(futures):
            master_findings.extend(future.result())
                
    return master_findings


def scan_git_history_multithreaded(repo_url: str, max_threads: int):
    """Clones remote repository, scans commit diffs concurrently, and returns all findings."""
    print(f"[*] Cloning remote repository: {repo_url}")
    temp_dir = tempfile.mkdtemp()
    master_findings = []
    
    try:
        repo = Repo.clone_from(repo_url, temp_dir)
        
        # Explicitly force fetch internal Pull Request and Merge Request references
        print("[*] Fetching hidden remote Pull Request and Merge Request references...")
        try:
            # Maps remote GitHub PR refs to local tracking pointers
            repo.git.fetch('origin', '+refs/pull/*:refs/remotes/origin/pr/*')
        except Exception:
            pass
            
        try:
            # Maps remote GitLab MR refs to local tracking pointers
            repo.git.fetch('origin', '+refs/merge-requests/*:refs/remotes/origin/mr/*')
        except Exception:
            pass

        # Set all=True to search across ALL local, remote, tags, and fetched PR/MR refs
        commits = list(repo.iter_commits(all=True))
        print(f"[+] Sync complete. Found {len(commits)} total commits across all branches/PRs.")
        print(f"[*] Spinning up Git Thread Pool (Threads: {max_threads})...")
        
        # Deduplicate commit hashes to prevent double-scanning identical commits on shared branches
        seen_commits = set()
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for commit in commits:
                if commit.hexsha in seen_commits:
                    continue
                seen_commits.add(commit.hexsha)
                
                if commit.parents:
                    # Scan standard branch intersections
                    for parent in commit.parents:
                        f = executor.submit(worker_scan_commit, commit.hexsha, parent.hexsha, temp_dir)
                        futures.append(f)
                else:
                    # Handle the initial commit tracking against the empty tree
                    f = executor.submit(worker_scan_commit, commit.hexsha, GIT_EMPTY_TREE_SHA, temp_dir)
                    futures.append(f)
                    
            for future in as_completed(futures):
                master_findings.extend(future.result())
                    
    except Exception as e:
        print(f"[–] Git scanning error: {e}")
    finally:
        shutil.rmtree(temp_dir)
        print("[*] Volatile temporary files destroyed safely.")
        
    # Final cleanup deduplication for cross-branch finding intersection
    unique_findings = []
    seen_findings_fingerprints = set()
    for f in master_findings:
        fingerprint = f"{f.get('commit','local')}-{f['location']}-{f['line']}-{f['value']}"
        if fingerprint not in seen_findings_fingerprints:
            seen_findings_fingerprints.add(fingerprint)
            unique_findings.append(f)

    return unique_findings

def install_pre_commit_hook():
    """Hooks SecretHunter into git commit workflows."""
    git_dir = os.path.join(os.getcwd(), ".git")
    if not os.path.isdir(git_dir):
        print("[–] Error: Active directory is not a Git repository. Run 'git init' first.")
        sys.exit(1)
        
    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    hook_file = os.path.join(hooks_dir, "pre-commit")
    
    script_path = os.path.abspath(__file__)
    
    hook_content = f"""#!/bin/sh
# SecretHunter Hook Guardrail
echo "[*] SecretHunter: Screening staged assets for leaks..."

# Isolate only modified/added files prepared for this specific commit
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

FAILED=0
for file in $STAGED_FILES; do
    # Execute tool on individual staged components
    python3 "{script_path}" -f "$file"
    if [ $? -ne 0 ]; then
        FAILED=1
    fi
done

if [ $FAILED -ne 0 ]; then
    echo "\n[!] COMMIT ABORTED: Hardcoded credentials detected by SecretHunter."
    echo "[*] Action Required: Clean the file or append '# secret-hunter:ignore' to bypass validation."
    exit 1
fi

exit 0
"""
    
    try:
        with open(hook_file, "w", encoding="utf-8") as f:
            f.write(hook_content)
        
        if os.name != "nt":
            os.chmod(hook_file, 0o755)
            
        print(f"[+] Shield Engaged! Pre-commit guard installed safely to: {hook_file}")
    except Exception as e:
        print(f"[–] Failed to write hook file: {e}")
        sys.exit(1)

# ----------------------------------------------------------------------
# 3. EXPORT & OUTPUT ENGINES
# ----------------------------------------------------------------------

def export_json(findings: list, output_file: str):
    """Dumps raw findings array into a structured JSON file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=4)
        print(f"[+] Successfully exported {len(findings)} findings to {output_file} (JSON format)")
    except Exception as e:
        print(f"[–] Failed to write JSON output: {e}")


def export_sarif(findings: list, output_file: str):
    """Transforms tracking schemas into the global industry standard SARIF v2.1.0."""
    sarif_output = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecretHunter",
                        "informationUri": "https://github.com/yourusername/secret-hunter",
                        "version": "2.0",
                        "rules": [
                            {
                                "id": "SH-001",
                                "name": "HardcodedCredential",
                                "shortDescription": {"text": "A hardcoded secret, encryption key, or token was discovered."}
                            }
                        ]
                    }
                },
                "results": []
            }
        ]
    }

    for finding in findings:
        sarif_result = {
            "ruleId": "SH-001",
            "level": "error",
            "message": {
                "text": f"[{finding['type']}] {finding['description']}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding['location']
                        },
                        "region": {
                            "startLine": finding['line']
                        }
                    }
                }
            ]
        }
        sarif_output["runs"][0]["results"].append(sarif_result)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sarif_output, f, indent=4)
        print(f"[+] Successfully exported {len(findings)} findings to {output_file} (SARIF specification format)")
    except Exception as e:
        print(f"[–] Failed to write SARIF output: {e}")


def print_to_terminal(findings: list):
    """Formats and prints findings to standard stdout."""
    for finding in findings:
        if "commit" in finding:
            print(f"\n[!] ALERT - HISTORICAL LEAK DETECTED!")
            print(f"    Commit:   {finding['commit']} ({finding['author']}) -> {finding['msg']}")
        else:
            print(f"\n[!] ALERT - {finding['type']} Found!")
            
        print(f"    File:     {finding['location']}")
        print(f"    Line {finding['line']}: {finding['description']}")
        print(f"    Secret:   {finding['value']}")
        print("-" * 60)
        
    print(f"\n[+] Scan complete. Total unique items recovered: {len(findings)}")


# ----------------------------------------------------------------------
# 4. CLI ENTRYPOINT
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SecretHunter (v2.0 - Universal Coverage): Concurrent cross-branch git history and static analysis engine."
    )
    parser.add_argument("-f", "--file", help="Path to a single local file to scan")
    parser.add_argument("-d", "--dir", help="Path to a local directory to scan recursively")
    parser.add_argument("-g", "--git", help="URL of a remote Git repository to deep scan")
    parser.add_argument("-t", "--threads", type=int, default=8, help="Number of concurrent threads (Default: 8)")
    parser.add_argument("--install-hook", action="store_true", help="Install SecretHunter as a native Git pre-commit hook")
    parser.add_argument("--format", choices=["console", "json", "sarif"], default="console", help="Reporting output format (Default: console)")
    parser.add_argument("-o", "--output", help="Filepath target to write results (Required for json/sarif targets)")
    
    args = parser.parse_args()

    if args.install_hook:
        install_pre_commit_hook()
        sys.exit(0)

    findings = []

    if args.file:
        if os.path.exists(args.file):
            findings = worker_scan_file(args.file)
        else:
            print("[–] File not found.")
            sys.exit(1)
    elif args.dir:
        if os.path.exists(args.dir):
            findings = scan_directory_multithreaded(args.dir, args.threads)
        else:
            print("[–] Directory not found.")
            sys.exit(1)
    elif args.git:
        findings = scan_git_history_multithreaded(args.git, args.threads)
    else:
        parser.print_help()
        sys.exit(0)

    if not findings:
        print("\n[+] Process complete. No secrets discovered.")
        sys.exit(0)

    if args.format == "json":
        if not args.output:
            print("[–] Error: You must supply a save filepath using '-o <file>' when setting format to JSON.")
            sys.exit(1)
        else:
            export_json(findings, args.output)
    elif args.format == "sarif":
        if not args.output:
            print("[–] Error: You must supply a save filepath using '-o <file>' when setting format to SARIF.")
            sys.exit(1)
        else:
            export_sarif(findings, args.output)
    else:
        print_to_terminal(findings)

    sys.exit(1)

if __name__ == "__main__":
    main()