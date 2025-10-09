import os
import shutil
import subprocess
import tempfile
import zipfile
import requests
import logging
from fastapi import HTTPException
from app.schemas.scan_schema import ScanResult
from dotenv import load_dotenv
import time
import uuid

# Configure logging to console and project directory
log_file = os.path.join(os.path.dirname(__file__), '..', 'sonarqube_service.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(log_file)
    ]
)
logger = logging.getLogger(__name__)

class SonarQubeService:
    def __init__(self):
        load_dotenv()
        self.sonar_host_scanner = "http://sonarqube-doc:9000"
        self.sonar_host_api = "http://localhost:9003"
        self.sonar_token = os.getenv("SONAR_TOKEN")
        if not self.sonar_token:
            raise ValueError("SONAR_TOKEN not set in .env")

        # Verify Docker
        try:
            subprocess.run(["docker", "--version"], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            raise ValueError("Docker is not installed or not running")

        # Verify SonarQube
        try:
            status_resp = requests.get(f"{self.sonar_host_api}/api/system/status", timeout=5)
            if status_resp.status_code != 200 or status_resp.json().get("status") != "UP":
                raise HTTPException(status_code=503, detail="SonarQube server is not available")
        except requests.RequestException as e:
            raise HTTPException(status_code=503, detail=f"Failed to connect to SonarQube: {str(e)}")

    async def scan_zip(self, file: bytes, filename: str) -> ScanResult:
        if not filename.endswith(".zip"):
            raise HTTPException(status_code=400, detail="Only .zip files allowed")

        # Supported extensions
        supported_extensions = {
            'abap': ['.abap'], 'ansible': ['.yml', '.yaml'], 'apex': ['.cls', '.apex'],
            'arm': ['.json', '.bicep'], 'cpp': ['.c', '.cpp', '.h', '.hpp', '.m', '.mm'],
            'cloudformation': ['.json', '.yml', '.yaml'], 'cs': ['.cs'],
            'cobol': ['.cbl', '.cob', '.cpy'], 'docker': ['.dockerfile', 'dockerfile', 'dockerfile.'],
            'dart': ['.dart'], 'flex': ['.mxml', '.as'], 'githubactions': ['.yml', '.yaml'],
            'go': ['.go'], 'html': ['.html', '.htm', '.xhtml', '.aspx'], 'java': ['.java'],
            'js': ['.js', '.jsx', '.ts', '.tsx', '.css', '.scss', '.less'], 'jcl': ['.jcl'],
            'json': ['.json'], 'kotlin': ['.kt', '.kts'], 'k8s': ['.yml', '.yaml'],
            'php': ['.php', '.php3', '.php4', '.php5', '.phtml'], 'pli': ['.pli', '.pl1'],
            'plsql': ['.sql'], 'py': ['.py'], 'rpg': ['.rpgle', '.sqlrpgle'],
            'ruby': ['.rb', '.erb', '.rjs', '.rhtml', '.haml', '.slim'], 'rust': ['.rs'],
            'scala': ['.scala', '.sc'], 'secrets': [], 'swift': ['.swift'],
            'terraform': ['.tf', '.tfvars'], 'tsql': ['.sql'], 'vbnet': ['.vb'],
            'vb6': ['.bas', '.frm', '.cls'], 'xml': ['.xml'], 'yaml': ['.yml', '.yaml']
        }
        all_supported_exts = set()
        for exts in supported_extensions.values():
            all_supported_exts.update(exts)

        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, filename)
        try:
            # Save and extract zip
            with open(zip_path, "wb") as f:
                f.write(file)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                if not zip_ref.namelist():
                    raise HTTPException(status_code=400, detail="Zip file is empty")
                has_supported_files = False
                for f in zip_ref.namelist():
                    if f.endswith(tuple(all_supported_exts)):
                        has_supported_files = True
                        break
                if not has_supported_files:
                    raise HTTPException(status_code=400, detail="No supported source files in zip")
                zip_ref.extractall(temp_dir)

            project_dir = temp_dir
            project_key = f"scan_{int(time.time())}_{uuid.uuid4().hex[:8]}"
            project_name = f"Scan_{filename}_{int(time.time())}"

            # Create SonarQube project
            api_base = f"{self.sonar_host_api}/api"
            auth_headers = {"Authorization": f"Bearer {self.sonar_token}"}
            create_project_url = f"{api_base}/projects/create"
            create_project_params = {"project": project_key, "name": project_name}
            try:
                create_resp = requests.post(create_project_url, headers=auth_headers, params=create_project_params, timeout=10)
                if create_resp.status_code != 200:
                    logger.error(f"Project creation failed: {create_resp.status_code} {create_resp.text}")
                    raise HTTPException(status_code=500, detail=f"Failed to create project: {create_resp.text}")
            except requests.RequestException as e:
                logger.error(f"Project creation exception: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Project creation failed: {str(e)}")

            # Create sonar-project.properties
            props_path = os.path.join(project_dir, "sonar-project.properties")
            props_content = f"""
                sonar.projectKey={project_key}
                sonar.projectName={project_name}
                sonar.sources=.
                sonar.sourceEncoding=UTF-8
                sonar.host.url={self.sonar_host_scanner}
                sonar.token={self.sonar_token}
                """
            if any(os.path.splitext(f)[1] in {'.rb', '.erb', '.rjs', '.rhtml', '.haml', '.slim'} for f in os.listdir(project_dir)):
                props_content += "sonar.ruby.file.suffixes=.rb,.erb,.rjs,.rhtml,.haml,.slim\n"
            if any(os.path.splitext(f)[1] in {'.java'} for f in os.listdir(project_dir)):
                props_content += "sonar.java.file.suffixes=.java\n"
            if any(os.path.splitext(f)[1] in {'.aspx'} for f in os.listdir(project_dir)):
                props_content += "sonar.html.file.suffixes=.aspx\n"
            with open(props_path, "w") as props_file:
                props_file.write(props_content)

            # Run SonarScanner
            volume_mount = f"{os.path.abspath(project_dir)}:/usr/src"
            docker_cmd = [
                "docker", "run", "--rm", "--network=sonarqube-net",
                "-v", volume_mount, "-w", "/usr/src",
                "-e", f"SONAR_HOST_URL={self.sonar_host_scanner}",
                "-e", f"SONAR_TOKEN={self.sonar_token}",
                "sonarsource/sonar-scanner-cli:latest"
            ]
            logger.info(f"Running SonarScanner for {project_key}")
            result = subprocess.run(docker_cmd, capture_output=True, text=True, cwd=project_dir)
            if result.returncode != 0:
                logger.error(f"Scan failed: {result.stderr}")
                raise HTTPException(status_code=500, detail=f"Scan failed: {result.stderr}\nOutput: {result.stdout}")

            # Wait for scan results
            for _ in range(15):
                issues_resp = requests.get(f"{api_base}/issues/search", headers=auth_headers, params={"componentKeys": project_key, "per_page": 100}, timeout=10)
                if issues_resp.status_code == 200 and issues_resp.json().get("issues"):
                    break
                logger.info(f"Waiting for scan results, attempt {_+1}/15")
                time.sleep(3)

            # Fetch measures
            measures_url = f"{api_base}/measures/component"
            measures_params = {"component": project_key, "metricKeys": "bugs,vulnerabilities,code_smells,coverage"}
            measures_resp = requests.get(measures_url, headers=auth_headers, params=measures_params, timeout=10)
            if measures_resp.status_code != 200:
                logger.error(f"Measures fetch failed: {measures_resp.status_code} {measures_resp.text}")
                raise HTTPException(status_code=500, detail=f"Failed to fetch measures: {measures_resp.text}")

            measures = {}
            measures_data = measures_resp.json().get("component", {}).get("measures", [])
            for measure in measures_data:
                key = measure["metric"]
                value = measure.get("value")
                measures[key] = float(value) if value else None

            # Fetch issues with detailed information
            issues_url = f"{api_base}/issues/search"
            issues_params = {"componentKeys": project_key, "per_page": 100}
            issues_resp = requests.get(issues_url, headers=auth_headers, params=issues_params, timeout=10)
            if issues_resp.status_code != 200:
                logger.error(f"Issues fetch failed: {issues_resp.status_code} {issues_resp.text}")
                raise HTTPException(status_code=500, detail=f"Failed to fetch issues: {issues_resp.text}")

            issues_data = issues_resp.json().get("issues", [])
            issues = []
            for i in issues_data:
                issue = {
                    "key": i["key"],
                    "message": i["message"],
                    "severity": i["severity"],
                    "file": i.get("component", "").split(":")[-1],
                    "line": i.get("line"),
                    "start_line": i.get("textRange", {}).get("startLine"),
                    "end_line": i.get("textRange", {}).get("endLine"),
                    "rule": i.get("rule", ""),
                    "code_snippet": None
                }
                if issue["line"]:
                    # Try API first
                    try:
                        source_url = f"{api_base}/sources/lines"
                        source_params = {
                            "key": i["component"],
                            "from": max(1, issue["line"] - 2),
                            "to": issue["line"] + 2
                        }
                        logger.info(f"Fetching code snippet for issue {i['key']} at {i['component']}:{issue['line']}")
                        source_resp = requests.get(source_url, headers=auth_headers, params=source_params, timeout=10)
                        if source_resp.status_code == 200:
                            lines = source_resp.json().get("sources", [])
                            issue["code_snippet"] = "\n".join([line["code"] for line in lines if "code" in line]) or None
                            logger.info(f"API snippet retrieved for {i['key']}")
                        else:
                            logger.warning(f"API failed for issue {i['key']}: {source_resp.status_code} {source_resp.text}")
                    except requests.RequestException as e:
                        logger.warning(f"API exception for issue {i['key']}: {str(e)}")

                    # Fallback: Read from extracted file
                    if not issue["code_snippet"]:
                        file_path = os.path.join(project_dir, issue["file"])
                        if os.path.exists(file_path):
                            try:
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    lines = f.readlines()
                                    line_num = issue["line"] - 1
                                    start = max(0, line_num - 2)
                                    end = min(len(lines), line_num + 3)
                                    issue["code_snippet"] = "".join(lines[start:end]).strip()
                                    logger.info(f"Fallback snippet retrieved for {i['key']} from {file_path}")
                            except Exception as e:
                                logger.warning(f"Fallback failed for {i['key']}: {str(e)}")
                        else:
                            logger.warning(f"File not found for fallback: {file_path}")
                issues.append(issue)

            # Comment out project deletion for UI verification
            # delete_project_url = f"{api_base}/projects/delete"
            # delete_project_params = {"project": project_key}
            # delete_resp = requests.post(delete_project_url, headers=auth_headers, params=delete_project_params, timeout=10)
            # if delete_resp.status_code != 204:
            #     logger.warning(f"Failed to delete project {project_key}: {delete_resp.text}")

            logger.info(f"Scan completed for {project_key}: {len(issues)} issues found")
            return ScanResult(
                bugs=int(measures.get("bugs", 0)),
                vulnerabilities=int(measures.get("vulnerabilities", 0)),
                code_smells=int(measures.get("code_smells", 0)),
                coverage=measures.get("coverage"),
                issues=issues
            )

        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)