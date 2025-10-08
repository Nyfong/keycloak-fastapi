import os
import shutil
import subprocess
import tempfile
import zipfile
import requests
from fastapi import HTTPException
from app.schemas.scan_schema import ScanResult
from dotenv import load_dotenv
import time
import uuid

class SonarQubeService:
    def __init__(self):
        load_dotenv()
        self.sonar_host_scanner = "http://sonarqube-doc:9000"  # For SonarScanner in Docker network
        self.sonar_host_api = "http://localhost:9003"  # For FastAPI on host
        self.sonar_token = os.getenv("SONAR_TOKEN")
        if not self.sonar_token:
            raise ValueError("SONAR_TOKEN not set in .env")

        # Verify Docker is available
        try:
            subprocess.run(["docker", "--version"], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            raise ValueError("Docker is not installed or not running")

    async def scan_zip(self, file: bytes, filename: str) -> ScanResult:
        if not filename.endswith(".zip"):
            raise HTTPException(status_code=400, detail="Only .zip files allowed")

        # Comprehensive mapping of SonarQube supported languages to file extensions
        supported_extensions = {
            'abap': ['.abap'],
            'ansible': ['.yml', '.yaml'],
            'apex': ['.cls', '.apex'],
            'arm': ['.json', '.bicep'],
            'cpp': ['.c', '.cpp', '.h', '.hpp', '.m', '.mm'],
            'cloudformation': ['.json', '.yml', '.yaml'],
            'cs': ['.cs'],
            'cobol': ['.cbl', '.cob', '.cpy'],
            'docker': ['.dockerfile', 'dockerfile', 'dockerfile.'],
            'dart': ['.dart'],
            'flex': ['.mxml', '.as'],
            'githubactions': ['.yml', '.yaml'],
            'go': ['.go'],
            'html': ['.html', '.htm', '.xhtml'],
            'java': ['.java'],
            'js': ['.js', '.jsx', '.ts', '.tsx', '.css', '.scss', '.less'],
            'jcl': ['.jcl'],
            'json': ['.json'],
            'kotlin': ['.kt', '.kts'],
            'k8s': ['.yml', '.yaml'],
            'php': ['.php', '.php3', '.php4', '.php5', '.phtml'],
            'pli': ['.pli', '.pl1'],
            'plsql': ['.sql'],
            'py': ['.py'],
            'rpg': ['.rpgle', '.sqlrpgle'],
            'ruby': ['.rb', '.erb', '.rjs', '.rhtml', '.haml', '.slim'],
            'rust': ['.rs'],
            'scala': ['.scala', '.sc'],
            'secrets': [],
            'swift': ['.swift'],
            'terraform': ['.tf', '.tfvars'],
            'tsql': ['.sql'],
            'vbnet': ['.vb'],
            'vb6': ['.bas', '.frm', '.cls'],
            'xml': ['.xml'],
            'yaml': ['.yml', '.yaml']
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
                if not any(f.endswith(tuple(all_supported_exts)) for f in zip_ref.namelist()):
                    raise HTTPException(status_code=400, detail="No supported source files in zip")
                zip_ref.extractall(temp_dir)

            project_dir = temp_dir
            # Generate unique project key
            project_key = f"scan_{int(time.time())}_{uuid.uuid4().hex[:8]}"
            project_name = f"Scan_{filename}_{int(time.time())}"

            # Create SonarQube project
            api_base = f"{self.sonar_host_api}/api"
            auth_headers = {"Authorization": f"Bearer {self.sonar_token}"}
            create_project_url = f"{api_base}/projects/create"
            create_project_params = {
                "project": project_key,
                "name": project_name
            }
            create_resp = requests.post(create_project_url, headers=auth_headers, params=create_project_params)
            if create_resp.status_code != 200:
                raise HTTPException(status_code=500, detail=f"Failed to create project: {create_resp.text}")

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
            if any(f.endswith('.rb') for f in os.listdir(project_dir)):
                props_content += "sonar.ruby.file.suffixes=.rb\n"
            with open(props_path, "w") as props_file:
                props_file.write(props_content)

            # Run SonarScanner via Docker
            volume_mount = f"{os.path.abspath(project_dir)}:/usr/src"
            docker_cmd = [
                "docker", "run", "--rm", "--network=sonarqube-net",
                "-v", volume_mount,
                "-w", "/usr/src",
                "-e", f"SONAR_HOST_URL={self.sonar_host_scanner}",
                "-e", f"SONAR_TOKEN={self.sonar_token}",
                "sonarsource/sonar-scanner-cli:latest"
            ]
            result = subprocess.run(docker_cmd, capture_output=True, text=True, cwd=project_dir)
            if result.returncode != 0:
                raise HTTPException(status_code=500, detail=f"Scan failed: {result.stderr}\nOutput: {result.stdout}")

            # Wait for scan results
            for _ in range(10):
                issues_resp = requests.get(f"{api_base}/issues/search", headers=auth_headers, params={"componentKeys": project_key, "per_page": 10})
                if issues_resp.status_code == 200 and issues_resp.json().get("issues"):
                    break
                time.sleep(2)

            # Fetch measures
            measures_url = f"{api_base}/measures/component"
            measures_params = {
                "component": project_key,
                "metricKeys": "bugs,vulnerabilities,code_smells,coverage"
            }
            measures_resp = requests.get(measures_url, headers=auth_headers, params=measures_params)
            if measures_resp.status_code != 200:
                raise HTTPException(status_code=500, detail=f"Failed to fetch measures: {measures_resp.text}")

            measures = {}
            measures_data = measures_resp.json().get("component", {}).get("measures", [])
            for measure in measures_data:
                key = measure["metric"]
                value = measure.get("value")
                measures[key] = float(value) if value else None

            # Fetch issues
            issues_url = f"{api_base}/issues/search"
            issues_params = {"componentKeys": project_key, "per_page": 10}
            issues_resp = requests.get(issues_url, headers=auth_headers, params=issues_params)
            if issues_resp.status_code != 200:
                raise HTTPException(status_code=500, detail=f"Failed to fetch issues: {issues_resp.text}")

            issues_data = issues_resp.json().get("issues", [])
            issues = [
                {"key": i["key"], "message": i["message"], "severity": i["severity"]}
                for i in issues_data
            ]

            # Optionally delete project to avoid clutter
            delete_project_url = f"{api_base}/projects/delete"
            delete_project_params = {"project": project_key}
            delete_resp = requests.post(delete_project_url, headers=auth_headers, params=delete_project_params)
            if delete_resp.status_code != 204:
                print(f"Warning: Failed to delete project {project_key}: {delete_resp.text}")

            return ScanResult(
                bugs=int(measures.get("bugs", 0)),
                vulnerabilities=int(measures.get("vulnerabilities", 0)),
                code_smells=int(measures.get("code_smells", 0)),
                coverage=measures.get("coverage"),
                issues=issues
            )

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)