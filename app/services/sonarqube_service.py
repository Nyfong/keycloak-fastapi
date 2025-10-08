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

        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, filename)
        try:
            # Save and extract zip
            with open(zip_path, "wb") as f:
                f.write(file)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                if not zip_ref.namelist():
                    raise HTTPException(status_code=400, detail="Zip file is empty")
                if not any(f.endswith(('.py', '.java', '.js', '.cpp')) for f in zip_ref.namelist()):
                    raise HTTPException(status_code=400, detail="No supported source files in zip")
                zip_ref.extractall(temp_dir)
            
            project_dir = temp_dir
            project_key = "static_upload"  # Pre-created project
            project_name = "Static Upload"
            
            # Create sonar-project.properties
            props_path = os.path.join(project_dir, "sonar-project.properties")
            with open(props_path, "w") as props_file:
                props_file.write(f"""
sonar.projectKey={project_key}
sonar.projectName={project_name}
sonar.sources=.
sonar.host.url={self.sonar_host_scanner}
sonar.token={self.sonar_token}
""")
            
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
                raise HTTPException(status_code=500, detail=f"Scan failed: {result.stderr}")

            # Wait for scan results
            api_base = f"{self.sonar_host_api}/api"
            auth_headers = {"Authorization": f"Bearer {self.sonar_token}"}
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