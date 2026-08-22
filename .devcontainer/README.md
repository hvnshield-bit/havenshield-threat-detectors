HavenShield devcontainer

- Python 3.11 image
- postCreateCommand installs pip requirements (pip install -r requirements.txt)
- VS Code extensions: Python, Pylance, GitLens, Docker, AutoDocstring

Notes:
- If you use Poetry or Pipenv, update postCreateCommand accordingly.
- Adjust forwardPorts and installed system packages as needed for your workflow.
