# PyPI Vulnerability Analyzer

This project analyzes vulnerabilities in the Python Package Index (PyPI) ecosystem.  
It gathers data on popular packages, builds their dependency graphs, and checks each dependency against public vulnerability databases.

---

## Features

- Fetches usage statistics of PyPI packages (via Google BigQuery)  
- Builds dependency graphs using the PyPI API  
- Checks for known vulnerabilities using the OSV (Open Source Vulnerabilities) API  
- Retrieves additional metadata from the GitHub API for vulnerable repositories  

---

## Setup Instructions

### 1. Clone this repository

```bash
git clone https://github.com/your-username/pypi-vulnerability-analyzer.git
cd pypi-vulnerability-analyzer
```

### 2. Activate virtual env
```bash
python3 -m venv venv
source venv/bin/activate       # on Linux/Mac
venv\Scripts\activate          # on Windows
```

### 3. Install requirements
```bash
pip install -r requirements.txt
```

### 4. To avoid GitHub API rate limits, you must provide a personal access token.
```bash
export GITHUB_TOKEN="your_token_here"       # Linux/Mac
setx GITHUB_TOKEN "your_token_here"         # Windows (persistent)
```

### 5. Run the project
```bash
python main.py
```
