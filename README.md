
# Local LLM Vulnerability Detector

## Overview
This project, developed by 0neand0nly (JohnJang), aims to assess how effectively a local LLM (Large Language Model) can identify potential vulnerabilities related to the top 10 CWE and CVEs. The project leverages two local LLMs, `llama3:70b-instruct` and `llama3:8b-instruct`, via Ollama.

## Requirements
- **Hardware**: Requires approximately 4 x 3090 GPUs (for llama3:70b-instruct) or 2 x 3090 GPUs (llama3:8b-instruct).
- **Python Libraries**:
  - `json`
  - `os`
  - `subprocess`
  - `sys`
  - `shutil`
  - `langchain_community`
  - `langchain_core`
  - `Ollama`

## Setup
1. **Clone the Repository**:
   ```bash
   git clone <repository_url>
   cd <repository_directory>
Install Dependencies:

bash
```
pip install -r requirements.txt
```
Environment Variables:
Ensure the following environment variables are set:

bash

export LANGCHAIN_TRACING_V2="true"

export LANGCHAIN_ENDPOINT="https://api.smith.langchain.com"

export LANGCHAIN_API_KEY="your_langchain_api_key"


Usage

Running the Project
```
bash
python <script_name>.py <project_name>
```
Replace <script_name> with the name of your Python script and <project_name> with the name of the project you want to analyze.

Main Functions

- setup_llm(): Initializes the local LLM and sets up the environment.

- query_llm(local_llm, chain, code_snippet): Queries the LLM to check for vulnerabilities in the provided code snippet.

- save_response(full_path, response, project_name): Saves the LLM response to a file.

- gather_commit_info(project_name): Gathers commit information from the Git repository.

- create_commit_file_dict(log_file_path): Creates a dictionary mapping commits to files.

- gather_files(commit_file_dict, project_name): Gathers the relevant files from the specified commits.

- read_file_query_gpt(commit_file_dict, project_name, local_llm, chain): Reads files and queries the LLM for each file.

- filter_response(project_name): Filters the responses to identify vulnerable files.

- filter_unique_files(project_name): Filters out duplicate files to identify unique vulnerable files.

