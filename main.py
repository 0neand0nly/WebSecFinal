'''
This project is developed by 0neand0nly (JohnJang).
The main goal for this project is to observe how well the local llm can identify potential vulnerabilities that are related to top 10 CWE of CVEs
You can run two kinds of local llm which is the llama3:70b-instruct and llama3 via Ollama.
In order to run models it requires about 4 X 3090 GPU or 2 X 3090.

'''
import json
import os
import subprocess
import sys
import shutil


from langchain_community.llms import Ollama
from langchain_core.output_parsers import StrOutputParser
from langchain.prompts import (
    ChatPromptTemplate, 
    MessagesPlaceholder,
    HumanMessagePromptTemplate,
    SystemMessagePromptTemplate,
    AIMessagePromptTemplate,
)

model_id = "llama3:70b-instruct"
# model_id = "llama3"

def setup_llm():
    
    local_llm = Ollama(model=model_id, temperature=0)
    
    #https://www.getastra.com/blog/security-audit/top-vulnerabilities/
    
    
   
    
    
    PREFIX = """
    You are going to be vulnerability detector.
    
    See if the user provided code contains any top 10 CWE(Common Weakness Enumeration) or CVE(Common Vulnerabilities and Exposure) related issues.
    
    """
   

    system_message_prompt = SystemMessagePromptTemplate.from_template(PREFIX)
    
    chat_prompt = ChatPromptTemplate.from_messages([
        system_message_prompt,
        ("user", "{user_input}")
    ])
    
    chain = chat_prompt | local_llm | StrOutputParser()
    
    return local_llm, chain

def query_llm(local_llm, chain, code_snippet):
    SUFFIX="""
    See if the user provided code contains any top 10 CWE(Common Weakness Enumeration) or CVE(Common Vulnerabilities and Exposure) related issues.
    
    If you observe vulnerabilities please point out the most suspicious CWE of CVE number and state the reason
    
    If you cannot find any vulnerabilities or security concerns just say "Vulnerability Not found" no need to explain further
    
    
    The top 10 CVE lists are:
    
    1. ZeroLogon (CVE-2020-1472)
    2. Log4Shell (CVE-2021-44228)
    3. ICMAD (CVE-2022-22536)
    4. ProxyLogon (CVE-2021-26855)
    5. Spring4Shell (CVE-2022-22965)
    6. Atlassian Confluence RCE (CVE-2022-26134)
    7. VMware vSphere (CVE-2021-21972)
    8. Google Chrome Zero-Day (CVE-2022-0609)
    9. Follina (CVE-2022-30190)
    10. PetitPotam (CVE-2021-36942)
    
    
    The Top 10 CWE lists are : 
    
    1	CWE-416	Use After Free
    2	CWE-122	Heap-based Buffer Overflow
    4	CWE-20	Improper Input Validation	
    5	CWE-78	Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')	
    6	CWE-502	Deserialization of Untrusted Data	
    7	CWE-918	Server-Side Request Forgery (SSRF)	
    8	CWE-843	Access of Resource Using Incompatible Type ('Type Confusion')	
    9	CWE-22	Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')	
    10	CWE-306	Missing Authentication for Critical Function
    """
    
    response = chain.invoke({"user_input": f"{code_snippet} \n {SUFFIX}"})
    print(response)
    
    return response


def save_response(full_path,response,project_name):
    relative_path = full_path.replace(f"./data/{project_name}/", "")
    text_file_name=relative_path.replace(".java",".txt").replace("/","_")
    
    response_dir = f"./response/{project_name}"
    response_path=os.path.join(response_dir,text_file_name)
    
    
    with open(response_path,"w") as response_file:
        response_file.write(response)
    
    


    

def gather_commit_info(project_name):
    log_file_name = f"{project_name.replace('/', '_').replace(':', '')}_mapping.txt"
    log_file_path = os.path.join(project_name, log_file_name)
    command = (
        f"cd {project_name} && "
        f"git log --since='2023-01-01' --until='2024-06-10' --pretty=format:'%H' --name-only | "
        f"awk 'NF{{print $0 \"\t\"}}' | sed 's/^\\t//' > {log_file_name}"
    )
    
    if not os.path.exists(log_file_path):
        print(f"Generating log file at: {log_file_path}")
        subprocess.run(command, shell=True, check=True)
    else:
        print(f"Log file already exists at: {log_file_path}")
    
    return log_file_path

def create_commit_file_dict(log_file_path):
    with open(log_file_path, "r") as log_file:
        data = log_file.read()
    
    lines = data.split("\n")
    commit_file_dict = {}
    current_commit = None
    
    for line in lines:
        if line.strip():  # If the line is not empty
            if not line.startswith('h2/'):  # If the line is a commit hash
                current_commit = line.strip()
                if current_commit not in commit_file_dict:
                    commit_file_dict[current_commit] = []
            else:  # If the line is a file path
                if current_commit:
                    if ".java" in line:
                        commit_file_dict[current_commit].append(line.strip())
    
    return commit_file_dict

def gather_files(commit_file_dict, project_name):
    data_dir_path = f"./data/{project_name}"
    project_path = f"./{project_name}"
    
    if not os.path.exists(data_dir_path):
        os.makedirs(data_dir_path)
    
    for hash_val, files in commit_file_dict.items():
        commited_dir_path = os.path.join(data_dir_path, hash_val)
        if not os.path.exists(commited_dir_path):
            os.makedirs(commited_dir_path)
        
        checkout_cmd = f"git checkout {hash_val}"
        subprocess.run(checkout_cmd, cwd=project_path, shell=True, check=True)
        
        for file_path in files:
            full_file_path = os.path.join(project_path, file_path)
            if os.path.exists(full_file_path):
                print(f"Copying {full_file_path} to {commited_dir_path}")
                shutil.copy(full_file_path, commited_dir_path)
            else:
                print(f"File {full_file_path} does not exist.")

def read_file_query_gpt(commit_file_dict, project_name, local_llm, chain):
    data_dir_path = f"./data/{project_name}"
    i = 1
    total_files_count = sum(len(files) for files in commit_file_dict.values())
    print(total_files_count)
    for hash_val, files in commit_file_dict.items():
        for file in files:
            file_name = file.split("/")[-1]
            file_path = os.path.join(hash_val, file_name)
            full_path = os.path.join(data_dir_path, file_path)
            if os.path.exists(full_path):
                if os.path.getsize(full_path) <= 70 * 1024:
                    with open(full_path, "r") as java_file:
                        code_snippet = java_file.read()
                    print("Querying: " + full_path)
                    response = query_llm(local_llm, chain, code_snippet)
                    save_response(full_path, response, project_name)
                    print(f"Progress : {i} / {total_files_count} ")
                    i += 1
                else:
                    print(f"File {full_path} exceeds the size limit.")
            else:
                print(f"File {full_path} does not exist.")

def filter_response(project_name):
    response_dir = f"./response/{project_name}"
    vulnerable_files = []
    ignore_phrases = [
        "vulnerability not found",
        "after analyzing the provided code, i did not find",
        "after analyzing the provided java code, i did not find",
        "please provide the code,",
        "i'm ready to analyze the user-provided code. please provide the code, and i'll check it for any potential vulnerabilities related to the top 10 cwe or cve lists.",
        "please paste the code, and i'll get started!"
    ]

    for root, dirs, files in os.walk(response_dir):
        for file in files:
            if file.endswith(".txt"):
                file_path = os.path.join(root, file)
                with open(file_path, "r") as f:
                    content = f.read().lower()
                    if not any(phrase in content for phrase in ignore_phrases):
                        vulnerable_files.append(file_path)

    total_responses = len([file for file in files if file.endswith(".txt")])
    vul_response_dir = f"./response/vulnerable_responses/{project_name}"
    os.makedirs(vul_response_dir, exist_ok=True)
    counter = 0
    total_vul_files = len(vulnerable_files)
    
    print(f"Number of Vulnerable Responses: {total_vul_files} / {total_responses}")
    
    for vulnerable_file in vulnerable_files:
        dest_path = os.path.join(vul_response_dir, os.path.basename(vulnerable_file))
        shutil.copy(vulnerable_file, dest_path)
        print(f"Copied {vulnerable_file} to {dest_path}")
        counter += 1
    print(f"Number of Files copied: {counter} / {total_vul_files}")
        
    return total_responses, total_vul_files

def filter_unique_files(project_name):
    vul_response_dir = f"./response/vulnerable_responses/{project_name}"
    duplicate_dir = f"./response/vulnerable_responses/{project_name}/duplicated_files"
    os.makedirs(duplicate_dir, exist_ok=True)  # 중복된 파일을 저장할 디렉토리를 생성합니다.

    unique_file_names = []
    duplicate_file_names = []
    seen_file_names = set()

    for root, dirs, files in os.walk(vul_response_dir):
        for file in files:
            file_name_part = file.split("_")[-1]
            full_file_path = os.path.join(root, file)
            if file_name_part in seen_file_names:
                duplicate_file_names.append(file)
                shutil.move(full_file_path, os.path.join(duplicate_dir, file))  # 중복된 파일을 이동합니다.
            else:
                unique_file_names.append(file_name_part)
                seen_file_names.add(file_name_part)

    print(f"Unique file names: {len(unique_file_names)}")
    for file_name in unique_file_names:
        print(file_name)

    print(f"\nDuplicate file names: {len(duplicate_file_names)}")
    for file_name in duplicate_file_names:
        print(file_name)

    return unique_file_names, duplicate_file_names


if __name__ == '__main__':
    project_name = sys.argv[1]
    
    
    
    log_file_path = gather_commit_info(project_name)
    commit_file_dict = create_commit_file_dict(log_file_path)
    gather_files(commit_file_dict, project_name)
   
    local_llm, chain = setup_llm()
    read_file_query_gpt(commit_file_dict,project_name,local_llm, chain)
    
    total_responses,total_vul_files=vulnerable_files = filter_response(project_name)
    unique_files, duplicate_files = filter_unique_files(project_name)
    
    print(f"Total number of suspicious files: {total_vul_files} / {total_responses}  rate: {(total_vul_files / total_responses) * 100:.2f} %")
    print(f"Total number of suspicious unique files: {len(unique_files)} / {total_responses}  rate: {(len(unique_files) / total_responses) * 100:.2f} %")
   
    
    
