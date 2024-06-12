import json
import os
import subprocess
import sys

#from langchain.chat_models import ChatOpenAI
from langchain_community.llms import Ollama
from langchain.agents import AgentExecutor, initialize_agent, AgentType, Tool, create_react_agent
from langchain.schema import HumanMessage, SystemMessage

from langchain.prompts import (
    ChatPromptTemplate, 
    MessagesPlaceholder,
    HumanMessagePromptTemplate,
    SystemMessagePromptTemplate,
    AIMessagePromptTemplate,
)

model_id = "llama3:70b-instruct"

def setup_llm():
    # local_llm = ChatOpenAI(
    #     api_key="ollama",
    #     model=model_id,
    #     base_url="http://localhost:11434/v1",
    #     temperature=0
    # )
    
    local_llm = Ollama(model=model_id, temperature=0)
    os.environ["LANGCHAIN_TRACING_V2"]="true"
    os.environ["LANGCHAIN_ENDPOINT"]="https://api.smith.langchain.com"
    os.environ["LANGCHAIN_API_KEY"]="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"
    os.environ["LANGCHAIN_PROJECT"]="web_sec_final"
    
    PREFIX = """
    You are an helpful AI assistant provide answers based on your knowledge and always try your best to do so
    """
    
    '''tools =[]
    system_message_prompt = SystemMessage(PREFIX)
    
    agent = create_react_agent(local_llm, tools, system_message_prompt)
    agent_executor = AgentExecutor(
        agent = agent,
        tools=tools,
        verbose=True,
        return_intermediate_steps=True,
        handle_parsing_errors=True
    )'''
    system_message_prompt = SystemMessagePromptTemplate.from_template(PREFIX)
    chat_prompt = ChatPromptTemplate.from_messages([
        system_message_prompt,
        ("user", "{user_input}"),
    ])
    
    chain = chat_prompt | local_llm
    
    return local_llm, chain

def query_llm(local_llm, chain):
    
    response = chain.invoke({"user_input": "What is the latests date of information you are trained with"})
    print(response)


    

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
                    commit_file_dict[current_commit].append(line.strip())
    
    return commit_file_dict

def gather_files(commit_file_dict, project_name):
    
    data_dir_path = f"./data/{project_name}"
    project_path = f"./{project_name}"
    
    subprocess.run(f"cd {project_path}", shell=True, check=True)
    
    commit_file_dict.
    
    if not os.path.exists(data_dir_path):
        os.mkdir(data_dir_path)
    
    


if __name__ == '__main__':
    project_name = sys.argv[1]
    
    
    
    log_file_path = gather_commit_info(project_name)
    commit_file_dict = create_commit_file_dict(log_file_path)
    
    # 출력이나 다른 작업을 추가할 수 있습니다.
    print(json.dumps(commit_file_dict, indent=4))
    
    local_llm, chain = setup_llm()
    query_llm(local_llm,chain)
    
    
