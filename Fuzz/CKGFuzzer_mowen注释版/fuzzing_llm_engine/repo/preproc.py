import os
import json
import shutil


def extract_api_from_file(src_api_file_path):
    api_list_path=os.path.join(src_api_file_path, 'api_list.json')
    api_summary_path=os.path.join(src_api_file_path, 'api_summary/api_with_summary.json')
    # 加载所有用户指定的 api
    with open(api_list_path, 'r') as f:
        api_list = json.load(f)
    # 加载之前提取的 api 信息
    with open(src_api_file_path+"/codebase/api/src_api.json", 'r') as f:
        src_api_data = json.load(f)

    api_file_dict = {}
    api_cnt = 0
    # 遍历非头文件获取所有函数名，判断是否属于 api_list ,属于则添加到 api_file_dict
    for key,value in src_api_data.items():  
        if key == "src":
            # src_key -> 文件路径
            for src_key,src_value in value.items():
                # api_file -> 文件名
                api_file = src_key.split('/')[-1]
                #api_file_dict[api_file] = {}
                apis = {}
                for key,value in src_value.items():
                    # 只提取函数定义列表
                    if key == "fn_def_list":
                        for api in value:
                            api_dict = {}
                            # 获取函数名
                            api_name = api["fn_meta"]["identifier"]
                            if api_name == '':
                                continue
                            # 如果存在于 api列表中 则添加
                            if api_name in api_list:
                                api_cnt += 1
                                apis[api_name] = ''
                if apis:
                    api_file_dict[api_file] = apis
    print(f"Total number of APIs in {src_api_file_path}: {api_cnt}")
    # 聚合 api 保存到 api_summary.json
    # Check if the directory exists, if not create it
    os.makedirs(os.path.dirname(api_summary_path), exist_ok=True)
    # Check if the file exists, if not create it
    if not os.path.exists(api_summary_path):
        with open(api_summary_path, "w", encoding='utf-8') as f:
            json.dump(api_file_dict, f, indent=2, sort_keys=True, ensure_ascii=False)  
    # Copy api_summary file to src_api_file_path/api_combine
    # 拷贝 api_summary.json 到 api_combine
    api_combine_dir = os.path.join(src_api_file_path, "api_combine")
    os.makedirs(api_combine_dir, exist_ok=True)
    shutil.copy2(api_summary_path, os.path.join(api_combine_dir, os.path.basename(api_summary_path)))
    print(f"Copied {api_summary_path} to {api_combine_dir}/{os.path.basename(api_summary_path)}")
    return api_file_dict

from bs4 import BeautifulSoup
import json
import os


def extract_api_list(src_api_path, file_name_path,head_or_src):
    # Load the JSON content

    api_list_file = os.path.join(src_api_path, "api_list.json")
    if os.path.exists(api_list_file):
        with open(api_list_file, 'r', encoding='utf-8') as f:
            api_list = json.load(f)
        print(f"Loaded {len(api_list)} APIs from {api_list_file}")
        return api_list
    
    else:
        with open(src_api_path+"/codebase/api/src_api.json", 'r', encoding='utf-8') as file:
            src_api_data = json.load(file)

        api_list = []

        # Get the absolute path of the target file

        # Check if the target file exists in the src_api_data
        if file_name_path in src_api_data[head_or_src]:
            file_content = src_api_data[head_or_src][file_name_path]
            
            # Extract API names from the target file
        for item in file_content.get('fn_def_list', []) + file_content.get('fn_declaraion', []):
            if 'fn_meta' in item and 'identifier' in item['fn_meta']:
                    api_name = item['fn_meta']['identifier']
                    if api_name == '':
                        continue
                    api_list.append(api_name)

        # Print the list of API names and its length
        for name in api_list:
            print(name)
        print(f"Total number of APIs in {os.path.basename(file_name_path)}: {len(api_list)}")

        return api_list


import json


def extract_fn_code(src_api_file_path):
    # 加载用户提供的 api_list.json
    api_list_path=os.path.join(src_api_file_path, 'api_list.json')
    with open(api_list_path, 'r') as f:
        api_list = json.load(f)
    # 创建 src/src_api_code.json 存储提取的 api code
    api_code_path = os.path.join(src_api_file_path, 'src/src_api_code.json')
    os.makedirs(os.path.dirname(api_code_path), exist_ok=True)
    # 加载repo中提取的 src_api.json
    with open(src_api_file_path+"/codebase/api/src_api.json", 'r') as f:
        src_api_data = json.load(f)
    # 提取code
    api_code_dict = {}
    api_name_list = []
    same_api_list = []
    api_code = ""
    api_cnt = 0
    for key,value in src_api_data.items():
        if key == "src":
            for src_key,src_value in value.items():
                api_file = src_key.split('/')[-1]
                for key,value in src_value.items():
                    if key == "fn_def_list":
                        for api in value:
                            api_name = api["fn_meta"]["identifier"]
                            api_code = api["fn_code"]
                            if api_name in api_list:
                                api_cnt += 1
                                api_code_dict[api_name] = api_code
  
    print(api_cnt)
    with open(api_code_path, 'w', encoding="utf-8") as f:
        json.dump(api_code_dict, f, indent=2, sort_keys=True, ensure_ascii=False)
    # Create the 'api_combine' directory if it doesn't exist
    api_combine_dir = os.path.join(src_api_file_path, 'api_combine')
    if not os.path.exists(api_combine_dir):
        os.makedirs(api_combine_dir)

    # Copy the api_code_path file to the api_combine directory
    destination_path = os.path.join(api_combine_dir, os.path.basename(api_code_path))
    shutil.copy2(api_code_path, destination_path)
    print(f"Copied {api_code_path} to {destination_path}")



import pandas as pd
import os
def combine_call_graph(src_api_file_path):
    # 获取用户提供的 api_list.json
    api_list_path=os.path.join(src_api_file_path, 'api_list.json')
    with open(api_list_path, 'r') as f:
        api_list = json.load(f)
    csv_folder_path = os.path.join(src_api_file_path, 'codebase/call_graph')
    csv_files = []
    # 遍历 codebase/call_graph 文件夹中所有以 .csv 结尾的文件
    # 根据用户提供的 api_list.json 来筛选出匹配的 CSV 文件 保存到 csv_files
    for file in os.listdir(csv_folder_path):
        if file.endswith('.csv'):
            # 通过特殊命名找到，api_name
            # api_name -> 文件中所有的函数命名
            api_name = file.split('@')[-1].split("_call_graph")[0]
            if api_name in api_list:
                print(f"Found matching API: {api_name}")
                csv_files.append(os.path.join(csv_folder_path, file))
    
    print(f"Number of matching CSV files: {len(csv_files)}")
    # 如果用户定义的 api 不存在，则返回None
    if not csv_files:
        print("No matching CSV files found. Check your api_list and csv_folder_path.")
        return None
    # 遍历需要的 CSV 文件，并读取到 data_frames 中
    data_frames = []
    for file in csv_files:
        df = pd.read_csv(file) # 读取 CSV 、返回值是 DataFrame
        if not df.empty:
            data_frames.append(df) 
        else:
            print(f"Warning: Empty CSV file: {file}")

    if not data_frames:
        print("All CSV files are empty. Check your CSV files.")
        return None
    # 多个 DataFrame 对象合并成一个单一的 DataFrame
    # ignore_index=True 拼接时重新生成索引
    combined_csv = pd.concat(data_frames, ignore_index=True)

    if combined_csv.empty:
        print("Combined DataFrame is empty. Check your CSV files and api_list.")
    else:
        print(f"Combined DataFrame shape: {combined_csv.shape}")
        print(combined_csv)
    # Create the 'api_combine' directory if it doesn't exist
    api_combine_dir = os.path.join(src_api_file_path, 'api_combine')
    if not os.path.exists(api_combine_dir):
        os.makedirs(api_combine_dir)
    # 将合并后的调用图数据（combined_csv）保存为一个新的 CSV 文件
    combined_csv.to_csv(api_combine_dir+'/'+'combined_call_graph.csv', index=False)


def find_call_graph_with_api(cg_file_path, api_name):
    data = pd.read_csv(cg_file_path)

  
    column1_name = 'caller'  
    column2_name = 'callee'  
    value_to_find = api_name  


    index = 0
    filtered_data = []
    for value in data[column1_name]:
        if value == value_to_find:
            api_cg = data.loc[index]
            filtered_data.append(api_cg)

        index += 1
    index = 0
    for value in data[column2_name]:
        if value == value_to_find:
            api_cg = data.loc[index]
            filtered_data.append(api_cg)

        index += 1
    #print(filtered_data)
    return filtered_data

import argparse

def setup_parser():
    parser = argparse.ArgumentParser(description="Process project-related files and generate API code summaries.")
    
    parser.add_argument('--project_name', required=True, help="Name of the project (e.g., c-ares).")
    parser.add_argument('--src_api_file_path', required=True, help="Path to the source API JSON file.")
   
    return parser

if __name__ == "__main__":
    parser = setup_parser()
    args =  parser.parse_args()

    src_api_file_path = args.src_api_file_path #"fuzzing_llm_engine/external_database/c-ares"
    # 合并 call_graph
    combine_call_graph(src_api_file_path)
    # 聚合 api 信息（文件名，函数名）
    extract_api_from_file(src_api_file_path)
    # 提取 api code
    extract_fn_code(src_api_file_path)

    
    





