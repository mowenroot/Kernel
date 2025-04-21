from loguru import logger
from collections import defaultdict
import json
import networkx as nx
import os
from concurrent.futures import ThreadPoolExecutor
import glob
import pandas as pd
from collections import defaultdict
import re
import json
import os
import tqdm
import chardet

def convert_json_to_function_signature(fn_meta):     
    function_signature = fn_meta.split("{")[0].strip()
    function_signature = " ".join(function_signature.split())
    params = extract_function_arguments(function_signature)
    params_types = {}
    for p in params:
        params_types[p.split()[-1]] = p.split()[0]
    name = function_signature.split("(")[0].split()[-1]
    return function_signature.strip(), params_types,name


def isContainingLabel(label_list_1, label_list_2):
    if isinstance(label_list_1, list):
        joined_list = set(label_list_1).intersection(set(label_list_2))
    else:
        if label_list_1 in label_list_2:
            return [label_list_1]
        else:
            return []
    return list(joined_list)


def isNaN(num):
    return num != num
    
def extract_function_arguments(signature):
    # This regular expression matches the arguments within the parentheses
    # It assumes that the signature is provided in a cleaned format without leading/trailing spaces
    match = re.search(r'\((.*?)\)', signature)
    if match:
        arguments = match.group(1)  # Extract the contents within the parentheses
        if arguments.strip():  # Check if there are arguments and not just empty space
            # Split the arguments by comma and strip whitespace from each argument
            return [arg.strip() for arg in arguments.split(',')]
        else:
            return []  # No arguments
    return []  # Return empty list if no parentheses are found or other issues


def fix_file_path(file_path):
    return file_path.replace("./docker_shared/source_code/", "./docker_shared/source_code/")


class CodeRepository:
    def __init__(self, project_name) -> None:
        self.graphs = None
        self.struct_def = None
        self.typdef_struct_alias = None
        self.enum_def = None
        self.typdef_enum_alias = None
        self.file_id_mapping = None
        self.fn_def = None
        self.call_relationship = None
        self.project_name = project_name
    
    def query_struct(self, name):
        result = []
        query_name = name
        if name in  self.typdef_struct_alias:
            query_name = self.typdef_struct_alias[name]
            
        if query_name in self.struct_def:
            struct_info = self.struct_def[query_name]
            parameters = struct_info['parameters'] 
            result.append( struct_info )
            for v, k in parameters.items():
                k = k.replace("*", "").strip() 
                struct_list = self.query_struct(k)
                result += struct_list
        return result
    
    def query_enum(self, name):
        result = []
        query_name = name
        if name in  self.typdef_enum_alias:
            query_name = self.typdef_enum_alias[name]
            
        if query_name in self.enum_def:
            enum_info = self.enum_def[query_name]
            parameters = enum_info['parameters'] 
            result.append( enum_info )
            for v, k in parameters.items():
                k = k.replace("*", "").strip() 
                struct_list = self.query_struct(k)
                result += struct_list
        return result
    
    def query_source_file(self, file_id):
        if file_id not in self.file_id_mapping:
            for fid, v in self.file_id_mapping.items():
                if file_id == os.path.basename(fid):
                    return v['code']
        else:
            return self.file_id_mapping[file_id]['code']
    
    def query_function(self, file_id, method_name):
        method_id = f"{file_id}-{method_name}"
        if method_id in self.fn_def:
            return self.fn_def[method_id]
        else:
            method_id = os.path.basename(method_id)
            for k in self.fn_def:
                if method_id == os.path.basename(k):
                    return self.fn_def[k]
        return None    
    
    def process_source_files(self, code_data, exclude_folders):

        fn_def_list_node_list = [ ]
        global_var_node_list = []
        struct_node_list = []
        enum_node_list = []
        # Patch
        api_path = list(code_data.keys())[0]
        api_path_prefix_len = api_path.find(f"{self.project_name}") + len(f"{self.project_name}")
        api_path_prefix = api_path[:api_path_prefix_len]
        logger.debug(f"{api_path_prefix}")
        for fname in code_data:
            values = code_data[fname]
            fn_def_list = values["fn_def_list"] # List of function definitions, Method Nodoes
            struct_list = values["struct_node_list"] # List of struct definitions, Struct Nodes
            include_list = values["include_list"] # include relationship between file and method
            global_varibales = values["global_variables"]
            # fn_declaraion = values["fn_declaraion"]
            enum_declaration = values["enumerate_node_list"]
            # remmove the shared folder name
            # Patch
            # fid = fname.replace(f"../docker_shared/source_code/{self.project_name}", "")    
            fid = fname.replace(api_path_prefix, "")
            if os.path.dirname(fid) in exclude_folders:
                continue 

            for i, fdef in enumerate(fn_def_list):
                fn_code = fdef['fn_code'].strip()
                fn_meta = fdef['fn_meta']
                fn_name = fn_meta['identifier']
                parameters = fn_meta['parameters']
                meta_node_info = {"id":f"{fid}-{fn_name}", "fid":fid, "project": self.project_name, "code":fn_code, "name":fn_name, "parameters": parameters} 
                fn_def_list_node_list.append(meta_node_info)

            for gi, gv in enumerate(global_varibales):
                meta_gnode_info = {id:f"{fid}-g-{gi}", "code":gv, "name":gi,  "project": self.project_name, "fid":fid}
                global_var_node_list.append(meta_gnode_info)
              
            for s in struct_list:
                struct_body = s[0]
                struct_parameters = s[1]
                struc_name = s[2]
                struct_id = f"{fid}-{struc_name}"
                meta_struct_node_info = {"id":struct_id, "name":struc_name, "fid":fid,"parameters":struct_parameters, "code":struct_body}
                struct_node_list.append(meta_struct_node_info)
            
            # 添加  enum
            for e in enum_declaration:
                enum_body = e[0]
                enum_parameters = e[1]
                enum_name = e[2]
                enum_id = f"{fid}-{enum_name}"
                meta_enum_node_info = {"id":enum_id, "name":enum_name, "fid":fid, "parameters":enum_parameters, "code":enum_body}
                enum_node_list.append(meta_enum_node_info)
                
        
            
        return fn_def_list_node_list, global_var_node_list, struct_node_list, enum_node_list


    def query_graph(self, file_id, method_name, edge_type_list):
        methods_graph_in_file = self.graphs[file_id]['methods']
        method_id = f"{file_id}-{method_name}"
        edges_filtered = {}
        nodes_filtered = {} 
        line_number_dict ={}
        if method_id in methods_graph_in_file:
            file_code = self.file_id_mapping[file_id]['code']
            codelines = file_code.split("\n")
            graph_data = methods_graph_in_file[method_id] 
            edges = graph_data['edge']
            nodes = graph_data['node']
            for (u, v), edge_attr in edges.items():
                labels_edge = edge_attr['label']
                confirmed_labels = isContainingLabel(labels_edge, edge_type_list)
                if len(confirmed_labels):
                        edges_filtered[(u, v)] = edge_attr
                        if "LINE_NUMBER"  in nodes[u]:
                            nodes[u]["CODE"] = codelines[ int(nodes[u]["LINE_NUMBER"])-1 ] #meta__node_info[u]["code"]
                            line_number_dict[u] = int(nodes[u]["LINE_NUMBER"])
                        if "LINE_NUMBER"  in nodes[v]:
                            nodes[v]["CODE"] = codelines[ int(nodes[v]["LINE_NUMBER"])-1 ] #meta__node_info[v]["code"]
                            line_number_dict[v] = int(nodes[v]["LINE_NUMBER"])
                        nodes_filtered[u] = nodes[u]
                        nodes_filtered[v] = nodes[v]
        return edges_filtered, nodes_filtered, line_number_dict
    
    # 构建代码图中的各种节点信息（函数、结构体、枚举、文件等）。   
    def construct_nodes_fn_doc(self, api_data, exclude_folders = []):
        '''
            构建代码图中的各种节点信息（函数、结构体、枚举、文件等）。

            节点ID的格式:
                - project_name/file_path-method_name-param_name
                - project_name/file_path-struct_name-param_name  
                - project_name/file_path-method_name-statement_id

            参数：
                - api_data: 包含源代码和头文件信息的字典，格式：
                    {
                        "src": {文件路径: 函数定义},
                        "head": {头文件路径: 函数定义}
                    }
                - exclude_folders: 排除分析的文件夹列表

            返回：
                - file_id_dict: 文件节点的元数据字典
                - (struct_def, typdef_struct_alias): 结构体定义和typedef结构体别名映射
                - (enum_def, typdef_enum_alias): 枚举定义和typedef枚举别名映射
                - fn_dec: 函数定义信息字典
        '''
        source_code = api_data["src"]
        header_code = api_data["head"]
        # Patch 
        api_path = list(source_code.keys())[0]
        api_path_prefix_len = api_path.find(f"{self.project_name}") + len(f"{self.project_name}")
        api_path_prefix = api_path[:api_path_prefix_len]
        file_id_dict = {}
        # 遍历 project/codebase/api/src_api.json 中所有 keys -> 构造文件节点的元数据字典 file_id_dict
        for idx, all_files in enumerate([list(source_code.keys()), list(header_code.keys()) ]):
            for fname in all_files:
                logger.info(f"Processing file: {fname}")
                # 读取文件内容，做了编码处理
                try:
                    with open(fix_file_path(fname), "r", encoding='utf-8') as f:
                        file_code = f.read()
                except UnicodeDecodeError:
                    with open(fix_file_path(fname), "rb") as f:
                        raw_data = f.read()
                    detected_encoding = chardet.detect(raw_data)['encoding']
                    logger.info(f"Detected encoding for {fname}: {detected_encoding}")
                    try:
                        file_code = raw_data.decode(detected_encoding)
                    except:
                        logger.error(f"Failed to decode {fname} with detected encoding {detected_encoding}. Skipping this file.")
                        continue
                # Patch 
                #fid = fname.replace(f"../docker_shared/source_code/{self.project_name}", "")
                fid = fname.replace(api_path_prefix, "")
                # 构建该文件的节点元数据
                metadata_file_node = { "id":fid, "file_name":os.path.basename(fname), "file_path":fid, "project":self.project_name, "code":file_code}
                file_id_dict[fid] = metadata_file_node
                  
        # 提取源代码中的函数定义、全局变量、结构体、枚举节点          
        src_fn_def_list_list, src_global_var_node_list, src_struct_node_list, src_enum_node_list = self.process_source_files(source_code, exclude_folders)
        
        head_fn_def_list_list, head_global_var_node_list, head_struct_node_list, head_enum_node_list = self.process_source_files(header_code, exclude_folders)
        
        ### 构建结构体定义与 typedef 映射 ###
        struct_def = {} # struct 名字 -> struct 定义节点
        typdef_struct_alias = {}  # struct typedef别名 -> 原始 struct 名
        # struct_declar = {}
        for struct in head_struct_node_list + src_struct_node_list:
            if len(struct['name'].strip()) != 0 and len(struct['parameters']) != 0:
                struct_def[struct['name']] = struct # 有名且有字段的定义
            else:
                # 处理 typedef struct 形式
                if struct["code"].startswith("typedef"):
                    alias_name, name = struct["code"].split()[-1], struct["code"].split()[-2]
                    typdef_struct_alias[alias_name] = name
        # 与 struct 逻辑一致
        enum_def =  {}
        typdef_enum_alias = {}
        # enum_declar = {}
        for enum in head_enum_node_list + src_enum_node_list:
            if len(enum['name'].strip()) != 0 and len(enum['parameters']) != 0:
                enum_def[enum['name']] = enum
            else:
                if enum["code"].startswith("typedef"):
                    alias_name, name = enum["code"].split()[-1], enum["code"].split()[-2]
                    typdef_enum_alias[alias_name] = name
        
        fn_dec = {}
        for fdef in src_fn_def_list_list + head_fn_def_list_list:
            fn_dec[ f"{fdef['fid']}-{fdef['name']}"] = fdef # 文件id-函数名 -> 函数定义
                     
        return file_id_dict, (struct_def, typdef_struct_alias), (enum_def, typdef_enum_alias), fn_dec
    
    def save_data(self, output_dir="./external_database/c-ares/data_structure_graphs"):
        json.dump(self.graphs, open(os.path.join(output_dir, f"graphs.json"), "w"), indent=2)
        json.dump(self.struct_def, open(os.path.join(output_dir, f"struct_def.json"), "w"), indent=2)
        json.dump(self.typdef_struct_alias, open(os.path.join(output_dir, f"typdef_struct_alias.json"), "w"), indent=2)
        json.dump(self.enum_def, open(os.path.join(output_dir, f"enum_def.json"), "w"), indent=2)
        json.dump(self.typdef_enum_alias, open(os.path.join(output_dir, f"typdef_enum_alias.json"), "w"), indent=2)
        json.dump(self.file_id_mapping, open(os.path.join(output_dir, f"file_id_mapping.json"), "w"), indent=2)
        json.dump(self.fn_def, open(os.path.join(output_dir, f"fn_def.json"), "w"), indent=2)
        json.dump(self.call_relationship, open(os.path.join(output_dir, f"call_relationship.json"), "w"), indent=2)
        
        
    def construct_call_repationship(self, call_graph_folder, exclude_folders = []):
        '''Code Node Relationship - Calling Relationship'''
        call_relationship = defaultdict(list)
        logger.info("Construct method call relationship")
        for call_graph_file in tqdm.tqdm(glob.glob(f"{call_graph_folder}/**/*.csv",recursive=True)):
            data =pd.read_csv(call_graph_file)
            rows = data.to_dict(orient='records')
            for r in rows:
                caller = r["caller"]
                callee = r["callee"]
                caller_src = r["caller_src"]
                callee_src = r["callee_src"]
                if isNaN(caller_src) or isNaN(callee_src):
                    continue
                if os.path.dirname(caller_src)  in exclude_folders or os.path.dirname(callee_src) in exclude_folders:
                    continue
                # print(caller_src)
                # print(callee_src)
                # print(r)
                caller_src = re.sub("/src/", "", caller_src, count=1)
                callee_src = re.sub("/src/", "", callee_src, count=1)
                caller_id = f"{caller_src}-{caller}"
                callee_id = f"{callee_src}-{callee}"
                r["caller_id"] = caller_id
                r["callee_id"] = callee_id
                call_relationship[caller_id].append(r)
        return call_relationship
                
def process_dot_file(method_grph_cpg_folder, fname_path, gname, dot_folder, dot_file):
    src_head_file_name = dot_folder
    tsrcfname = src_head_file_name.replace(".", "-")
    fid_path_part = fname_path.replace(tsrcfname, "").replace("-", "/")
    fid = os.path.join(fid_path_part, src_head_file_name)
    
    method_name = dot_file.replace(".dot", "")
    mid = f"{fid}-{method_name}"
    dot_path_file = os.path.join(method_grph_cpg_folder, fname_path, gname, dot_folder, dot_file)
    try:
        G = nx.nx_pydot.read_dot(dot_path_file)
    except:
        return None, None, {"node": None, "edge": None}
    print(f"{mid} G nodes {len(G.nodes)} before")
    # merged_G = merge_duplicate_nodes(G)
    print(f"G nodes {len(G.nodes)} After")
    node_dict = {node: attr for node, attr in G.nodes(data=True)}
    edge_dict = {(u, v): attrs for u, v, attrs in G.edges(data=True)}
    return fid, mid, {"node": node_dict, "edge": edge_dict}

def contruct_method_analysis_graph(method_grph_cpg_folder, gname="cpg"):
    results = {}
    logger.info("construct method cpg graphs")
    for fname_path in tqdm.tqdm(os.listdir(method_grph_cpg_folder)):
        res = {}
        meta_info_file = os.path.join(method_grph_cpg_folder, fname_path, gname, "meta.json")
        meta_info = json.load(open(meta_info_file, "r"))
        res["meta"] = meta_info
        src_head_file_name = ""
        method_graph_map = {}
        for dot_folder in os.listdir(os.path.join(method_grph_cpg_folder, fname_path, gname)):
            if dot_folder in ["<empty>", "<includes>", "meta.json"]:
                continue
            src_head_file_name = dot_folder
            tsrcfname = src_head_file_name.replace(".", "-")
            fid_path_part = fname_path.replace(tsrcfname, "").replace("-", "/")
            fid = os.path.join(fid_path_part, src_head_file_name)
            dot_files = os.listdir(os.path.join(method_grph_cpg_folder, fname_path, gname, dot_folder))
            with ThreadPoolExecutor(max_workers=15) as executor:
                futures = [executor.submit(process_dot_file, method_grph_cpg_folder, fname_path, gname, dot_folder, file) for file in dot_files if file.endswith(".dot")]
                for future in futures:
                    _, mid, graph_data = future.result()
                    if mid is None:
                        continue
                    method_graph_map[mid] = graph_data
            res["methods"] = method_graph_map
            res["fid"] = fid
            results[fid] = res
    return results
          

def get_codebase(src_api_file, project_name="c-ares", exclude_folder_list=["c-ares/src/tools"]) -> CodeRepository:
    method_code = json.load(open(src_api_file, "r"))
    pkg = CodeRepository(project_name)

    file_id_dict, (struct_def, typdef_struct_alias), (enum_def, typdef_enum_alias), fn_def = pkg.construct_nodes_fn_doc(method_code, exclude_folders=exclude_folder_list)
    pkg.file_id_mapping = file_id_dict
    pkg.struct_def = struct_def
    pkg.typdef_struct_alias = typdef_struct_alias
    pkg.enum_def = enum_def
    pkg.typdef_enum_alias = typdef_enum_alias
    pkg.fn_def = fn_def
    pkg.graphs = [] #graphs

    return pkg
    
    
    