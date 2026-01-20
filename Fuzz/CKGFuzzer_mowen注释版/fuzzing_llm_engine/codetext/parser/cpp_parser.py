from typing import List, Dict, Any
import re
import tree_sitter
import logging

from .language_parser import LanguageParser, get_node_text, get_node_by_kind
from ..utils import get_language,generate_hash_code

logger = logging.getLogger(name=__name__)


class CppParser(LanguageParser):
    
    BLACKLISTED_FUNCTION_NAMES = ['main', 'constructor']
    
    @staticmethod
    def get_docstring(node, blob=None):
        """
        Get docstring description for node
        
        Args:
            node (tree_sitter.Node)
            blob (str): original source code which parse the `node`
        Returns:
            str: docstring
        """
        if blob:
            logger.info('From version `0.0.6` this function will update argument in the API')
        docstring_node =  CppParser.get_docstring_node(node)
        docstring = '\n'.join(get_node_text(s) for s in docstring_node)
        return docstring
    
    @staticmethod
    def get_docstring_node(node):
        """
        Get docstring node from it parent node.
        C and C++ share the same syntax. Their docstring usually is 1 single block
        Expect length of return list == 1
        
        Args:
            node (tree_sitter.Node): parent node (usually function node) to get its docstring
        Return:
            List: list of docstring nodes (expect==1)
        Example:
            str = '''
                /**
                * Find 2 sum
                *
                * @param nums List number.
                * @param target Sum target.
                * @return postion of 2 number.
                */
                vector<int> twoSum(vector<int>& nums, int target) {
                    ...
                }
            '''
            ...
            print(CppParser.get_docstring_node(function_node))
            
            >>> [<Node type=comment, start_point=(x, y), end_point=(x, y)>]
        """
        docstring_node = []
        
        prev_node = node.prev_sibling
        if prev_node and prev_node.type == 'comment':
            docstring_node.append(prev_node)
            prev_node = prev_node.prev_sibling

        while prev_node and prev_node.type == 'comment':
            # Assume the comment is dense
            x_current = prev_node.start_point[0]
            x_next = prev_node.next_sibling.start_point[0]
            if x_next - x_current > 1:
                break
            
            docstring_node.insert(0, prev_node)    
            prev_node = prev_node.prev_sibling
        
        return docstring_node
    
    @staticmethod
    def get_function_list(node):
        res = get_node_by_kind(node, ['function_definition'])
        return res
    
    @staticmethod
    def get_function_declarator_list(node):
        res = get_node_by_kind(node, ['function_declarator'])
        res = [n  for n in res if CppParser.isFunctionDeclaration(n)]
        res = [CppParser.isTemplateFnDec(n)[1]  for n in res]
        return res
    
    @staticmethod
    def isFunctionDeclaration(node):

        assert node.type == 'function_declarator'
        if node.parent.type == 'function_definition':
            return False
        return True

    @staticmethod
    def isTemplateFnDec(node):

        assert node.type == 'function_declarator'
        if node.parent is not None and node.parent.type == 'declaration':
            if node.parent.parent is not None and node.parent.parent.type == 'template_declaration':
                return True, node.parent.parent
        return False, node

    @staticmethod
    def get_class_list(root_node):

        res = get_node_by_kind(root_node, ['class_specifier'])
        res = [ n if n.parent is not None and n.parent.type != 'template_declaration' else n.parent for n in res ]
        return res
    
    @staticmethod
    def get_class_name(node):
        if node.type == 'class_specifier':
            for child in node.children:
                if child.type == 'type_identifier':
                    return get_node_text(child)
        elif node.type == 'template_declaration':
            for child in node.children:
                if child.type == 'class_specifier':
                    return CppParser.get_class_name(child)

        return None

        
    @staticmethod
    def get_comment_node(node):
        """
        Return all comment node inside a parent node
        Args:
            node (tree_sitter.Node)
        Return:
            List: list of comment nodes
        """
        comment_node = get_node_by_kind(node, kind=['comment'])
        return comment_node
    
    @staticmethod
    def get_function_metadata(function_node, blob: str=None) -> Dict[str, Any]:
        """
        node type: function_definition or the parent of function_declarator
        Function metadata contains:
            - identifier (str): function name
            - parameters (Dict[str, str]): parameter's name and their type (e.g: {'param_a': 'int'})
            - return_type (str or NoneType): function's return type
        """
        if blob:
            logger.info('From version `0.0.6` this function will update argument in the API')
        metadata = {
            'identifier': '',
            'parameters': {},
            'return_type': None,
        }
        assert type(function_node) == tree_sitter.Node
        
        for child in function_node.children:
            if child.type in ['primitive_type', 'type_identifier']:
                metadata['return_type'] = get_node_text(child)
                # search for "function_declarator"
            elif child.type == 'pointer_declarator':
                for subchild in child.children:
                    if subchild.type == 'function_declarator':
                        child = subchild
            if child.type == 'function_declarator':
                for subchild in child.children:
                    if subchild.type in ['qualified_identifier', 'identifier', 'field_identifier']:
                        metadata['identifier'] = get_node_text(subchild)
                    elif subchild.type == 'parameter_list':
                        param_nodes = get_node_by_kind(subchild, ['parameter_declaration'])
                        for param in param_nodes:
                            param_type = param.child_by_field_name('type')
                            param_type = get_node_text(param_type)
                            list_name = get_node_by_kind(param, ['identifier'])
                            if not list_name:
                                continue
                            param_name = get_node_text(list_name[0])
                            metadata['parameters'][param_name] = param_type

        return metadata

    @staticmethod
    def get_function_metadata_v2(function_node, blob: str=None) -> Dict[str, Any]:
        pass

    @staticmethod
    def get_class_metadata(class_node, blob: str=None) -> Dict[str, str]:
        """
        Class metadata contains:
            - identifier (str): class's name
            - parameters (List[str]): inheritance class
        """
        if blob:
            logger.info('From version `0.0.6` this function will update argument in the API')
        metadata = {
            'identifier': '',
            'parameters': {},
        }
        assert type(class_node) == tree_sitter.Node
        
        for child in class_node.children:
            if child.type == 'type_identifier':
                metadata['identifier'] = get_node_text(child)
            elif child.type == 'base_class_clause':
                argument_list = []
                for param in child.children:
                    if param.type == 'type_identifier':
                        metadata['parameters'][get_node_text(param)] = None

        return metadata

    
    @staticmethod
    def getClassFromFnNode(node):
        if node.type == 'class_specifier':
            return node
        else:
            if node.parent is None:
                return None
            return CppParser.getClassFromFnNode(node.parent)
        
    @staticmethod
    def getClassFieldAndFunction(node):
        field_declaration_list = get_node_by_kind( node, ['field_declaration'] )
        template_declaration_fn_or_field_list =  get_node_by_kind( node, ['template_declaration'] )
        template_declaration_field_list =  [ n for n in template_declaration_fn_or_field_list if len(get_node_by_kind( n, ['function_declarator'] )) == 0 ]
        
        class_member = CppParser.getFunctionNodes(node)
        class_member['field_declaration_list'] = field_declaration_list
        class_member['template_declaration_field_list'] = template_declaration_field_list
        return class_member
            
    @staticmethod
    def getTemplateFunction(node):

        template_declaration_list = get_node_by_kind(node, ['template_declaration'])
        template_fn_list = []
        for n in template_declaration_list:
            for c in n.children:
                if c.type == 'function_definition':
                    template_fn_list.append(n) 
                    break
        return template_fn_list   

    @staticmethod
    def getTempateFunctionDeclaration(node):

        template_declaration_list =  get_node_by_kind( node, ['template_declaration'] )
        template_dec_list = []
        for n in template_declaration_list:
            for c in n.children:
                if c.type == 'declaration':
                    template_dec_list[n]
                    break
        return template_dec_list 

    @staticmethod
    def extract_struct_names(c_code):
        # Regex to match typedef struct names
        typedef_pattern = re.compile(r"typedef\s+struct\s*\{[^}]*\}\s*([\w]+)\s*;")
        # Regex to match named struct declarations
        struct_pattern = re.compile(r"struct\s+([\w]+)\s*\{")

        # Find all matches in the C code
        typedef_matches = typedef_pattern.findall(c_code)
        struct_matches = struct_pattern.findall(c_code)

        # Combine and return unique struct names
        all_matches = set(typedef_matches + struct_matches)
        return list(all_matches)
    
    @staticmethod
    def extract_enum_names(c_code):
        # Regex to match typedef struct names
        typedef_pattern = re.compile(r"typedef\s+enum\s*\{[^}]*\}\s*([\w]+)\s*;")
        # Regex to match named struct declarations
        enum_pattern = re.compile(r"enum\s+([\w]+)\s*\{")

        # Find all matches in the C code
        typedef_matches = typedef_pattern.findall(c_code)
        enum_matches = enum_pattern.findall(c_code)

        # Combine and return unique enum names
        all_matches = set(typedef_matches + enum_matches)
        return list(all_matches)


    @staticmethod
    def getStructRelatedNodes(node):
        """
        Get class declaration
        """
        struct_list = get_node_by_kind(node, ['struct_specifier'])
        struct_def_list = []
        struct_other_list = []
        for n in struct_list:
            for c in n.children:
               if c.type == 'field_declaration_list':
                   struct_def_list.append(n)
                   break
            struct_other_list.append(n)

        struct_def_list = [ n if n.parent.type != 'type_definition' else n.parent for n in struct_def_list + struct_other_list ]
        res =[]
        for n in struct_def_list:

            field_declaration_list = get_node_by_kind(n, ['field_declaration'])
            parameters = {}
            struct_list = get_node_by_kind(n, ['struct_specifier'])
            for c in field_declaration_list:
                children = [ j for j in c.children if n.type != 'comment' ]
                parameters[get_node_text(children[1])] = get_node_text(children[0])

            
            if n.type == "type_definition" and len(struct_list) != 0:
                assert len(n.children) >= 2
                for cn in n.children:
                    if cn.type == "struct_specifier":
                        continue
                    type_identifier_lst = get_node_by_kind(cn, ['type_identifier'])
                    for cnn in type_identifier_lst:
                        cnn_name = get_node_text(cnn)
                        res.append( ( get_node_text(n), parameters, cnn_name, n.start_point, n.end_point ) )  
            else:
                sname = ""
                if len(CppParser.extract_struct_names( get_node_text(n))) != 0:
                    sname= CppParser.extract_struct_names( get_node_text(n))[0]
                res.append( ( get_node_text(n), parameters, sname, n.start_point, n.end_point ) )  
                

        return res
    
    @staticmethod
    def getEnumerateNode(node):
        """
        Get class declaration
        """
        enum_list = get_node_by_kind(node, ['enum_specifier'])
        struct_def_list = []
        struct_other_list = []
        for n in enum_list:
            for c in n.children:
               if c.type == 'enumerator_list ':
                   struct_def_list.append(n)
                   break
            struct_other_list.append(n)

        struct_def_list = [ n if n.parent.type != 'type_definition' else n.parent for n in struct_def_list + struct_other_list ]
        res =[]
        for n in struct_def_list:
            field_declaration_list = get_node_by_kind(n, ['enumerator'])
            parameters = {}
            enum_list = get_node_by_kind(n, ['enum_specifier'])
            for c in field_declaration_list:
                children = [ j for j in c.children if n.type != 'comment' ]
                logger.info(f"{c}, {get_node_text(c)}, {get_node_text(n)}")
                logger.info(f"{children}")
                if len(children)==2:
                    parameters[get_node_text(children[1])] = get_node_text(children[0])
                else:
                    parameters[get_node_text(children[0])] = ""
            
            if n.type == "type_definition" and len(enum_list) != 0:
                assert len(n.children) >= 2
                for cn in n.children:
                    if cn.type == "enum_specifier":
                        continue
                    type_identifier_lst = get_node_by_kind(cn, ['type_identifier'])
                    for cnn in type_identifier_lst:
                        cnn_name = get_node_text(cnn)
                        res.append( ( get_node_text(n), parameters, cnn_name, n.start_point, n.end_point ) )  
            else:
                sname = ""
                if len(CppParser.extract_enum_names( get_node_text(n))) != 0:
                    sname= CppParser.extract_enum_names( get_node_text(n))[0]
                res.append( ( get_node_text(n), parameters, sname, n.start_point, n.end_point ) ) 

        return res
    
    @staticmethod
    def isTemplateFn(node):

        assert node.type in ['function_definition', 'function_declarator']

        if node.type == 'function_declarator':
            if node.parent is not None and node.parent.type == 'declaration' and node.parent.parent.type == 'template_declaration':
                return True
            else:
                return False
        if node.type == 'function_definition':
            if node.parent is not None and node.parent.type == 'template_declaration':
                return True
            else:
                return False
            
        assert False, "node type is not function_definition or function_declarator"
    
    @staticmethod
    def getIncludeList(node):
        """
        Check if a node is a include node
        """
        include_list = get_node_by_kind(node, ['preproc_include'])
        include_list = [ (get_node_text(n), n.start_point, n.end_point) for n in include_list ]
        return include_list
       
    

    

    @staticmethod
    def get_function_body(node):
        """
        Get function declaration from function node
        """
        if node.children[-1].type == 'compound_statement':
            return node.children[-1]
        else:
            return None
    
    @staticmethod
    def extract_global_variables(node):
        if isinstance(node, str):
            _, cpp_parse = get_language('cpp')
            node = cpp_parse.parse(bytes(node, 'utf-8')).root_node
        globals = []
        cursor = node.walk()

        def collect_globals():
            # Start from the declaration node and iterate through children
            if cursor.node.type == 'declaration':
                parent = cursor.node.parent
                if parent and parent.type == 'translation_unit':  # Ensure it's a global declaration
                    for child in cursor.node.children:
                        # Skip qualifiers like 'static', 'const'
                        if child.type not in ('storage_class_specifier', 'type_qualifier'):
                            # Check if the child is a type specifier
                            if child.type in ('primitive_type', 'type_identifier'):
                                globals.append(cursor.node)
                                break  # Stop after finding the first valid type specifier


        if cursor.goto_first_child():
            collect_globals()
            while cursor.goto_next_sibling():
                collect_globals()
        #.text.decode('utf8')
        globals = [g.text.decode('utf8') for g in globals if get_node_by_kind(g, ['function_declarator'])==0 ]
        return globals

    @staticmethod
    def split_code(code, is_return_node=False):

        _, cpp_parse = get_language('cpp')
        root_node = cpp_parse.parse(bytes(code, 'utf-8')).root_node


        template_declaration_list = CppParser.getTemplateFunction(root_node)
        

        global_variables = CppParser.extract_global_variables(root_node)


        implementation_fn = CppParser.get_function_list(root_node)

        implementation_fn = [ n for n in implementation_fn if not CppParser.isTemplateFn(n)  ]

        fn_def_list = template_declaration_list + implementation_fn

  
        fn_declaraion = CppParser.get_function_declarator_list(root_node)


        class_node_list = CppParser.get_class_list(root_node)
        class_node_dict = {}
        for n in class_node_list:
            class_name = CppParser.get_class_name(n)
            if class_name:
                hash_code = generate_hash_code(n.text.decode())
                class_node_dict[hash_code] = {
                    "class_code": n.text.decode(),
                    "class_name": class_name,
                    "class_pos": [n.start_point, n.end_point]
                }
            else:
                logger.warning(f"Could not extract class name for node: {n}")

        fn_def_list = [ (n, CppParser.getClassFromFnNode(n), CppParser.get_function_metadata(n)) for n in fn_def_list ]
        fn_declaraion = [ (n, CppParser.getClassFromFnNode(n), CppParser.get_function_metadata(n.parent)) for n in fn_declaraion ]
        
        
        struct_node_list = CppParser.getStructRelatedNodes(root_node)
        enumerate_node_list = CppParser.getEnumerateNode(root_node)
        
        include_list = CppParser.getIncludeList(root_node)

        if is_return_node:
            fn_def_list = [ {"fn_code":n[0],  "class_code":n[1], "fn_meta":n[2]} for n in fn_def_list ]
            fn_declaraion = [ {"fn_code":n[0], "class_code":n[1], "fn_meta":n[2]} for n in fn_declaraion ]
            class_node_list = { generate_hash_code(n.text.decode()):{"class_code":n, "class_name":CppParser.get_class_name(n) } for n in class_node_list }
            return fn_def_list, fn_declaraion, class_node_list, struct_node_list, include_list, global_variables
        else:
            fn_def_list = [{"fn_code": n[0].text.decode(), "fn_code_pos": [n[0].start_point, n[0].end_point],
                        "class_code": "" if n[1] is None else generate_hash_code(n[1].text.decode()),
                        "class_node_pos": [n[1].start_point, n[1].end_point] if n[1] is not None else [],
                        "fn_meta": n[2]} for n in fn_def_list]
            fn_declaraion = [{"fn_code": n[0].text.decode(), "fn_dec_pos": [n[0].start_point, n[0].end_point],
                          "class_code": "" if n[1] is None else generate_hash_code(n[1].text.decode()),
                          "class_node_pos": [n[1].start_point, n[1].end_point] if n[1] is not None else [],
                          "fn_meta": n[2]} for n in fn_declaraion]
            return fn_def_list, fn_declaraion, class_node_dict, struct_node_list, include_list, global_variables, enumerate_node_list

        
