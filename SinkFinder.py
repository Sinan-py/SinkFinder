import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import esprima
import sys

print("""

        ╭━━━╮╱╱╱╭╮╱╭━━━╮╱╱╱╱╱╭╮
        ┃╭━╮┃╱╱╱┃┃╱┃╭━━╯╱╱╱╱╱┃┃
        ┃╰━━┳┳━╮┃┃╭┫╰━━┳┳━╮╭━╯┣━━┳━╮
        ╰━━╮┣┫╭╮┫╰╯┫╭━━╋┫╭╮┫╭╮┃┃━┫╭╯
        ┃╰━╯┃┃┃┃┃╭╮┫┃╱╱┃┃┃┃┃╰╯┃┃━┫┃
        ╰━━━┻┻╯╰┻╯╰┻╯╱╱╰┻╯╰┻━━┻━━┻╯
        Created by: Sinan Web3
        Follow us on Twitter: @malware_door
        Contact with me: backdoorkit@proton.me

""")

GREEN = '\033[92m'  
RED = '\033[91m'    
RESET = '\033[0m'   

sinks = {
    'general': [
        'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
        'insertAdjacentHTML', 'eval', 'setTimeout', 'setInterval',
        'Function', 'execScript', 'location', 'setAttribute', 'src',
        'href', 'action', 'formaction', 'data', 'lowsrc', 'background',
        'code', 'codebase', 'cite', 'longdesc', 'usemap', 'style.cssText',
        'localStorage', 'sessionStorage', 'indexedDB', 'window.name'
    ],
    'react': [
        'dangerouslySetInnerHTML', 'setState', 'eval', 'dangerouslySetInnerHTML'
    ],
    'angular': [
        'ng-bind-html', 'ng-bind', 'ng-src', 'ng-href', 'ng-include'
    ],
    'vue': [
        'v-html', 'v-bind:href', 'v-bind:src'
    ],
    'jquery': [
        'html', 'text', 'attr', 'prop', 'append', 'prepend',
        'before', 'after', 'replaceWith'
    ]
}

def find_vulnerable_sinks(script_content, file_path):
    try:
        tree = esprima.parseScript(script_content, tolerant=True)
        for node in tree.body:
            check_node(node, file_path)
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")

def check_node(node, file_path):
    if node.type == 'ExpressionStatement':
        expression = node.expression
        if expression.type == 'AssignmentExpression':
            check_assignment_expression(expression, file_path)
        elif expression.type == 'CallExpression':
            check_call_expression(expression, file_path)
    elif node.type == 'VariableDeclaration':
        for declaration in node.declarations:
            if declaration.init and declaration.init.type == 'CallExpression':
                check_call_expression(declaration.init, file_path)
    elif node.type == 'FunctionDeclaration' or node.type == 'FunctionExpression':
        for body_node in node.body.body:
            check_node(body_node, file_path)

def check_assignment_expression(expression, file_path):
    if expression.left.type == 'MemberExpression':
        check_member_expression(expression.left, file_path)

def check_call_expression(expression, file_path):
    if expression.callee.type == 'MemberExpression':
        check_member_expression(expression.callee, file_path)
    elif expression.callee.type == 'Identifier':
        if expression.callee.name in sinks['general']:
            print(f"{RED}Vulnerable sink found in {file_path}: {expression.callee.name}{RESET}")
            global vulnerable_sinks_count
            vulnerable_sinks_count += 1
        elif expression.callee.name in sinks['react']:
            print(f"{RED}React-specific vulnerable sink found in {file_path}: {expression.callee.name}{RESET}")
            vulnerable_sinks_count += 1
        elif expression.callee.name in sinks['angular']:
            print(f"{RED}Angular-specific vulnerable sink found in {file_path}: {expression.callee.name}{RESET}")
            vulnerable_sinks_count += 1
        elif expression.callee.name in sinks['vue']:
            print(f"{RED}Vue-specific vulnerable sink found in {file_path}: {expression.callee.name}{RESET}")
            vulnerable_sinks_count += 1
        elif expression.callee.name in sinks['jquery']:
            print(f"{RED}jQuery-specific vulnerable sink found in {file_path}: {expression.callee.name}{RESET}")
            vulnerable_sinks_count += 1

def check_member_expression(expression, file_path):
    if expression.property.type == 'Identifier':
        if expression.property.name in sinks['general']:
            print(f"{RED}Vulnerable sink found in {file_path}: {expression.property.name}{RESET}")
            global vulnerable_sinks_count
            vulnerable_sinks_count += 1
        elif expression.property.name in sinks['react']:
            print(f"{RED}React-specific vulnerable sink found in {file_path}: {expression.property.name}{RESET}")
            vulnerable_sinks_count += 1
        elif expression.property.name in sinks['angular']:
            print(f"{RED}Angular-specific vulnerable sink found in {file_path}: {expression.property.name}{RESET}")
            vulnerable_sinks_count += 1
        elif expression.property.name in sinks['vue']:
            print(f"{RED}Vue-specific vulnerable sink found in {file_path}: {expression.property.name}{RESET}")
            vulnerable_sinks_count += 1
        elif expression.property.name in sinks['jquery']:
            print(f"{RED}jQuery-specific vulnerable sink found in {file_path}: {expression.property.name}{RESET}")
            vulnerable_sinks_count += 1

def download_and_scan_js(js_url, session):
    try:
        response = session.get(js_url)
        if response.status_code == 200:
            find_vulnerable_sinks(response.text, js_url)
        else:
            print(f"Failed to retrieve {js_url}, status code: {response.status_code}")
    except Exception as e:
        print(f"Error downloading {js_url}: {e}")

def scan_website_for_vulnerabilities(url):
    global vulnerable_sinks_count
    vulnerable_sinks_count = 0
    
    session = requests.Session()
    try:
        response = session.get(url)
        if response.status_code != 200:
            print(f"Failed to retrieve {url}, status code: {response.status_code}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script')
        
        total_files = len(scripts)
        processed_files = 0

        for script in scripts:
            if script.string:
                find_vulnerable_sinks(script.string, url)
            elif script.get('src'):
                js_url = script.get('src')
                full_js_url = urljoin(url, js_url)
                download_and_scan_js(full_js_url, session)
            processed_files += 1
            progress = (processed_files / total_files) * 100
            sys.stdout.write(f"\r{GREEN}Progress: [{int(progress)}%] ({processed_files}/{total_files}){RESET}\n")
            sys.stdout.flush()
        
        print(f"\n{GREEN}Scanning completed.{RESET}\n")
        print(f"{RED}Total vulnerable sinks found: {vulnerable_sinks_count}{RESET}")
    except Exception as e:
        print(f"Error scanning {url}: {e}")

website_url = input("Enter the full website URL (e.g., http://example.com/path/to/resource): ")

scan_website_for_vulnerabilities(website_url)
