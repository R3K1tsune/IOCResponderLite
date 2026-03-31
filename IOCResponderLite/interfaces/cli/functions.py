import sys, colorama, yaml, textwrap
import IOCResponderLite.core.functions

def Banner():
    print(f'{colorama.Fore.MAGENTA} _____ _____ _____    _____                       _ \n|     |     |     |  | __  |___ ___ ___ ___ ___ _| |___ ___ \n||   || ||| |   |||  |    -| -_|_ -| . | . |   | . | -_|  _|\n|_____|_____|_____|  |__|__|___|___|  _|___|_|_|___|___|_|\n                      by {colorama.Fore.CYAN}R3狐 (R3K){colorama.Fore.MAGENTA}|_|{colorama.Fore.MAGENTA}LITE          1.0.1{colorama.Fore.RESET}\n', end='\n')

def OpenConfig(Path):
    with open(Path,'r', encoding='utf-8') as YAML:
        ConfigYAML = yaml.safe_load(YAML)
    return ConfigYAML
        
def InitConfig(arg_path_to_config):
    if arg_path_to_config == 'none':
        try:
            ConfYAML = OpenConfig('Settings.yml')
            return ConfYAML
        except FileNotFoundError:
            print(f'{colorama.Fore.RED}Configuration is not avaible `settings.yml` available. Check it{colorama.Fore.RESET}',end='\n')
            PathToConf = input(f'Please enter full path: ')
            try:
                ConfYAML = OpenConfig(PathToConf)
                return ConfYAML
            except:
                print(f'{colorama.Fore.RED}The attempt to open the configuration file failed. Exit{colorama.Fore.RESET}')
                sys.exit()
    else:
        try:
            ConfYAML = OpenConfig(arg_path_to_config)
            return ConfYAML
        except:
            print(f'{colorama.Fore.RED}{colorama.Fore.BLACK}The attempt to open the configuration file failed. Exit{colorama.Fore.RESET}')
            sys.exit()

def ReadIOCsFile(arg_path_to_iocs_file,section_type):
    if arg_path_to_iocs_file != 'none':
        result_list = []
        try:
            with open(arg_path_to_iocs_file, 'r', encoding='utf-8') as iocs_file:
                current_section = None
                for line in iocs_file:
                    line = line.strip()
                    if line.startswith('###'):
                        current_section = line[3:].strip()
                    if current_section == section_type and line and not line.startswith('###'):
                        if section_type == 'Hashes':
                            if IOCResponderLite.core.functions.DetermineIocType(line) in ('MD5','SHA256','SHA1'):
                                result_list.append(line)
                        else:
                            result_list.append(line)
            return result_list
        except FileNotFoundError:
            print(f'{colorama.Fore.RED}Error: {arg_path_to_iocs_file} not found.{colorama.Fore.RESET}')
            return []
        except Exception as Error:
            print(f'{colorama.Fore.RED}Error in open file: {Error}{colorama.Fore.RESET}')
            return []

def ColourOutput(string):
    red_flag = ['malware','phishing', 'malicious', 'backdoor', 
                'worm', 'exploit', 'rootkit', 'heur:','trojan',
                'virus','webshell','revshell','threat','red',
                'werewolf','apt','self-signed']
    yellow_flag = ['suspicious','tool']
    green_flag = ['clean', 'green', 'signed', 'eicar']
    legit = ['eicar','not a virus','not-a-virus']
    if any(value in string.lower() for value in red_flag) and not any(value in string.lower() for value in legit):
        print(f'{colorama.Fore.RED}{string}{colorama.Fore.RESET}')
    elif any(value in string.lower() for value in yellow_flag):
        print(f'{colorama.Fore.YELLOW}{string}{colorama.Fore.RESET}')
    elif any(value in string.lower() for value in green_flag):
        print(f'{colorama.Fore.GREEN}{string}{colorama.Fore.RESET}')
    else:
        print(string)

def CreateFileOutput(object,file_path,file_name):
    try:
        with open(file_path+'\\'+file_name+'.json','w+', encoding='utf-8') as output_file:
            output_file.write(object)
    except Exception as Error:
        print(f'Error with create output file {file_path}: {Error}')

def PrintTable(row, widths):
    wrapped = {
        key: textwrap.wrap(str(row.get(key, '')), widths[key]) or ['']
        for key in widths
    }
    max_lines = max(len(lines) for lines in wrapped.values())
    for i in range(max_lines):
        ColourOutput('| '+' | '.join(f'{wrapped[key][i] if i < len(wrapped[key]) else "":<{widths[key]}}' for key in widths)+' |')
