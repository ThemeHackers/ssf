import os 
import importlib .util 
import sys 
from typing import List ,Any 
from rich .console import Console 

class PluginManager :
    def __init__ (self ,plugin_dir :str ="plugins"):
        self .plugin_dir =plugin_dir 
        self .console =Console ()
        self .plugins =[]

    def load_plugins(self, plugins_arg: str = None) -> List[Any]:
        self.plugins = [] 
        if not os.path.exists(self.plugin_dir):
            return []
        
        if not plugins_arg:
            return [] 

        selected_plugins = []
        if plugins_arg.lower() == "all":
             selected_plugins = ["all"]
        else:
             selected_plugins = [p.strip() for p in plugins_arg.split(",")]

        self.console.print(f"[cyan][*] Loading plugins from {self.plugin_dir}...[/]")

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                plugin_name_fs = filename[:-3]
                
          
                if "all" not in selected_plugins:
                     if plugin_name_fs not in selected_plugins:
                          continue

                plugin_path = os.path.join(self.plugin_dir, filename)
                try:
                    module_name = filename[:-3]
                    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)

                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if isinstance(attr, type) and attr_name.endswith("Scanner") and attr_name != "BaseScanner":
                            self.plugins.append(attr)
                            self.console.print(f"    [green][+] Loaded plugin: {attr_name} from {filename}[/]")

                except Exception as e:
                    self.console.print(f"    [red][!] Failed to load plugin {filename}: {e}[/]")

        return self.plugins 
