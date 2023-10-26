import os
import time
import ctypes
import winreg

def print_in_color(text, color):
    if color == "red":
        color_code = 12
    elif color == "green":
        color_code = 10
    elif color == "purple":  
        color_code = 13
    else:
        color_code = 7  

    ctypes.windll.kernel32.SetConsoleTextAttribute(ctypes.windll.kernel32.GetStdHandle(-11), color_code)
    print(text)
    ctypes.windll.kernel32.SetConsoleTextAttribute(ctypes.windll.kernel32.GetStdHandle(-11), 7)  

# Function to check for specific persistence indicators
def check_specific_persistence_indicators():
    persistence_indicators = {
        "BoxCaon": "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows\load",
        "AppleSeed": "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\EstsoftAutoUpdate",
        "APT41": "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost",
        "BBSRAT": "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ssonsvr.exe",
        "BoomBox": "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicroNativeCacheSvc",
        "Cardinal RAT": "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load",
        "Chaes": "Software\microsoft\windows\currentversion\run\microsoft windows html help",
        "Chinoxy": "HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "EvilBunny": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "HTTPBrowser": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKEY_USERS\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "InnaputRAT": r"HKU\Software\Microsoft\Windows\CurrentVersion\Run:" + os.environ['APPDATA'] + "\\NeutralApp\\NeutralApp.exe",
        "LoJax": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
        "Lucifer": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\QQMusic", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\QQMusic"],
        "Mivast": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Micromedia",
        "Mosquito": "HKCU\\Software\\Run auto_update",
        "MuddyWater": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemTextEncoding",
        "Mustang Panda": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\AdobelmdyU",
        "Operation Honeybee": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost",
        "S-Type": ["Start menu folder", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "STARWHALE": ["Startup folder", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OutlookM"],
        "VBShower": r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[a-f0-9A-F]{8}",
        "WarzoneRAT": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UIF2IS20VK"],
        "ZIRCONIUM": "Dropbox Update Setup",
    }

    for item, indicators in persistence_indicators.items():
        print_in_color("Checking persistence for: " + item, "purple")
        if isinstance(indicators, str):
            check_registry_entry(indicators)
        elif isinstance(indicators, list):
            for indicator in indicators:
                check_registry_entry(indicator)
        elif "HKCU" in indicators:  # Check for Startup folder
            check_startup_folder(indicators)
        elif "HKLM" in indicators:  # Check for Registry Run key
            check_registry_run_key(indicators)
        print()

# Function to check for suspicious items in a registry entry
def check_registry_entry(path):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
        print(f"Checking registry entry: {path}")
        try:
            value, _ = winreg.QueryValueEx(key, None)
            if not value.startswith(os.environ['ProgramFiles']):
                print_in_color("Found suspicious registry entry", "red")
                print(f"{path} ({value})")
                # Get and print the last write time of the registry key
                last_write_time = os.path.getmtime(path)
                print(f"Last Write Time: {time.ctime(last_write_time)}")
            else:
                print_in_color("No suspicious registry entry found", "green")
        except WindowsError:
            print_in_color("No suspicious registry entry found", "green")
        winreg.CloseKey(key)
    except FileNotFoundError:
        print(f"Checking registry entry: {path}")
        print_in_color("No suspicious registry entry found", "green")

# Function to check for suspicious items in HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
def check_registry_run_key(path):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
        print(f"Checking registry entry: {path}")
        try:
            value, _ = winreg.QueryValueEx(key, None)
            if not value.startswith(os.environ['ProgramFiles']):
                print_in_color("Found suspicious registry entry", "red")
                print(f"{path} ({value})")
            else:
                print_in_color("No suspicious registry entry found", "green")
        except WindowsError:
            print_in_color("No suspicious registry entry found", "green")
        winreg.CloseKey(key)
    except FileNotFoundError:
        print(f"Checking registry entry: {path}")
        print_in_color("No suspicious registry entry found", "green")

# Function to check for specific items in HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
def check_registry_run_key_with_exceptions(path):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
        print(f"Checking registry entry: {path}")
        found_suspicious = False
        try:
            while True:
                subkey_name, _ = winreg.EnumValue(key, 0)
                if not subkey_name.startswith(os.environ['ProgramFiles']):
                    print_in_color("Found suspicious registry entry", "red")
                    print(f"{path}\\{subkey_name}")
                    found_suspicious = True
        except WindowsError:
            if not found_suspicious:
                print_in_color("No suspicious registry entry found", "green")
        winreg.CloseKey(key)
    except FileNotFoundError:
        print(f"Checking registry entry: {path}")
        print_in_color("No suspicious registry entry found", "green")

# Function to check for suspicious items in startup folders
def check_startup_folder(path):
    print(f"Checking startup folder: {path}")
    found_suspicious = False
    try:
        for filename in os.listdir(path):
            file_path = os.path.join(path, filename)
            if not filename.startswith(os.environ['ProgramFiles']):
                print_in_color("Found suspicious file in startup folder", "red")
                print(f"File Name: {filename}")
                print(f"File Path: {file_path}")
                # Get and print the last write time of the file
                last_write_time = os.path.getmtime(file_path)
                print(f"Last Write Time: {time.ctime(last_write_time)}")
                found_suspicious = True
    except FileNotFoundError:
        pass

    if not found_suspicious:
        print_in_color("No suspicious files found in startup folder", "green")

def main():
    print("---------------------------------------------")
    print("RegKey Canine - Registry Run Keys / Startup Folder Detection Script")
    print("Version: 1.0.0")
    print("Author: Cyb3rN8TE 2023")
    print("This script checks for suspicious registry entries, files in startup folders, and known persistence indicators (ATT&CK T1547.001).")
    print("Suspicious findings will be displayed in red.")
    print("---------------------------------------------")
    print()

    # Registry paths to check
    registry_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserShellFolders",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellFolders",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserShellFolders",
        r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    ]

    # Startup folders to check
    startup_folders = [
        os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
        os.path.join(os.environ['ProgramData'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    ]

    # Check for specific persistence indicators
    print("")
    print("---------------------------------------------")
    print("Checking Known Threats - T1547.001")
    print("---------------------------------------------")
    print("")
    check_specific_persistence_indicators()
    print()

    print("")
    print("---------------------------------------------")
    print("Checking Common Locations - T1547.001")
    print("---------------------------------------------")
    print("")

    for registry_path in registry_paths:
        if "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" in registry_path:
            check_registry_run_key_with_exceptions(registry_path)
        else:
            check_registry_entry(os.path.join(r"HKEY_LOCAL_MACHINE", registry_path))
        print()

    for folder_path in startup_folders:
        check_startup_folder(folder_path)
        print()

    print("")
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
