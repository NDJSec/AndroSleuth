from typing import Iterator
from androguard.core.analysis.analysis import Analysis

def __convert_to_java_package(dalvik_name: str) -> str:
    if dalvik_name.startswith('L') and dalvik_name.endswith(';'):
        dalvik_name = dalvik_name[1:-1]

    java_name = dalvik_name.replace('/', '.')
    java_name = java_name.replace('$', '.')

    return java_name

def __filter_third_party_packages(java_packages: Iterator[str]) -> list[str]:
    third_party_packages = []
    for java_package in java_packages:
        java_package = __convert_to_java_package(java_package.name)

        if (java_package.startswith(('com', 'org', 'net'))):
            third_party_packages.append(java_package)

    return third_party_packages



def get_packages(_vmx: Analysis) -> None:
    with open("packages.txt", "w") as package_file:
        package_file.write("EXTERNAL\n")
        for package in __filter_third_party_packages(_vmx.get_external_classes()):
            package_file.write(f"{package}\n")
        package_file.write("INTERNAL\n")
        for package in __filter_third_party_packages(_vmx.get_internal_classes()):
            package_file.write(f"{package}\n")

