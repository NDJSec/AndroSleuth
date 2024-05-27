from typing import Iterator
from androguard.core.analysis.analysis import Analysis, ClassAnalysis

def __convert_to_java_package(dalvik_name: str) -> str:
    if dalvik_name.startswith('L') and dalvik_name.endswith(';'):
        dalvik_name = dalvik_name[1:-1]

    java_name = dalvik_name.replace('/', '.')
    java_name = java_name.replace('$', '.')

    return java_name

def __filter_third_party_packages(java_packages: Iterator[ClassAnalysis], app_package: str) -> list[str]:
    third_party_packages = []
    common_prefixes = ('com.', 'org.', 'net.', 'io.', 'edu.', 'gov.', 'me.', 'co.', 'biz.')

    app_package_prefix = app_package + "."

    for java_package in set(java_packages):
        java_package = __convert_to_java_package(java_package.name)

        # Check if the package is a common prefix and does not start with the app package
        if any(java_package.startswith(prefix) for prefix in common_prefixes) and not java_package.startswith(app_package_prefix):
            third_party_packages.append(java_package)

    return third_party_packages



def get_packages(_vmx: Analysis, app_package: str) -> None:
    app_package = '.'.join(app_package.split('.')[:2])
    with open("packages.txt", "w") as package_file:
        package_file.write("EXTERNAL\n")
        for package in __filter_third_party_packages(_vmx.get_external_classes(), app_package):
            package_file.write(f"{package}\n")
        package_file.write("INTERNAL\n")
        for package in __filter_third_party_packages(_vmx.get_internal_classes(), app_package):
            package_file.write(f"{package}\n")

