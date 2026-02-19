# win_objects_il

## Overview
The `win_objects_il` tool is a command-line utility designed to set integrity levels on various Windows objects, such as files, registry keys, services, printers, kernel objects, windows, and directory service objects.^[1]^ This tool allows administrators to control the security and access permissions of these objects by specifying their integrity levels and inheritance properties.^[2]^

## Usage
```
win_objects_il types
win_objects_il get <object_type_num> <object_name>
win_objects_il set <object_type_num> <object_name> <LW|ME|MP|HI|SI> [OI|CI|OICI]
```

### Parameters
- **ObjectType**: Specifies the type of object to modify. Valid options are:
  - `0`:SE_UNKNOWN_OBJECT_TYPE
  - `1`:SE_FILE_OBJECT
  - `2`:SE_SERVICE
  - `3`:SE_PRINTER
  - `4`:SE_REGISTRY_KEY
  - `5`:SE_LMSHARE
  - `6`:SE_KERNEL_OBJECT
  - `7`:SE_WINDOW_OBJECT
  - `8`:SE_DS_OBJECT
  - `9`:SE_DS_OBJECT_ALL
  - `10`:SE_PROVIDER_DEFINED_OBJECTI
  - `11`:SE_WMIGUID_OBJECT
  - `12`:SE_REGISTRY_WOW64_32KEY
  - `13`:SE_REGISTRY_WOW64_64KEY

- **ObjectPath**: The path to the object. For example:
  - For files: `C:\Temp\test.txt`
  - For registry keys: `CURRENT_USER\Software\MyApp`
  - For services: `MyService`

- **IntegrityLevel**: Specifies the integrity level to set. Valid options are:
  - `LW` (Low)
  - `ME` (Medium)
  - `MP` (Medium Plus)
  - `HI` (High)
  - `SI` (System)

- **inheritance (optional)**: Specifies how the integrity level should be inherited by child objects. Valid options are:
  - `OI`: Object inheritance.
  - `CI`: Container inheritance.
  - `OICI`: Both container and object inheritance.

### Examples
```
win_objects_il set 1 C:\test.txt ME OICI
win_objects_il set 4 CURRENT_USER\Software\test LW
win_objects_il get 2 Spooler
```

## Integrity Levels
Integrity levels are a security feature in Windows that help protect objects from unauthorized modifications. They are part of the Mandatory Integrity Control (MIC) mechanism, which assigns integrity levels to processes and objects to control access permissions.^[10]^ The integrity levels, from lowest to highest, are:

- **Low**: Used for objects with limited trust, such as files downloaded from the internet.
- **Medium**: Default integrity level for most user files and processes.
- **High**: Used for objects that require a higher level of trust, such as system files.
- **System**: Highest integrity level, used for critical system components.

## Inheritance
Inheritance determines how access control entries (ACEs), including integrity levels, are passed down to child objects.^[16]^ The inheritance options are:

- **None**: The integrity level is not inherited by child objects.
- **Container**: The integrity level is inherited by container objects (e.g., directories).
- **Object**: The integrity level is inherited by non-container objects (e.g., files).
- **Both**: The integrity level is inherited by both container and non-container objects.

By following this guide, administrators can effectively use the `win_objects_il` tool to manage integrity levels and enhance the security of Windows objects.