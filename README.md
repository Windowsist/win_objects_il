# SetObjectIntegrity Tool

## Overview
The `SetObjectIntegrity` tool is a command-line utility designed to set integrity levels on various Windows objects, such as files, registry keys, services, printers, kernel objects, windows, and directory service objects.^[1]^ This tool allows administrators to control the security and access permissions of these objects by specifying their integrity levels and inheritance properties.^[2]^

## Usage
```
SetObjectIntegrity.exe /types
SetObjectIntegrity.exe <ObjectType> <ObjectPath> <IntegrityLevel> [inheritance]
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
	- 
- **ObjectPath**: The path to the object.^[3]^ For example:
  - For files: `C:\Temp\test.txt`
  - For registry keys: `CURRENT_USER\Software\MyApp`
  - For services: `MyService`

- **IntegrityLevel**: Specifies the integrity level to set.^[4]^ Valid options are:
  - `S-1-16-0` (Untrusted)
  - `S-1-16-4096` (Low)
  - `S-1-16-8192` (Medium)
  - `S-1-16-12288` (High)
  - `S-1-16-16384` (System)

- **inheritance (optional)**: Specifies how the integrity level should be inherited by child objects.^[6]^ Valid options are:
  - `0`: No inheritance.^[7]^
  - `1`: Object inheritance.^[8]^
  - `2`: Container inheritance.
  - `3`: Both container and object inheritance.^[9]^

### Examples
```
SetObjectIntegrity.exe 1 C:\DirectoryName\FileName.dat S-1-16-4096 0
SetObjectIntegrity.exe 4 CLASSES_ROOT\SomePath S-1-16-8192 3
SetObjectIntegrity.exe 2 ServiceName S-1-16-12288 3
```

## Integrity Levels
Integrity levels are a security feature in Windows that help protect objects from unauthorized modifications. They are part of the Mandatory Integrity Control (MIC) mechanism, which assigns integrity levels to processes and objects to control access permissions.^[10]^ The integrity levels, from lowest to highest, are:

- **Untrusted (S-1-16-0)**: Typically used for objects that should not be trusted.^[11]^
- **Low (S-1-16-4096)**: Used for objects with limited trust, such as files downloaded from the internet.^[12]^
- **Medium (S-1-16-8192)**: Default integrity level for most user files and processes.^[13]^
- **High (S-1-16-12288)**: Used for objects that require a higher level of trust, such as system files.^[14]^
- **System (S-1-16-16384)**: Highest integrity level, used for critical system components.^[15]^

## Inheritance
Inheritance determines how access control entries (ACEs), including integrity levels, are passed down to child objects.^[16]^ The inheritance options are:

- **None**: The integrity level is not inherited by child objects.^[17]^
- **Container**: The integrity level is inherited by container objects (e.g., directories).
- **Object**: The integrity level is inherited by non-container objects (e.g., files).^[18]^
- **Both**: The integrity level is inherited by both container and non-container objects.^[19]^

## Windows Object Types
Windows supports various object types that can be managed using this tool:

- **File (SE_FILE_OBJECT)**: Files and directories in the file system.^[20]^
- **Registry Key (SE_REGISTRY_KEY)**: Keys in the Windows registry.^[21]^
- **Service (SE_SERVICE)**: Windows services.^[22]^
- **Printer (SE_PRINTER)**: Printers and print queues.^[23]^
- **Kernel Object (SE_KERNEL_OBJECT)**: Kernel-mode objects, such as events and semaphores.^[24]^
- **Window (SE_WINDOW_OBJECT)**: Window stations and desktops.^[25]^
- **Directory Service Object (SE_DS_OBJECT)**: Objects in Active Directory.^[26]^

## Additional Notes
- **Privileges**: The tool requires appropriate privileges to modify the security settings of objects. Ensure that the user running the tool has the necessary permissions.^[27]^
- **Verification**: After setting the integrity level, the tool attempts to verify the change by querying the object's security descriptor.^[28]^ This verification step is supported for files and registry keys.^[29]^
- **Error Handling**: The tool provides detailed error messages if any step fails, helping administrators troubleshoot issues.^[30]^

By following this guide, administrators can effectively use the `SetObjectIntegrity` tool to manage integrity levels and enhance the security of Windows objects.