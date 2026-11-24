# ETW providers

All GUIDs, keyword masks, event ids and field layouts used by `rousseau-etw` were read from the manifests installed on Windows 11, not taken from secondary sources. Constants live in `crates/rousseau-etw/src/providers.rs`.

## Re-verifying

```powershell
wevtutil gp Microsoft-Windows-Kernel-Process /ge /gm:false     # GUID, keywords, events
(Get-WinEvent -ListProvider Microsoft-Windows-Kernel-Process).Events |
  Where-Object Id -in 1,2,5 | ForEach-Object { $_.Id; $_.Template }   # field templates
logman query providers Microsoft-Windows-Kernel-File
```

## Providers

| Provider | GUID | Keywords enabled | Events used |
|---|---|---|---|
| Microsoft-Windows-Kernel-Process | `22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716` | `0x10` PROCESS, `0x40` IMAGE | 1 ProcessStart, 2 ProcessStop, 5 ImageLoad |
| Microsoft-Windows-Kernel-File | `edd08927-9cc4-4e65-b970-c2560fb5c289` | `0x10` FILENAME, `0x20` FILEIO, `0x80` CREATE, `0x100` READ, `0x200` WRITE, `0x400` DELETE_PATH, `0x800` RENAME_SETLINK_PATH, `0x1000` CREATE_NEW_FILE | 12 Create, 14 Close, 15 Read, 16 Write, 26 DeletePath, 27 RenamePath, 30 CreateNewFile |
| Microsoft-Windows-Kernel-Network | `7dd42a49-5329-4832-8dfd-43d979153a88` | `0x10` IPV4, `0x20` IPV6 | TCP: 10/26 send, 11/27 recv, 12/28 connect, 13/29 disconnect, 15/31 accept; UDP: 42/58 send |
| Microsoft-Windows-DNS-Client | `1c95126e-7eea-49a9-a3fe-a378b03ddb4d` | all | 3006 query |
| Microsoft-Windows-Kernel-Registry | `70eb4f03-c1de-4f73-a051-33d13d5413bd` | `0x100` SetValueKey, `0x200` DeleteValueKey, `0x1000` CreateKey, `0x2000` OpenKey | 1 CreateKey, 2 OpenKey, 5 SetValueKey, 6 DeleteValueKey |

## Field layouts relied on

- **ProcessStart (1)**: `ProcessID`, `CreateTime` (FILETIME), `ParentProcessID`, `ImageName` (NT device path, normalized with `QueryDosDeviceW`). The command line is not part of the event; Rousseau reads it with `NtQueryInformationProcess(ProcessCommandLineInformation)` for candidate agents and children of tracked processes.
- **ProcessStop (2)**: `ProcessID`, `ExitCode`.
- **ImageLoad (5)**: `ProcessID`, `ImageName`.
- **Kernel-File**: the acting process is the event header's process id. `Create`/`CreateNewFile` carry `FileObject` and `FileName`; `Read`/`Write`/`Close` carry `FileObject` only, so paths come from a FileObject → path map filled on create and cleared on close. `DeletePath`/`RenamePath` carry `FilePath` (for renames, the new name).
- **Kernel-Network**: `PID` (payload, not header), `size`, `daddr`/`saddr` (4 bytes for IPv4, 16 for IPv6), `dport`/`sport` (UInt16 in network byte order), `connid`.
- **DNS-Client 3006**: `QueryName`, `QueryType`; acting process from the header.
- **Kernel-Registry**: `KeyObject`, `BaseObject`, `BaseName`, `RelativeName` (create/open) build a KeyObject → path map; `SetValueKey` carries `KeyName` (sometimes empty, then resolved from the map), `ValueName`, `Type`, `CapturedData`. Only writes under security-relevant keys are recorded (`decode::is_security_relevant_key`).

## Session handling

- One real-time session named `Rousseau-Sensor`. A session left behind by a crashed instance is stopped before starting.
- Lost events and lost real-time buffers are read with `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)` and reported in sensor health.
- Drive mappings are refreshed every minute.
