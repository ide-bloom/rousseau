//! Provider GUIDs, keywords and event ids.
//!
//! Every value here was read from the provider manifests installed on
//! Windows 11 (`wevtutil gp <provider> /ge` for GUIDs, keywords and event
//! ids, `Get-WinEvent -ListProvider <provider>` for templates). See
//! `docs/etw-providers.md` for field layouts and how to re-verify.

/// `Microsoft-Windows-Kernel-Process`.
pub mod kernel_process {
    pub const NAME: &str = "Microsoft-Windows-Kernel-Process";
    pub const GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
    pub const KEYWORD_PROCESS: u64 = 0x10;
    pub const KEYWORD_IMAGE: u64 = 0x40;
    /// ProcessStart: ProcessID, CreateTime, ParentProcessID, SessionID, …, ImageName.
    pub const EVENT_PROCESS_START: u16 = 1;
    /// ProcessStop: ProcessID, CreateTime, ExitTime, ExitCode, …, ImageName (ANSI).
    pub const EVENT_PROCESS_STOP: u16 = 2;
    /// ImageLoad: ImageBase, ImageSize, ProcessID, …, ImageName.
    pub const EVENT_IMAGE_LOAD: u16 = 5;
}

/// `Microsoft-Windows-Kernel-File`.
pub mod kernel_file {
    pub const NAME: &str = "Microsoft-Windows-Kernel-File";
    pub const GUID: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
    pub const KEYWORD_FILENAME: u64 = 0x10;
    pub const KEYWORD_FILEIO: u64 = 0x20;
    pub const KEYWORD_CREATE: u64 = 0x80;
    pub const KEYWORD_READ: u64 = 0x100;
    pub const KEYWORD_WRITE: u64 = 0x200;
    pub const KEYWORD_DELETE_PATH: u64 = 0x400;
    pub const KEYWORD_RENAME_SETLINK_PATH: u64 = 0x800;
    pub const KEYWORD_CREATE_NEW_FILE: u64 = 0x1000;
    /// Create (open): Irp, FileObject, IssuingThreadId, CreateOptions, CreateAttributes, ShareAccess, FileName.
    pub const EVENT_CREATE: u16 = 12;
    /// Close: Irp, FileObject, FileKey, IssuingThreadId.
    pub const EVENT_CLOSE: u16 = 14;
    /// Read: ByteOffset, Irp, FileObject, FileKey, IssuingThreadId, IOSize, IOFlags, ExtraFlags.
    pub const EVENT_READ: u16 = 15;
    /// Write: same layout as Read.
    pub const EVENT_WRITE: u16 = 16;
    /// DeletePath: Irp, FileObject, FileKey, ExtraInformation, IssuingThreadId, InfoClass, FilePath.
    pub const EVENT_DELETE_PATH: u16 = 26;
    /// RenamePath: same layout as DeletePath; FilePath is the new name.
    pub const EVENT_RENAME_PATH: u16 = 27;
    /// CreateNewFile: same layout as Create.
    pub const EVENT_CREATE_NEW_FILE: u16 = 30;
}

/// `Microsoft-Windows-Kernel-Network`.
pub mod kernel_network {
    pub const NAME: &str = "Microsoft-Windows-Kernel-Network";
    pub const GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
    pub const KEYWORD_IPV4: u64 = 0x10;
    pub const KEYWORD_IPV6: u64 = 0x20;
    /// TCPv4 send/recv/connect/disconnect/accept; fields PID, size, daddr, saddr, dport, sport, …, connid.
    pub const TCP4_SEND: u16 = 10;
    pub const TCP4_RECV: u16 = 11;
    pub const TCP4_CONNECT: u16 = 12;
    pub const TCP4_DISCONNECT: u16 = 13;
    pub const TCP4_ACCEPT: u16 = 15;
    /// TCPv6 equivalents (addresses are 16-byte binary).
    pub const TCP6_SEND: u16 = 26;
    pub const TCP6_RECV: u16 = 27;
    pub const TCP6_CONNECT: u16 = 28;
    pub const TCP6_DISCONNECT: u16 = 29;
    pub const TCP6_ACCEPT: u16 = 31;
    /// UDP send/recv.
    pub const UDP4_SEND: u16 = 42;
    pub const UDP4_RECV: u16 = 43;
    pub const UDP6_SEND: u16 = 58;
    pub const UDP6_RECV: u16 = 59;
}

/// `Microsoft-Windows-DNS-Client`.
pub mod dns_client {
    pub const NAME: &str = "Microsoft-Windows-DNS-Client";
    pub const GUID: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
    /// Query started: QueryName, QueryType, QueryOptions, ServerList, …
    pub const EVENT_QUERY: u16 = 3006;
    /// Query completed: QueryName, QueryType, QueryOptions, QueryStatus, QueryResults.
    pub const EVENT_QUERY_COMPLETE: u16 = 3008;
}

/// `Microsoft-Windows-Kernel-Registry`.
pub mod kernel_registry {
    pub const NAME: &str = "Microsoft-Windows-Kernel-Registry";
    pub const GUID: &str = "70eb4f03-c1de-4f73-a051-33d13d5413bd";
    pub const KEYWORD_SET_VALUE_KEY: u64 = 0x100;
    pub const KEYWORD_DELETE_VALUE_KEY: u64 = 0x200;
    pub const KEYWORD_CREATE_KEY: u64 = 0x1000;
    pub const KEYWORD_OPEN_KEY: u64 = 0x2000;
    /// CreateKey / OpenKey: BaseObject, KeyObject, Status, Disposition, BaseName, RelativeName.
    pub const EVENT_CREATE_KEY: u16 = 1;
    pub const EVENT_OPEN_KEY: u16 = 2;
    /// SetValueKey: KeyObject, Status, Type, DataSize, KeyName, ValueName, CapturedDataSize, CapturedData, …
    pub const EVENT_SET_VALUE_KEY: u16 = 5;
    /// DeleteValueKey: KeyObject, Status, KeyName, ValueName.
    pub const EVENT_DELETE_VALUE_KEY: u16 = 6;
}

/// Name of Rousseau's real-time ETW session.
pub const SESSION_NAME: &str = "Rousseau-Sensor";
