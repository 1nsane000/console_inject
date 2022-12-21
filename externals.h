#pragma once
#include <Windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

#define SE_MIN_WELL_KNOWN_PRIVILEGE (2L)
#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)

#define SE_MACHINE_ACCOUNT_PRIVILEGE (6L)
#define SE_TCB_PRIVILEGE (7L)
#define SE_SECURITY_PRIVILEGE (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (9L)
#define SE_LOAD_DRIVER_PRIVILEGE (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE (11L)
#define SE_SYSTEMTIME_PRIVILEGE (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE (16L)
#define SE_BACKUP_PRIVILEGE (17L)
#define SE_RESTORE_PRIVILEGE (18L)
#define SE_SHUTDOWN_PRIVILEGE (19L)
#define SE_DEBUG_PRIVILEGE (20L)
#define SE_AUDIT_PRIVILEGE (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (24L)
#define SE_UNDOCK_PRIVILEGE (25L)
#define SE_SYNC_AGENT_PRIVILEGE (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE (28L)
#define SE_IMPERSONATE_PRIVILEGE (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE (32L)
#define SE_INC_WORKING_SET_PRIVILEGE (33L)
#define SE_TIME_ZONE_PRIVILEGE (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (35L)
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE (36L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE


#pragma comment( lib, "ntdll.lib" )

extern "C" {

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtAdjustPrivilegesToken(
            _In_ HANDLE TokenHandle,
            _In_ BOOLEAN DisableAllPrivileges,
            _In_opt_ PTOKEN_PRIVILEGES NewState,
            _In_ ULONG BufferLength,
            _Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
            _Out_opt_ PULONG ReturnLength
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtOpenProcessToken(
            _In_ HANDLE ProcessHandle,
            _In_ ACCESS_MASK DesiredAccess,
            _Out_ PHANDLE TokenHandle
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtClose(
            _In_ _Post_ptr_invalid_ HANDLE Handle
        );



}