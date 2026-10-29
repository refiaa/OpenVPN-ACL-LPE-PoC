#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>

#define SERVICE_NAME L"OpenVPNServiceInteractive"
#define MARKER_PATH "C:\\ProgramData\\OpenVPNPrefixAclLocalSystemPoC\\protected-marker.json"
#define MAX_SERVICE_RUNTIME_MILLISECONDS 60000

static SERVICE_STATUS_HANDLE service_status_handle = NULL;
static SERVICE_STATUS service_status;
static HANDLE stop_event = NULL;

static void report_status(DWORD state, DWORD error, DWORD wait_hint)
{
    static DWORD checkpoint = 1;
    ZeroMemory(&service_status, sizeof(service_status));
    service_status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    service_status.dwCurrentState = state;
    service_status.dwWin32ExitCode = error;
    service_status.dwWaitHint = wait_hint;
    service_status.dwControlsAccepted =
        state == SERVICE_RUNNING ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    service_status.dwCheckPoint =
        (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? checkpoint++ : 0;
    SetServiceStatus(service_status_handle, &service_status);
}

static int write_identity_observation(void)
{
    HANDLE token = NULL;
    HANDLE marker = INVALID_HANDLE_VALUE;
    TOKEN_USER *token_user = NULL;
    LPSTR sid_text = NULL;
    DWORD token_size = 0;
    DWORD name_size = 0;
    DWORD domain_size = 0;
    SID_NAME_USE sid_type;
    char name[256] = { 0 };
    char domain[256] = { 0 };
    char identity[520] = { 0 };
    char json[1600] = { 0 };
    DWORD written = 0;
    int success = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        goto cleanup;
    }
    GetTokenInformation(token, TokenUser, NULL, 0, &token_size);
    if (token_size == 0) {
        goto cleanup;
    }
    token_user = (TOKEN_USER *)LocalAlloc(LPTR, token_size);
    if (!token_user
        || !GetTokenInformation(token, TokenUser, token_user, token_size, &token_size)) {
        goto cleanup;
    }
    if (!ConvertSidToStringSidA(token_user->User.Sid, &sid_text)) {
        goto cleanup;
    }
    name_size = (DWORD)sizeof(name);
    domain_size = (DWORD)sizeof(domain);
    if (!LookupAccountSidA(NULL, token_user->User.Sid, name, &name_size,
                           domain, &domain_size, &sid_type)) {
        goto cleanup;
    }
    if (domain[0] != '\0') {
        _snprintf_s(identity, sizeof(identity), _TRUNCATE, "%s\\\\%s", domain, name);
    } else {
        _snprintf_s(identity, sizeof(identity), _TRUNCATE, "%s", name);
    }
    _snprintf_s(json, sizeof(json), _TRUNCATE,
                "{\"executed\":true,\"pid\":%lu,\"identity\":\"%s\","
                "\"sid\":\"%s\",\"service\":\"OpenVPNServiceInteractive\"}\r\n",
                (unsigned long)GetCurrentProcessId(), identity, sid_text);

    marker = CreateFileA(MARKER_PATH, GENERIC_WRITE, FILE_SHARE_READ,
                         NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (marker == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }
    if (!WriteFile(marker, json, (DWORD)strlen(json), &written, NULL)
        || written != (DWORD)strlen(json)
        || !FlushFileBuffers(marker)) {
        goto cleanup;
    }
    success = 1;

cleanup:
    if (marker != INVALID_HANDLE_VALUE) {
        CloseHandle(marker);
    }
    if (sid_text) {
        LocalFree(sid_text);
    }
    if (token_user) {
        LocalFree(token_user);
    }
    if (token) {
        CloseHandle(token);
    }
    return success;
}

static DWORD WINAPI service_control(DWORD control, DWORD event_type,
                                    LPVOID event_data, LPVOID context)
{
    (void)event_type;
    (void)event_data;
    (void)context;
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        report_status(SERVICE_STOP_PENDING, NO_ERROR, 2000);
        SetEvent(stop_event);
        return NO_ERROR;
    }
    if (control == SERVICE_CONTROL_INTERROGATE) {
        SetServiceStatus(service_status_handle, &service_status);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static VOID WINAPI service_main(DWORD argc, LPWSTR *argv)
{
    DWORD error = NO_ERROR;
    (void)argc;
    (void)argv;
    service_status_handle =
        RegisterServiceCtrlHandlerExW(SERVICE_NAME, service_control, NULL);
    if (!service_status_handle) {
        return;
    }
    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop_event) {
        error = GetLastError();
        report_status(SERVICE_STOPPED, error, 0);
        return;
    }
    if (!write_identity_observation()) {
        error = GetLastError();
        if (error == NO_ERROR) {
            error = ERROR_WRITE_FAULT;
        }
        CloseHandle(stop_event);
        stop_event = NULL;
        report_status(SERVICE_STOPPED, error, 0);
        return;
    }
    report_status(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(stop_event, MAX_SERVICE_RUNTIME_MILLISECONDS);
    CloseHandle(stop_event);
    stop_event = NULL;
    report_status(SERVICE_STOPPED, NO_ERROR, 0);
}

int main(void)
{
    SERVICE_TABLE_ENTRYW dispatch_table[] = {
        { SERVICE_NAME, service_main },
        { NULL, NULL }
    };
    return StartServiceCtrlDispatcherW(dispatch_table) ? 0 : 1;
}
