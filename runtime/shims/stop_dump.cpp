// A minimal stop report: on the first exception, write the registers, the faulting site and the memory the
// argument registers point at. Enabled with LEONIDA_STOP_DUMP=<file>; silent otherwise. Windows only, and gta6rt
// only runs on Windows.
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>

namespace {

FILE* g_file = nullptr;
bool g_ready = false;
DWORD g_tid = 0;

uint64_t g_game_base = 0, g_game_end = 0;

const char* module_of(void* address, uintptr_t& rva) {
    const auto a = reinterpret_cast<uint64_t>(address);
    if (g_game_base && a >= g_game_base && a < g_game_end) {
        rva = a - g_game_base;
        return "title";
    }
    HMODULE mod = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(address), &mod))
        return "?";
    rva = reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(mod);
    static char name[MAX_PATH];
    char full[MAX_PATH];
    if (!GetModuleFileNameA(mod, full, MAX_PATH)) return "?";
    const char* slash = std::strrchr(full, '\\');
    std::snprintf(name, sizeof name, "%s", slash ? slash + 1 : full);
    return name;
}

bool readable(uint64_t address, size_t len);  // defined below

// A broken stack does not stop the written words from being read: any eight-byte value inside the title's image is
// almost certainly a return address. They are listed in stack order, which is call order.
void scan_stack(uint64_t rsp) {
    if (!g_file || !rsp) return;
    constexpr size_t kScan = 4096;
    if (!readable(rsp, kScan)) {
        std::fprintf(g_file, "\n[stack] %p not readable\n", reinterpret_cast<const void*>(rsp));
        return;
    }
    std::fprintf(g_file, "\n[stack] possible returns into the image or a host module, from %p:\n",
                 reinterpret_cast<const void*>(rsp));
    const auto* slots = reinterpret_cast<const uint64_t*>(rsp);
    unsigned shown = 0;
    for (size_t i = 0; i < kScan / 8 && shown < 24; ++i) {
        const uint64_t value = slots[i];
        if (g_game_base && value >= g_game_base && value < g_game_end) {
            std::fprintf(g_file, "  +%#04zx  title+%#llx\n", i * 8,
                         static_cast<unsigned long long>(value - g_game_base));
            ++shown;
            continue;
        }
        HMODULE mod = nullptr;
        if (value > 0x10000 &&
            GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(value), &mod) && mod) {
            std::fprintf(g_file, "  +%#04zx  host+%#llx\n", i * 8,
                         static_cast<unsigned long long>(value - reinterpret_cast<uint64_t>(mod)));
            ++shown;
        }
    }
    if (!shown) std::fprintf(g_file, "  (none)\n");
    std::fflush(g_file);
}

// Is this range readable? Ask before touching it: a register dump usually points at memory that is not there, and
// raising inside the exception handler only adds noise and hides the real fault.
bool readable(uint64_t address, size_t len) {
    if (len == 0) return false;
    uint64_t at = address;
    const uint64_t end = address + len;
    // An argument register is often -1 (an empty handle or an "infinite" count). Adding the length wraps and the
    // range would look empty, so the check would say it is readable and the dump would read 0xFFFFFFFFFFFFFFFF.
    // Reject it before asking.
    if (end < address) return false;
    while (at < end) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(at), &info, sizeof info) == 0) return false;
        if (info.State != MEM_COMMIT) return false;
        if (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
        const uint64_t next = reinterpret_cast<uint64_t>(info.BaseAddress) + info.RegionSize;
        if (next <= at) return false;
        at = next;
    }
    return true;
}

void hexdump(const char* label, const void* p, size_t len) {
    if (!g_file || !p) return;
    if (!readable(reinterpret_cast<uint64_t>(p), len)) {
        std::fprintf(g_file, "\n[%s] %p (%zu bytes) not readable\n", label, p, len);
        std::fflush(g_file);
        return;
    }
    std::fprintf(g_file, "\n[%s] %p (%zu bytes)\n", label, p, len);
    const auto* b = static_cast<const unsigned char*>(p);
    for (size_t i = 0; i < len; i += 16) {
        std::fprintf(g_file, "  %p  ", static_cast<const void*>(b + i));
        for (size_t j = 0; j < 16; ++j) std::fprintf(g_file, "%02x ", i + j < len ? b[i + j] : 0);
        std::fprintf(g_file, " |");
        for (size_t j = 0; j < 16 && i + j < len; ++j) {
            const unsigned char c = b[i + j];
            std::fputc(c >= 0x20 && c < 0x7f ? c : '.', g_file);
        }
        std::fprintf(g_file, "|\n");
    }
    std::fflush(g_file);
}

// Defensive copy: the range may not be readable, and a dump must not take the process down.
void safe_dump(const char* label, uint64_t address, size_t len) {
    if (!g_file || address < 0x10000) return;
    __try {
        hexdump(label, reinterpret_cast<const void*>(address), len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        std::fprintf(g_file, "\n[%s] %p not readable\n", label, reinterpret_cast<const void*>(address));
        std::fflush(g_file);
    }
}

LONG CALLBACK on_exception(EXCEPTION_POINTERS* info) {
    if (!g_ready || !info || !info->ExceptionRecord || !info->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;
    // The title runs on its own thread, so this does not filter by thread: the first stop is the one that matters.
    if (info->ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) return EXCEPTION_CONTINUE_SEARCH;

    uintptr_t rva = 0;
    const char* mod = module_of(info->ExceptionRecord->ExceptionAddress, rva);

    // Only the title's own modules, and once per address: the process can repeat the same fault in a loop.
    struct Seen {
        uint32_t code;
        uintptr_t addr;
    };
    static Seen seen[64];
    static int seen_count = 0;
    for (int i = 0; i < seen_count; ++i)
        if (seen[i].code == info->ExceptionRecord->ExceptionCode && seen[i].addr == rva)
            return EXCEPTION_CONTINUE_SEARCH;
    if (seen_count < 64) seen[seen_count++] = {info->ExceptionRecord->ExceptionCode, rva};
    std::fprintf(g_file, "\n== stop: code=0x%08lX at %s+0x%llx (tid %lu)\n",
                 static_cast<unsigned long>(info->ExceptionRecord->ExceptionCode), mod,
                 static_cast<unsigned long long>(rva), GetCurrentThreadId());

    const CONTEXT* c = info->ContextRecord;
    std::fprintf(g_file, "  rax=%016llx rbx=%016llx rcx=%016llx rdx=%016llx\n", c->Rax, c->Rbx, c->Rcx, c->Rdx);
    std::fprintf(g_file, "  rsi=%016llx rdi=%016llx rbp=%016llx rsp=%016llx\n", c->Rsi, c->Rdi, c->Rbp, c->Rsp);
    std::fprintf(g_file, "  r8 =%016llx r9 =%016llx r10=%016llx r11=%016llx\n", c->R8, c->R9, c->R10, c->R11);
    std::fprintf(g_file, "  r12=%016llx r13=%016llx r14=%016llx r15=%016llx\n", c->R12, c->R13, c->R14, c->R15);
    // XMM: a title comparing a computed float against a threshold keeps the value that matters here, not in the
    // general registers.
    for (int i = 0; i < 8; ++i) {
        const M128A& x = (&c->Xmm0)[i];
        float as_float = 0.0f;
        double as_double = 0.0;
        std::memcpy(&as_float, &x.Low, sizeof as_float);
        std::memcpy(&as_double, &x.Low, sizeof as_double);
        std::fprintf(g_file, "  xmm%d = %016llx (float %.6f · double %.6f)\n", i,
                     static_cast<unsigned long long>(x.Low), static_cast<double>(as_float), as_double);
    }
    std::fflush(g_file);
    scan_stack(c->Rsp);

    // The four argument registers: what the check was looking at.
    safe_dump("rcx", c->Rcx, 512);
    safe_dump("rdx", c->Rdx, 1024);
    safe_dump("r8", c->R8, 512);
    safe_dump("r9", c->R9, 512);
    safe_dump("rsp", c->Rsp, 256);
    safe_dump("rsi", c->Rsi, 96);
    safe_dump("rdi", c->Rdi, 96);

    std::fprintf(g_file, "\n== end of report\n");
    std::fflush(g_file);
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

namespace rt::diag {

// `std::terminate` is the one stop with no exception record to catch: it runs when no handler is installed, when a
// `std::thread` is destroyed while joinable, when an exception escapes a thread's entry, or when a `noexcept`
// function throws. Without this the run only prints "terminate called without an active exception" and leaves,
// naming no thread and no site. The frames go through the same module+RVA map the exception reporter uses.
void install_terminate_trace() {
    std::set_terminate([] {
        std::fprintf(stderr, "[rt] terminate: uncaught exception or joinable thread destroyed\n");
        if (std::exception_ptr current = std::current_exception()) {
            try {
                std::rethrow_exception(current);
            } catch (const std::exception& e) {
                std::fprintf(stderr, "[rt] terminate: what(): %s\n", e.what());
            } catch (...) {
                std::fprintf(stderr, "[rt] terminate: non-std exception\n");
            }
        }
        void* frames[48] = {};
        const USHORT count = CaptureStackBackTrace(0, 48, frames, nullptr);
        for (USHORT i = 0; i < count; ++i) {
            uintptr_t rva = 0;
            const char* module = module_of(frames[i], rva);
            std::fprintf(stderr, "[rt] terminate: #%u %s+0x%llx\n", i, module, static_cast<unsigned long long>(rva));
        }
        std::fflush(stderr);
        std::abort();
    });
}

// Called once, before the title runs. Silent when the variable is not set.
void install_stop_dump(void* base, size_t size) {
    g_game_base = reinterpret_cast<uint64_t>(base);
    g_game_end = g_game_base + size;
    if (g_ready) return;
    const char* path = std::getenv("LEONIDA_STOP_DUMP");
    if (!path || !*path) return;
    g_file = std::fopen(path, "ab");
    if (!g_file) {
        std::fprintf(stderr, "[rt] LEONIDA_STOP_DUMP: cannot open %s\n", path);
        return;
    }
    g_tid = GetCurrentThreadId();
    std::fprintf(g_file, "\n# stop report · pid %lu · thread %lu\n", GetCurrentProcessId(), g_tid);
    std::fflush(g_file);
    AddVectoredExceptionHandler(1, &on_exception);
    g_ready = true;
    std::fprintf(stderr, "[rt] LEONIDA_STOP_DUMP: report in %s\n", path);
}

}  // namespace rt::diag
