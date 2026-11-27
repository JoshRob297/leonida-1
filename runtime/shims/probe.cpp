// A single-point probe: LEONIDA_PROBE=<rva>[,<rva>...] places an int3 at that address in the title, and on every hit
// writes the registers, the id in rbx and the memory the pointers name, then continues. It disarms itself after N
// hits per address so the report does not flood.
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

FILE* g_file = nullptr;
uint64_t g_game_base = 0, g_game_end = 0;
uint32_t g_hits = 0;
const uint32_t kMaxHits = 24;

struct Probe {
    uint64_t rva;
    unsigned char original;
    bool armed;
};

Probe g_probes[8];
int g_probe_count = 0;
Probe* g_stepping = nullptr;

void hexdump(const char* label, uint64_t address, size_t len) {
    if (!g_file || address < 0x10000) return;
    __try {
        std::fprintf(g_file, "\n[%s] %016llx (%zu bytes)\n", label, static_cast<unsigned long long>(address), len);
        const auto* b = reinterpret_cast<const unsigned char*>(address);
        for (size_t i = 0; i < len; i += 16) {
            std::fprintf(g_file, "  %016llx  ", static_cast<unsigned long long>(address + i));
            for (size_t j = 0; j < 16; ++j) std::fprintf(g_file, "%02x ", i + j < len ? b[i + j] : 0);
            std::fprintf(g_file, "\n");
        }
        std::fflush(g_file);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        std::fprintf(g_file, "\n[%s] %016llx not readable\n", label, static_cast<unsigned long long>(address));
        std::fflush(g_file);
    }
}

void arm(Probe& p) {
    auto* at = reinterpret_cast<unsigned char*>(g_game_base + p.rva);
    if (!p.armed) {
        p.original = *at;
        DWORD old = 0;
        VirtualProtect(at, 1, PAGE_EXECUTE_READWRITE, &old);
        *at = 0xCC;
        VirtualProtect(at, 1, old, &old);
        FlushInstructionCache(GetCurrentProcess(), at, 1);
        p.armed = true;
    }
}

void disarm(Probe& p) {
    if (!p.armed) return;
    auto* at = reinterpret_cast<unsigned char*>(g_game_base + p.rva);
    DWORD old = 0;
    VirtualProtect(at, 1, PAGE_EXECUTE_READWRITE, &old);
    *at = p.original;
    VirtualProtect(at, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), at, 1);
    p.armed = false;
}

LONG CALLBACK on_exception(EXCEPTION_POINTERS* info) {
    if (!g_file || !info || !info->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    const DWORD code = info->ExceptionRecord->ExceptionCode;

    // Single step after disarming: re-arm and carry on where it was.
    if (code == EXCEPTION_SINGLE_STEP && g_stepping) {
        arm(*g_stepping);
        g_stepping = nullptr;
        info->ContextRecord->EFlags &= ~0x100u;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;
    const uint64_t at = reinterpret_cast<uint64_t>(info->ExceptionRecord->ExceptionAddress);
    for (int i = 0; i < g_probe_count; ++i) {
        Probe& p = g_probes[i];
        if (g_game_base + p.rva != at) continue;
        const CONTEXT* c = info->ContextRecord;
        std::fprintf(g_file, "\n== probe +0x%llx (hit %u)\n", static_cast<unsigned long long>(p.rva), ++g_hits);
        std::fprintf(g_file, "  rax=%016llx rbx=%016llx rcx=%016llx rdx=%016llx\n", c->Rax, c->Rbx, c->Rcx, c->Rdx);
        std::fprintf(g_file, "  rsi=%016llx rdi=%016llx r8 =%016llx r9 =%016llx\n", c->Rsi, c->Rdi, c->R8, c->R9);
        std::fprintf(g_file, "  id in rbx (dword) = 0x%08lx\n", static_cast<unsigned long>(c->Rbx & 0xffffffffu));
        std::fflush(g_file);
        hexdump("rbx", c->Rbx, 32);
        hexdump("rsp", c->Rsp, 0x60);
        disarm(p);
        if (g_hits >= kMaxHits) return EXCEPTION_CONTINUE_SEARCH;
        g_stepping = &p;
        info->ContextRecord->EFlags |= 0x100u;  // trap flag: one step, then re-arm
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

namespace rt::diag {

void install_probe(void* base, size_t size) {
    if (g_file) return;
    const char* spec = std::getenv("LEONIDA_PROBE");
    const char* file = std::getenv("LEONIDA_PROBE_LOG");
    if (!spec || !*spec) return;
    g_file = std::fopen(file && *file ? file : "leonida-probe.log", "ab");
    if (!g_file) return;
    g_game_base = reinterpret_cast<uint64_t>(base);
    g_game_end = g_game_base + size;

    char buf[256];
    std::snprintf(buf, sizeof buf, "%s", spec);
    for (char* tok = std::strtok(buf, ","); tok && g_probe_count < 8; tok = std::strtok(nullptr, ",")) {
        g_probes[g_probe_count].rva = std::strtoull(tok, nullptr, 0);
        g_probes[g_probe_count].armed = false;
        arm(g_probes[g_probe_count]);
        ++g_probe_count;
    }
    AddVectoredExceptionHandler(1, &on_exception);
    std::fprintf(stderr, "[rt] LEONIDA_PROBE: %d probe(s) armed\n", g_probe_count);
}

}  // namespace rt::diag
