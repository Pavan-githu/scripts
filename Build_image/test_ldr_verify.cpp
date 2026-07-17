/**
 * test_ldr_verify.cpp
 *
 * Standalone local test for verifyLdrHeader().
 * Compiled and run on the host — no cross-toolchain needed.
 *
 * Build:
 *   g++ -std=c++11 -o test_ldr_verify test_ldr_verify.cpp && ./test_ldr_verify
 */

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdint>
#include <string>

// ============================================================================
// FirmwareHeader — must match the layout in firmwareupdate.h exactly
// ============================================================================
static constexpr uint8_t  LDR_MAGIC[4]    = {'R', 'P', 'I', 'F'};
static constexpr uint16_t LDR_HDR_VERSION = 1;
static constexpr uint16_t LDR_HDR_SIZE    = 116;

typedef struct __attribute__((packed)) {
    uint8_t  magic[4];        /* "RPIF"                              */
    uint16_t hdr_version;     /* must be 1                           */
    uint16_t hdr_size;        /* must be 116                         */
    char     fw_version[32];  /* e.g. "v0.1.0\0..."                  */
    char     timestamp[32];   /* e.g. "2026-06-29T16:36:52Z\0..."    */
    uint8_t  sha256[32];      /* raw SHA-256 digest of payload       */
    uint64_t payload_size;    /* byte count of the payload region    */
    uint32_t hdr_crc32;       /* CRC32/ISO-HDLC of header[0..111]   */
} FirmwareHeader;

// ============================================================================
// CRC-32/ISO-HDLC  (poly 0xEDB88320, init 0xFFFFFFFF, final XOR 0xFFFFFFFF)
// ============================================================================
static uint32_t crc32Compute(const uint8_t* data, size_t len)
{
    struct Table {
        uint32_t t[256];
        Table() {
            for (uint32_t i = 0; i < 256; ++i) {
                uint32_t c = i;
                for (int k = 0; k < 8; ++k)
                    c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
                t[i] = c;
            }
        }
    };
    static const Table tbl;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i)
        crc = tbl.t[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

// ============================================================================
// verifyLdrHeader — mirrors FirmwareUpdateManager::verifyLdrHeader()
// ============================================================================
static bool verifyLdrHeader(const std::string& ldr_path,
                             FirmwareHeader&    header_out,
                             std::string&       error_out)
{
    std::ifstream ifs(ldr_path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        error_out = "Cannot open file: " + ldr_path;
        return false;
    }
    const std::streamoff file_size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    if (file_size < static_cast<std::streamoff>(LDR_HDR_SIZE)) {
        error_out = "File too small (" + std::to_string(static_cast<long long>(file_size)) + " bytes)";
        return false;
    }

    FirmwareHeader hdr;
    if (!ifs.read(reinterpret_cast<char*>(&hdr), sizeof(hdr))) {
        error_out = "Failed to read header";
        return false;
    }
    ifs.close();

    // 1. Magic
    if (std::memcmp(hdr.magic, LDR_MAGIC, 4) != 0) {
        error_out = std::string("Invalid magic: expected 'RPIF', got '")
                    + static_cast<char>(hdr.magic[0])
                    + static_cast<char>(hdr.magic[1])
                    + static_cast<char>(hdr.magic[2])
                    + static_cast<char>(hdr.magic[3]) + "'";
        return false;
    }

    // 2. Header version
    if (hdr.hdr_version != LDR_HDR_VERSION) {
        error_out = "Unsupported hdr_version: " + std::to_string(hdr.hdr_version)
                    + " (expected " + std::to_string(LDR_HDR_VERSION) + ")";
        return false;
    }

    // 3. Header size field
    if (hdr.hdr_size != LDR_HDR_SIZE) {
        error_out = "Unexpected hdr_size: " + std::to_string(hdr.hdr_size)
                    + " (expected " + std::to_string(LDR_HDR_SIZE) + ")";
        return false;
    }

    // 4. CRC32 of bytes 0..111
    const size_t   covered = LDR_HDR_SIZE - sizeof(uint32_t); // 112
    const uint32_t computed = crc32Compute(reinterpret_cast<const uint8_t*>(&hdr), covered);
    if (computed != hdr.hdr_crc32) {
        std::ostringstream oss;
        oss << std::hex << std::uppercase
            << "CRC32 mismatch: computed 0x" << computed
            << ", stored 0x" << hdr.hdr_crc32;
        error_out = oss.str();
        return false;
    }

    // 5. fw_version null-terminated
    bool fv_ok = false;
    for (int i = 0; i < 32; ++i) if (hdr.fw_version[i] == '\0') { fv_ok = true; break; }
    if (!fv_ok) { error_out = "fw_version not null-terminated"; return false; }

    // 6. timestamp null-terminated
    bool ts_ok = false;
    for (int i = 0; i < 32; ++i) if (hdr.timestamp[i] == '\0') { ts_ok = true; break; }
    if (!ts_ok) { error_out = "timestamp not null-terminated"; return false; }

    // 7. payload_size vs file size
    const uint64_t expected_total = static_cast<uint64_t>(LDR_HDR_SIZE) + hdr.payload_size;
    if (static_cast<uint64_t>(file_size) != expected_total) {
        error_out = "Size mismatch: header says payload=" + std::to_string(hdr.payload_size)
                    + " bytes (total=" + std::to_string(expected_total)
                    + "), but file is " + std::to_string(static_cast<uint64_t>(file_size)) + " bytes";
        return false;
    }

    header_out = hdr;
    return true;
}

// ============================================================================
// Helper: bytes → hex string
// ============================================================================
static std::string toHex(const uint8_t* buf, size_t len)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<unsigned int>(buf[i]);
    return ss.str();
}

// ============================================================================
// main
// ============================================================================
int main()
{
    const std::string ldr_path =
        "/home/pg3930/capstone1/raceiotprj/scripts/Build_image/RPIF_v0.1.0.ldr";

    std::cout << "==================================================" << std::endl;
    std::cout << "  .ldr Header Verification Test" << std::endl;
    std::cout << "  File: " << ldr_path << std::endl;
    std::cout << "==================================================" << std::endl;

    FirmwareHeader hdr;
    std::string    error;

    // --- Run each check individually and report ---
    auto checkStep = [](const std::string& name, bool ok, const std::string& detail) {
        std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] " << name;
        if (!detail.empty()) std::cout << " — " << detail;
        std::cout << std::endl;
    };

    // Open file
    std::ifstream ifs(ldr_path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        std::cerr << "[FAIL] Cannot open: " << ldr_path << std::endl;
        return 1;
    }
    const uint64_t file_size = static_cast<uint64_t>(ifs.tellg());
    ifs.seekg(0, std::ios::beg);

    std::cout << "\nFile size: " << file_size << " bytes\n\n";

    FirmwareHeader raw;
    ifs.read(reinterpret_cast<char*>(&raw), sizeof(raw));
    ifs.close();

    // Check 1: magic
    bool m_ok = (std::memcmp(raw.magic, LDR_MAGIC, 4) == 0);
    checkStep("Magic bytes",
              m_ok,
              std::string("'")
              + static_cast<char>(raw.magic[0])
              + static_cast<char>(raw.magic[1])
              + static_cast<char>(raw.magic[2])
              + static_cast<char>(raw.magic[3]) + "'");

    // Check 2: hdr_version
    bool v_ok = (raw.hdr_version == LDR_HDR_VERSION);
    checkStep("Header version",
              v_ok,
              "hdr_version=" + std::to_string(raw.hdr_version) + " (expected 1)");

    // Check 3: hdr_size
    bool s_ok = (raw.hdr_size == LDR_HDR_SIZE);
    checkStep("Header size field",
              s_ok,
              "hdr_size=" + std::to_string(raw.hdr_size) + " (expected 116)");

    // Check 4: CRC32
    const uint32_t crc_computed = crc32Compute(reinterpret_cast<const uint8_t*>(&raw),
                                               LDR_HDR_SIZE - sizeof(uint32_t));
    bool crc_ok = (crc_computed == raw.hdr_crc32);
    {
        std::ostringstream d;
        d << std::hex << std::uppercase
          << "computed=0x" << crc_computed << "  stored=0x" << raw.hdr_crc32;
        checkStep("CRC32 of header[0..111]", crc_ok, d.str());
    }

    // Check 5: fw_version null-termination
    bool fv_ok = false;
    for (int i = 0; i < 32; ++i) if (raw.fw_version[i] == '\0') { fv_ok = true; break; }
    // Safe print: ensure null-terminated copy
    char fv_safe[33] = {};
    std::memcpy(fv_safe, raw.fw_version, 32);
    checkStep("fw_version null-terminated", fv_ok, std::string("value=\"") + fv_safe + "\"");

    // Check 6: timestamp null-termination
    bool ts_ok = false;
    for (int i = 0; i < 32; ++i) if (raw.timestamp[i] == '\0') { ts_ok = true; break; }
    char ts_safe[33] = {};
    std::memcpy(ts_safe, raw.timestamp, 32);
    checkStep("timestamp null-terminated", ts_ok, std::string("value=\"") + ts_safe + "\"");

    // Check 7: payload_size vs file size
    const uint64_t expected_total = static_cast<uint64_t>(LDR_HDR_SIZE) + raw.payload_size;
    bool ps_ok = (file_size == expected_total);
    {
        std::ostringstream d;
        d << "payload_size=" << raw.payload_size
          << "  header+payload=" << expected_total
          << "  file=" << file_size;
        checkStep("payload_size vs file size", ps_ok, d.str());
    }

    // SHA-256 info (informational — payload digest, not verified here)
    std::cout << "\n  SHA-256 (payload, from header): " << toHex(raw.sha256, 32) << std::endl;

    // --- Summary via verifyLdrHeader() ---
    std::cout << "\n--------------------------------------------------" << std::endl;
    std::cout << "  Full verifyLdrHeader() result:" << std::endl;
    bool overall = verifyLdrHeader(ldr_path, hdr, error);
    if (overall) {
        std::cout << "  [PASS] Header is VALID" << std::endl;
        std::cout << "  fw_version  : " << hdr.fw_version  << std::endl;
        std::cout << "  timestamp   : " << hdr.timestamp   << std::endl;
        std::cout << "  payload_size: " << hdr.payload_size << " bytes" << std::endl;
        std::cout << "  sha256(hex) : " << toHex(hdr.sha256, 32) << std::endl;
    } else {
        std::cout << "  [FAIL] " << error << std::endl;
    }
    std::cout << "==================================================" << std::endl;

    return overall ? 0 : 1;
}
