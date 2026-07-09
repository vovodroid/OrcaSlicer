#pragma once

#include <cstdint>
#include <string>

namespace Slic3r { namespace GUI {

// Stable, opaque identity for a speed-dial action, used as the AppConfig key,
// the JS/registry handle, and the favourite_actions/stats key. FNV-1a 64-bit over
// the UTF-8 bytes of `plugin_key 0x1f capability`, lowercase 16-char hex.
//
// why: this is PERSISTED, so it must be deterministic across runs and platforms.
// std::hash<std::string> is explicitly NOT usable here (unspecified, per-process).
// note: 64-bit hash -> collision is astronomically unlikely at the tens-of-actions
//   scale; upgrade path (128-bit / full-string key) only if that ever changes.
inline std::string speed_dial_action_id(const std::string& plugin_key, const std::string& capability)
{
    constexpr std::uint64_t kOffset = 14695981039346656037ULL; // FNV offset basis (0xcbf29ce484222325)
    constexpr std::uint64_t kPrime  = 1099511628211ULL;       // FNV prime
    std::uint64_t h = kOffset;
    // note: [&], not [&h] - MSVC rejects the constexpr kPrime read inside the lambda
    // without a default capture mode (error C3493).
    auto mix = [&](const std::string& s) {
        for (unsigned char c : s) { h ^= c; h *= kPrime; }
    };
    mix(plugin_key);
    h ^= 0x1f; h *= kPrime;   // 0x1f (unit separator) between the two fields
    mix(capability);

    static const char* kHex = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i) { out[i] = kHex[h & 0xf]; h >>= 4; }
    return out;
}

}} // namespace Slic3r::GUI
