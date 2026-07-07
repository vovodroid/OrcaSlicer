/**
 * @file DevUtilBackend.h
 * @brief Provides common static utility methods for backend (preset/slicing).
 */

#pragma once
#include "DevDefs.h"
#include "DevFilaSystem.h"

#include <optional>
#include <string>

namespace Slic3r
{

class DevUtilBackend
{
public:
    DevUtilBackend() = delete;

public:
    // for filament preset
    static std::optional<DevFilamentDryingPreset> GetFilamentDryingPreset(const std::string& fila_id);
};

}; // namespace Slic3r
