# AMS Drying Control — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the AMS filament drying control feature from BambuStudio into OrcaSlicer, enabling users to start, monitor, and stop filament drying via the AMS unit from the slicer UI.

**Architecture:** Add drying status enums/structs to the `DevAms` data model, extend the JSON parser to populate them, add `CtrlAmsStartDryingHour`/`CtrlAmsStopDrying` commands to `DevFilaSystem`, create a `DevUtilBackend` utility for filament drying preset lookup, and build the `AMSDryCtrWin` dialog. Wire the dialog to open when clicking the AMS humidity indicator for N3F/N3S AMS types.

**Tech Stack:** C++17, wxWidgets, nlohmann/json, Boost

## Global Constraints

- **N3F/N3S only:** Standard AMS and AMS Lite do not have heating hardware; the dialog is not shown for them
- **Backward compatibility:** Existing `command_ams_drying_stop()` is preserved; new commands are additive
- **Cross-platform:** wxWidgets UI must work on Windows, macOS, Linux
- **Dark mode:** Dialog must support dark mode via `wxGetApp().dark_mode()` and `StateColor::darkModeColorFor()`
- **Profile compatibility:** Existing profiles with `filament_dev_ams_drying_*` keys (Qidi) continue to work; the feature reads the same keys
- **No printer-agent changes needed:** All commands go through existing `publish_json()` → `NetworkAgent` path
- **Reference:** `D:\projects\BambuStudio` — match its behavior as much as possible; when in doubt, check the BambuStudio source

---

### Task 1: Global `DevAmsType` enum in `DevDefs.h`

**Files:**
- Modify: `src/slic3r/GUI/DeviceCore/DevDefs.h`
- Modify: `src/slic3r/GUI/DeviceCore/DevFilaSystem.h` (replace local `AmsType` enum with typedef)
- Modify: `src/slic3r/GUI/DeviceCore/DevMapping.cpp` (rename `DevAms::DUMMY` → `DevAms::EXT_SPOOL`)

**Interfaces:**
- Produces: Global `enum DevAmsType { EXT_SPOOL=0, AMS=1, AMS_LITE=2, N3F=3, N3S=4 }` in `DevDefs.h`
- Produces: `using AmsType = DevAmsType;` inside `DevAms` class (replaces old local enum)
- Note: Old `DevAms::DUMMY` becomes `DevAms::EXT_SPOOL`; all existing references update accordingly

- [ ] **Step 1: Add global `DevAmsType` enum to `DevDefs.h`**

In `src/slic3r/GUI/DeviceCore/DevDefs.h`, add before the closing `namespace Slic3r` or after existing enums:

```cpp
enum DevAmsType : int
{
    EXT_SPOOL = 0,      // EXT
    AMS = 1,            // AMS1
    AMS_LITE = 2,       // AMS-Lite
    N3F = 3,            // N3F, AMS 2PRO
    N3S = 4,            // N3S, AMS HT
};
```

- [ ] **Step 2: Replace `DevAms::AmsType` local enum with typedef**

In `src/slic3r/GUI/DeviceCore/DevFilaSystem.h`, find the `DevAms` class and replace the local enum:

```cpp
// Before (delete this):
    enum AmsType : int
    {
        DUMMY = 0,
        AMS = 1,      // AMS
        AMS_LITE = 2, // AMS-Lite
        N3F = 3,      // N3F
        N3S = 4,      // N3S
    };

// After (replace with):
    using AmsType = DevAmsType;
```

- [ ] **Step 3: Rename `DevAms::DUMMY` → `DevAms::EXT_SPOOL` in `DevMapping.cpp`**

In `src/slic3r/GUI/DeviceCore/DevMapping.cpp` line 189:

```cpp
// Before:
_parse_tray_info(atoi(tray.id.c_str()), 0, DevAms::DUMMY, tray, info);
// After:
_parse_tray_info(atoi(tray.id.c_str()), 0, DevAms::EXT_SPOOL, tray, info);
```

- [ ] **Step 4: Rename `DUMMY` → `EXT_SPOOL` in `DevFilaSystem.cpp`**

In `src/slic3r/GUI/DeviceCore/DevFilaSystem.cpp` line 114:

```cpp
// Before:
assert(DUMMY < type && m_ams_type <= N3S);
// After:
assert(EXT_SPOOL < type && m_ams_type <= N3S);
```

- [ ] **Step 5: Verify the build compiles**

```powershell
cmake --build . --config RelWithDebInfo --target ALL_BUILD -- -m
```

Expected: build succeeds, no `DUMMY` or `AmsType` related compile errors.

- [ ] **Step 6: Commit**

```bash
git add src/slic3r/GUI/DeviceCore/DevDefs.h src/slic3r/GUI/DeviceCore/DevFilaSystem.h src/slic3r/GUI/DeviceCore/DevFilaSystem.cpp src/slic3r/GUI/DeviceCore/DevMapping.cpp
git commit -m "refactor: promote DevAmsType to global enum, rename DUMMY to EXT_SPOOL

Matches BambuStudio's DevAmsType naming convention."
```

---

### Task 2: Drying enums and structs in `DevAms`

**Files:**
- Modify: `src/slic3r/GUI/DeviceCore/DevFilaSystem.h`

**Interfaces:**
- Produces: `DevAms::DryCtrlMode`, `DevAms::DryStatus`, `DevAms::DrySubStatus`, `DevAms::DryFanStatus`, `DevAms::CannotDryReason` enums
- Produces: `DevAms::DrySettings` struct
- Produces: Getters: `GetDryStatus()`, `GetDrySubStatus()`, `GetFan1Status()`, `GetFan2Status()`, `GetCannotDryReason()`, `GetDrySettings()`
- Produces: `IsSupportRemoteDry(const MachineObject*)`, `AmsIsDrying()`
- Produces: `SupportDrying()` — already exists as `m_ams_type > AMS_LITE`; update to check N3F/N3S
- Produces: Members: `m_dry_status`, `m_dry_sub_status`, `m_dry_fan1_status`, `m_dry_fan2_status`, `m_dry_cannot_reasons`, `m_dry_settings`

**Reference:** `D:\projects\BambuStudio\src\slic3r\GUI\DeviceCore\DevFilaSystem.h` lines 119–262

- [ ] **Step 1: Add enums inside `DevAms` class**

In `src/slic3r/GUI/DeviceCore/DevFilaSystem.h`, inside the `DevAms` class (after the `using AmsType = DevAmsType;` line, before the `public:` constructor section), add:

```cpp
public:

    enum class DryCtrlMode : int
    {
        Off = 0,
        OnTime = 1,
        OnHumidity = 2,
    };

    enum class DryStatus : char
    {
        Off = 0,
        Checking = 1,
        Drying = 2,
        Cooling = 3,
        Stopping = 4,
        Error = 5,
        CannotStopHeatOutofControl = 6,
        PrdTesting = 7,
    };

    enum class DrySubStatus
    {
        Off = 0,
        Heating = 1,
        Dehumidify = 2,
    };

    enum class DryFanStatus : char
    {
        Off = 0,
        On = 1,
    };

    enum class CannotDryReason : int
    {
        TaskOccupied = 0,
        InsufficientPower = 1,
        AmsBusy = 2,
        ConsumableAtAmsOutlet = 3,
        InitiatingAmsDrying = 4,
        NotSupportedIn2dMode = 5,
        DryingInProgress = 6,
        Upgrading = 7,
        InsufficientPowerNeedPluginPower = 8,
        FilamentAtAmsOutletManualUnload = 10,
    };

    struct DrySettings
    {
        std::string dry_filament;
        int dry_temp = -1; // -1 means invalid
        int dry_hour = -1; // -1 means invalid, hours
    };
```

- [ ] **Step 2: Add new getters to `DevAms`**

After the existing `GetLeftDryTime()` getter, add:

```cpp
    // remote drying control
    bool IsSupportRemoteDry(const MachineObject* obj) const;
    std::optional<DryStatus> GetDryStatus() const { return m_dry_status; };
    std::optional<DrySubStatus> GetDrySubStatus() const { return m_dry_sub_status; }
    std::optional<DryFanStatus> GetFan1Status() const { return m_dry_fan1_status; }
    std::optional<DryFanStatus> GetFan2Status() const { return m_dry_fan2_status; }
    std::optional<std::vector<CannotDryReason>> GetCannotDryReason() const { return m_dry_cannot_reasons; }
    std::optional<DrySettings> GetDrySettings() const { return m_dry_settings; };

    bool AmsIsDrying();
```

- [ ] **Step 3: Add new private members to `DevAms`**

In the private section of `DevAms`, after `m_left_dry_time`, add:

```cpp
    // see is_support_remote_dry
    std::optional<DryStatus> m_dry_status;
    std::optional<DrySubStatus> m_dry_sub_status;
    std::optional<DryFanStatus> m_dry_fan1_status;
    std::optional<DryFanStatus> m_dry_fan2_status;
    std::optional<std::vector<CannotDryReason>> m_dry_cannot_reasons;
    std::optional<DrySettings> m_dry_settings;
```

Note: In BambuStudio these members are `public:` (prefixed with `public:` before `m_dry_status`). Keep them private and use getters. The friends (`DevFilaSystemParser`) can access them.

Also remove the duplicate `GetAmsType()` which currently returns `m_ams_type` — since `m_ams_type` is now `DevAmsType`, the getter still works.

- [ ] **Step 4: Add forward declaration for `DevFilamentDryingPreset`**

At the top of the file, after the existing forward declarations:

```cpp
struct DevFilamentDryingPreset;
```

- [ ] **Step 5: Verify the header compiles**

```powershell
cmake --build . --config RelWithDebInfo --target ALL_BUILD -- -m
```

Expected: build succeeds. If there are compilation errors related to `GetAmsType()` return type, check that `AmsType` typedef resolves correctly.

- [ ] **Step 6: Commit**

```bash
git add src/slic3r/GUI/DeviceCore/DevFilaSystem.h
git commit -m "feat: add drying enums, structs, getters to DevAms

Adds DryCtrlMode, DryStatus, DrySubStatus, DryFanStatus,
CannotDryReason enums and DrySettings struct for AMS drying control."
```

---

### Task 3: `DevFilamentDryingPreset` struct and `DevFilaSystem` ctrl declarations

**Files:**
- Modify: `src/slic3r/GUI/DeviceCore/DevFilaSystem.h`

**Interfaces:**
- Produces: `struct DevFilamentDryingPreset` at namespace scope
- Produces: `DevFilaSystem::CtrlAmsStartDryingHour(int ams_id, std::string filament_type, int tag_temp, int tag_duration_hour, bool rotate_tray, int cooling_temp, bool close_power_conflict = false) const`
- Produces: `DevFilaSystem::CtrlAmsStopDrying(int ams_id) const`
- Produces: `DevAmsTray::get_ams_drying_preset()` method

**Reference:** `D:\projects\BambuStudio\src\slic3r\GUI\DeviceCore\DevFilaSystem.h` lines 350–362

- [ ] **Step 1: Add `DevFilamentDryingPreset` struct at namespace scope**

In `src/slic3r/GUI/DeviceCore/DevFilaSystem.h`, add after the `DevFilaSystemParser` class (at the very end of the file, before `}// namespace Slic3r`):

```cpp
struct DevFilamentDryingPreset
{
    std::string filament_id;

    std::unordered_set<DevAmsType> ams_limitations; // only use ams types in the set
    std::unordered_map<DevAmsType, float> filament_dev_ams_drying_time_on_idle; // hour
    std::unordered_map<DevAmsType, float> filament_dev_ams_drying_temperature_on_idle;
    std::unordered_map<DevAmsType, float> filament_dev_ams_drying_time_on_print; // hour
    std::unordered_map<DevAmsType, float> filament_dev_ams_drying_temperature_on_print;
    float filament_dev_drying_cooling_temperature = 0.0f;
    float filament_dev_drying_softening_temperature = 0.0f;
    float filament_dev_ams_drying_heat_distortion_temperature = 0.0f;
};
```

- [ ] **Step 2: Add control method declarations to `DevFilaSystem`**

In the `DevFilaSystem` class, after the existing `CtrlAmsReset()` declaration:

```cpp
    // crtl
    int  CtrlAmsStartDryingHour(int ams_id, std::string filament_type, int tag_temp, int tag_duration_hour, bool rotate_tray, int cooling_temp, bool close_power_conflict = false) const;
    int  CtrlAmsStopDrying(int ams_id) const;
```

- [ ] **Step 3: Add `get_ams_drying_preset()` to `DevAmsTray`**

In the `DevAmsTray` class, add after the `get_filament_type()` method:

```cpp
    std::optional<DevFilamentDryingPreset> get_ams_drying_preset() const;
```

Also add `#include <unordered_set>` and `#include <unordered_map>` to the includes if not already present.
Add `#include <optional>` if not already present.

- [ ] **Step 4: Verify build**

```powershell
cmake --build . --config RelWithDebInfo --target ALL_BUILD -- -m
```

- [ ] **Step 5: Commit**

```bash
git add src/slic3r/GUI/DeviceCore/DevFilaSystem.h
git commit -m "feat: add DevFilamentDryingPreset, ctrl method declarations, tray preset getter"
```

---

### Task 4: `DevUtilBackend` utility class

**Files:**
- Create: `src/slic3r/GUI/DeviceCore/DevUtilBackend.h`
- Create: `src/slic3r/GUI/DeviceCore/DevUtilBackend.cpp`
- Modify: `src/slic3r/GUI/DeviceCore/CMakeLists.txt`

**Interfaces:**
- Produces: `DevUtilBackend::GetFilamentDryingPreset(const std::string& fila_id)` → `std::optional<DevFilamentDryingPreset>`

**Reference:** `D:\projects\BambuStudio\src\slic3r\GUI\DeviceCore\DevUtilBackend.h`, `DevUtilBackend.cpp`

- [ ] **Step 1: Create `DevUtilBackend.h`**

Create `src/slic3r/GUI/DeviceCore/DevUtilBackend.h`:

```cpp
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
```

- [ ] **Step 2: Create `DevUtilBackend.cpp`**

Create `src/slic3r/GUI/DeviceCore/DevUtilBackend.cpp`:

```cpp
#include "DevUtilBackend.h"

#include "slic3r/GUI/GUI_App.hpp"

#include "libslic3r/Preset.hpp"

#include <boost/log/trivial.hpp>

namespace Slic3r
{

static std::unordered_map<std::string, DevAmsType> s_ams_type_map = {
    {"0", DevAmsType::N3F},
    {"1", DevAmsType::N3S},
};

std::optional<Slic3r::DevFilamentDryingPreset> DevUtilBackend::GetFilamentDryingPreset(const std::string& fila_id)
{
    if (fila_id.empty() || !GUI::wxGetApp().preset_bundle) {
        return std::nullopt;
    }

    for (auto iter = GUI::wxGetApp().preset_bundle->filaments.begin(); iter != GUI::wxGetApp().preset_bundle->filaments.end(); ++iter) {
        const Preset& filament_preset = *iter;
        const auto& config = filament_preset.config;
        if (filament_preset.filament_id == fila_id) {
            DevFilamentDryingPreset info;
            info.filament_id = fila_id;
            try {
                if (config.has("filament_dev_ams_drying_ams_limitations")) {
                    std::vector<std::string> types = config.option<ConfigOptionStrings>("filament_dev_ams_drying_ams_limitations")->values;
                    for (auto type : types) {
                        if (s_ams_type_map.count(type) == 0) {
                            continue;
                        }
                        info.ams_limitations.insert(s_ams_type_map[type]);
                    }
                }

                if (config.has("filament_dev_ams_drying_temperature")) {
                    info.filament_dev_ams_drying_temperature_on_idle[DevAmsType::N3F] = config.option<ConfigOptionFloats>("filament_dev_ams_drying_temperature")->get_at(0);
                    info.filament_dev_ams_drying_temperature_on_idle[DevAmsType::N3S] = config.option<ConfigOptionFloats>("filament_dev_ams_drying_temperature")->get_at(1);
                    info.filament_dev_ams_drying_temperature_on_print[DevAmsType::N3F] = config.option<ConfigOptionFloats>("filament_dev_ams_drying_temperature")->get_at(2);
                    info.filament_dev_ams_drying_temperature_on_print[DevAmsType::N3S] = config.option<ConfigOptionFloats>("filament_dev_ams_drying_temperature")->get_at(3);
                }

                if (config.has("filament_dev_ams_drying_time")) {
                    info.filament_dev_ams_drying_time_on_idle[DevAmsType::N3F] = config.option<ConfigOptionFloats>("filament_dev_ams_drying_time")->get_at(0);
                    info.filament_dev_ams_drying_time_on_idle[DevAmsType::N3S] = config.option<ConfigOptionFloats>("filament_dev_ams_drying_time")->get_at(1);
                    info.filament_dev_ams_drying_time_on_print[DevAmsType::N3F] = config.option<ConfigOptionFloats>("filament_dev_ams_drying_time")->get_at(2);
                    info.filament_dev_ams_drying_time_on_print[DevAmsType::N3S] = config.option<ConfigOptionFloats>("filament_dev_ams_drying_time")->get_at(3);
                }

                if (config.has("filament_dev_drying_softening_temperature")) {
                    info.filament_dev_drying_softening_temperature = config.option<ConfigOptionFloats>("filament_dev_drying_softening_temperature")->get_at(0);
                }

                if (config.has("filament_dev_ams_drying_heat_distortion_temperature")) {
                    info.filament_dev_ams_drying_heat_distortion_temperature = config.option<ConfigOptionFloats>("filament_dev_ams_drying_heat_distortion_temperature")->get_at(0);
                }

                if (config.has("filament_dev_drying_cooling_temperature")) {
                    info.filament_dev_drying_cooling_temperature = config.option<ConfigOptionFloats>("filament_dev_drying_cooling_temperature")->get_at(0);
                }

                return info;
            } catch (const std::exception& e) {
                BOOST_LOG_TRIVIAL(error) << __FUNCTION__ << " exception: " << e.what();
            }
        }
    }

    return std::nullopt;
}

}; // namespace Slic3r
```

- [ ] **Step 3: Register new files in CMakeLists.txt**

In `src/slic3r/GUI/DeviceCore/CMakeLists.txt`, add the new files. After the existing `DevFilaSystemCtrl.cpp` line:

```cmake
    GUI/DeviceCore/DevUtilBackend.h
    GUI/DeviceCore/DevUtilBackend.cpp
```

- [ ] **Step 4: Verify build**

```powershell
cmake --build . --config RelWithDebInfo --target ALL_BUILD -- -m
```

Expected: build succeeds. If `ConfigOptionStrings` or `ConfigOptionFloats` are not found, check the includes — they're in `libslic3r/Preset.hpp` and `libslic3r/PrintConfig.hpp`.

- [ ] **Step 5: Commit**

```bash
git add src/slic3r/GUI/DeviceCore/DevUtilBackend.h src/slic3r/GUI/DeviceCore/DevUtilBackend.cpp src/slic3r/GUI/DeviceCore/CMakeLists.txt
git commit -m "feat: add DevUtilBackend with GetFilamentDryingPreset

Reads filament_dev_ams_drying_* config keys from filament presets
and returns structured DevFilamentDryingPreset data."
```

---

### Task 5: JSON parsing for drying status fields

**Files:**
- Modify: `src/slic3r/GUI/DeviceCore/DevFilaSystem.cpp`

**Interfaces:**
- Consumes: `DevAms::DryStatus`, `DevAms::DrySubStatus`, `DevAms::DryFanStatus`, `DevAms::CannotDryReason`, `DevAms::DrySettings`
- Parses from JSON: `dry_time`, info flag bits (dry_status/fan1/fan2/sub_status), `dry_setting`, `dry_sf_reason`

**Reference:** `D:\projects\BambuStudio\src\slic3r\GUI\DeviceCore\DevFilaSystem.cpp` lines 690–712

- [ ] **Step 1: Locate the AMS parsing section in `DevFilaSystemParser::ParseV1_0()`**

First, read `DevFilaSystem.cpp` to find where `m_left_dry_time` is parsed (look for "dry_time") and where the AMS info section is. The parsing function is `DevFilaSystemParser::ParseV1_0`.

- [ ] **Step 2: Add drying status field parsing**

After the existing `m_left_dry_time` parsing line (which parses `"dry_time"` from JSON), add the drying status parsing. The exact location will be in the AMS loop where `curr_ams` is populated.

After `DevJsonValParser::ParseVal(j_ams, "dry_time", curr_ams->m_left_dry_time);` (or the equivalent line), add:

```cpp
    // Drying status — only parse if printer supports remote drying
    if (obj->is_support_remote_dry) {
        if (j_ams.contains("info")) {
            const std::string& info = j_ams["info"].get<std::string>();
            curr_ams->m_dry_status = (DevAms::DryStatus)DevUtil::get_flag_bits(info, 4, 4);
            curr_ams->m_dry_fan1_status = (DevAms::DryFanStatus)DevUtil::get_flag_bits(info, 18, 2);
            curr_ams->m_dry_fan2_status = (DevAms::DryFanStatus)DevUtil::get_flag_bits(info, 20, 2);
            curr_ams->m_dry_sub_status = (DevAms::DrySubStatus)DevUtil::get_flag_bits(info, 22, 2);
        }

        if (j_ams.contains("dry_setting")) {
            const auto& j_dry_settings = j_ams["dry_setting"];
            DevAms::DrySettings dry_settings;
            DevJsonValParser::ParseVal(j_dry_settings, "dry_filament", dry_settings.dry_filament);
            DevJsonValParser::ParseVal(j_dry_settings, "dry_temperature", dry_settings.dry_temp);
            DevJsonValParser::ParseVal(j_dry_settings, "dry_duration", dry_settings.dry_hour);
            curr_ams->m_dry_settings = dry_settings;
        }

        if (j_ams.contains("dry_sf_reason")) {
            curr_ams->m_dry_cannot_reasons = DevJsonValParser::GetVal<std::vector<DevAms::CannotDryReason>>(j_ams, "dry_sf_reason");
        }
    }
```

Note: Check if `DevUtil::get_flag_bits` and `DevJsonValParser` exist in OrcaSlicer. If not, these utilities must be added. Check BambuStudio's `DevUtil.h` for `get_flag_bits` and `DevJsonValParser` for the parsing helper. If these are missing, add minimal versions or inline the parsing.

Check specifically whether `DevUtil.h` in OrcaSlicer has `get_flag_bits`. The `DevUtil.h` exists in the CMakeLists. Check its contents — it should have a static `get_flag_bits(std::string, int, int)` method. If not present, port it from BambuStudio.

- [ ] **Step 3: Implement `IsSupportRemoteDry()` and `AmsIsDrying()`**

In the same file, add the implementations after the existing `DevAms` methods:

```cpp
bool DevAms::IsSupportRemoteDry(const MachineObject* obj) const
{
    if (obj && obj->is_support_remote_dry) {
        return SupportDrying();
    }
    return false;
}

bool DevAms::AmsIsDrying()
{
    if (!GetDryStatus().has_value()) {
        return false;
    }

    return GetDryStatus().value() == DevAms::DryStatus::Checking
        || GetDryStatus().value() == DevAms::DryStatus::Drying
        || GetDryStatus().value() == DevAms::DryStatus::Error
        || GetDryStatus().value() == DevAms::DryStatus::CannotStopHeatOutofControl;
}
```

- [ ] **Step 4: Implement `DevAmsTray::get_ams_drying_preset()`**

```cpp
std::optional<DevFilamentDryingPreset> DevAmsTray::get_ams_drying_preset() const
{
    return DevUtilBackend::GetFilamentDryingPreset(setting_id);
}
```

- [ ] **Step 5: Ensure `#include "DevUtilBackend.h"` is present in `DevFilaSystem.cpp`**

Add at the top if not present.

- [ ] **Step 6: Verify build**

```powershell
cmake --build . --config RelWithDebInfo --target ALL_BUILD -- -m
```

- [ ] **Step 7: Commit**

```bash
git add src/slic3r/GUI/DeviceCore/DevFilaSystem.cpp
git commit -m "feat: add drying status JSON parsing and DevAms helper methods

Parse dry_status, dry_sub_status, dry_fan statuses,
dry_settings, and dry_cannot_reasons from printer JSON.
Implement IsSupportRemoteDry, AmsIsDrying, get_ams_drying_preset."
```

---

### Task 6: `is_support_remote_dry` flag on `MachineObject`

**Files:**
- Modify: `src/slic3r/GUI/DeviceManager.hpp` (add field)
- Modify: `src/slic3r/GUI/DeviceManager.cpp` (parse the flag)

**Interfaces:**
- Produces: `MachineObject::is_support_remote_dry` (bool)

**Reference:** `D:\projects\BambuStudio\src\slic3r\GUI\DeviceManager.hpp` line 566, `DeviceManager.cpp` line 4403

- [ ] **Step 1: Add `is_support_remote_dry` field to `MachineObject`**

In `src/slic3r/GUI/DeviceManager.hpp`, find the section with other `is_support_*` flags (near `is_support_ams_humidity`) and add:

```cpp
    bool is_support_remote_dry = false;
```

- [ ] **Step 2: Parse `is_support_remote_dry` from firmware flags**

In `src/slic3r/GUI/DeviceManager.cpp`, find the `parse_version_func()` or `parse_new_info()` method where other `is_support_*` flags are set. Look for the `is_support_ams_humidity` parsing pattern.

Add parsing for `is_support_remote_dry` from the `fun2` field. Check the BambuStudio reference: it uses `get_flag_bits_no_border(fun2, 5) == 1` for bit 5. The exact location depends on how OrcaSlicer parses firmware capability bits.

If a `fun2` parsing block exists, add:
```cpp
    is_support_remote_dry = (get_flag_bits_no_border(fun2, 5) == 1);
```

If `fun2` parsing or `get_flag_bits_no_border` don't exist yet in OrcaSlicer, check how similar flags like `is_support_ams_humidity` are parsed and follow the same pattern. If the needed helper methods are missing, port them from BambuStudio's `DeviceManager.cpp`.

- [ ] **Step 3: Verify build**

```powershell
cmake --build . --config RelWithDebInfo --target ALL_BUILD -- -m
```

- [ ] **Step 4: Commit**

```bash
git add src/slic3r/GUI/DeviceManager.hpp src/slic3r/GUI/DeviceManager.cpp
git commit -m "feat: add is_support_remote_dry flag to MachineObject

Parsed from firmware fun2 bit 5. Controls whether drying
status fields are parsed and drying commands are available."
```

---

### Task 7: Start/Stop drying commands in `DevFilaSystemCtrl.cpp`

**Files:**
- Modify: `src/slic3r/GUI/DeviceCore/DevFilaSystemCtrl.cpp`

**Interfaces:**
- Consumes: `MachineObject::m_sequence_id`, `MachineObject::publish_json()`
- Produces: `DevFilaSystem::CtrlAmsStartDryingHour(...)`, `DevFilaSystem::CtrlAmsStopDrying(int)`

**Reference:** `D:\projects\BambuStudio\src\slic3r\GUI\DeviceCore\DevFilaSystemCtrl.cpp`

- [ ] **Step 1: Add `CtrlAmsStartDryingHour` and `CtrlAmsStopDrying`**

In `src/slic3r/GUI/DeviceCore/DevFilaSystemCtrl.cpp`, add after the existing `CtrlAmsReset()` method:

```cpp
int DevFilaSystem::CtrlAmsStartDryingHour(int ams_id,
                                          std::string filament_type,
                                          int tag_temp,
                                          int tag_duration_hour,
                                          bool rotate_tray,
                                          int cooling_temp,
                                          bool close_power_conflict) const
{
    json jj_command;
    jj_command["print"]["command"] = "ams_filament_drying";
    jj_command["print"]["sequence_id"] = std::to_string(MachineObject::m_sequence_id++);
    jj_command["print"]["ams_id"] = ams_id;
    jj_command["print"]["mode"] = DevAms::DryCtrlMode::OnTime;
    jj_command["print"]["filament"] = filament_type;
    jj_command["print"]["temp"] = tag_temp;
    jj_command["print"]["duration"] = tag_duration_hour;
    jj_command["print"]["humidity"] = 0;
    jj_command["print"]["rotate_tray"] = rotate_tray;
    jj_command["print"]["cooling_temp"] = cooling_temp;
    jj_command["print"]["close_power_conflict"] = close_power_conflict;
    return m_owner->publish_json(jj_command);
}

int DevFilaSystem::CtrlAmsStopDrying(int ams_id) const
{
    json jj_command;
    jj_command["print"]["command"] = "ams_filament_drying";
    jj_command["print"]["sequence_id"] = std::to_string(MachineObject::m_sequence_id++);
    jj_command["print"]["ams_id"] = ams_id;
    jj_command["print"]["mode"] = DevAms::DryCtrlMode::Off;
    jj_command["print"]["filament"] = "";
    jj_command["print"]["temp"] = 0;
    jj_command["print"]["duration"] = 0;
    jj_command["print"]["humidity"] = 0;
    jj_command["print"]["rotate_tray"] = false;
    jj_command["print"]["cooling_temp"] = 0;
    jj_command["print"]["close_power_conflict"] = false;
    return m_owner->publish_json(jj_command);
}
```

Note: The `DevAms::DryCtrlMode` enum class uses `DevAms::DryCtrlMode::OnTime` in C++. When serialized to JSON (`jj_command["print"]["mode"] = DevAms::DryCtrlMode::OnTime`), nlohmann/json will convert the enum class to its underlying int (1). This matches the BambuStudio behavior. If the implicit conversion doesn't compile, add a `static_cast<int>()` wrapper.

- [ ] **Step 2: Verify build**

```powershell
cmake --build . --config RelWithDebInfo --target ALL_BUILD -- -m
```

- [ ] **Step 3: Commit**

```bash
git add src/slic3r/GUI/DeviceCore/DevFilaSystemCtrl.cpp
git commit -m "feat: add CtrlAmsStartDryingHour and CtrlAmsStopDrying commands

Publish 'ams_filament_drying' JSON commands via MQTT for
starting and stopping AMS filament drying."
```

---

### Task 8: Copy image assets from BambuStudio

**Files:**
- Copy 14 image files from `D:\projects\BambuStudio\resources\images\` to `resources\images\`

**Assets to copy:**

```powershell
Copy-Item "D:\projects\BambuStudio\resources\images\hum_level1_no_num_light.svg" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\hum_level2_no_num_light.svg" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\hum_level3_no_num_light.svg" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\hum_level4_no_num_light.svg" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\hum_level5_no_num_light.svg" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_n3f_heating.png" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_n3f_dehumidifying.png" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_n3f_error.png" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_n3f_cooling.png" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_n3s_heating.png" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_n3s_dehumidifying.png" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_n3s_error.png" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_n3s_cooling.png" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_heating_icon.svg" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_filament_in_chamber.png" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_enable.svg" -Destination "resources\images\"
Copy-Item "D:\projects\BambuStudio\resources\images\dev_ams_dry_ctr_disable.svg" -Destination "resources\images\"
```

- [ ] **Step 1: Copy each asset**

Run each Copy-Item command. If any file is missing from the source, note it — the dialog will degrade gracefully with null bitmaps.

- [ ] **Step 2: Verify files exist**

```powershell
Get-ChildItem resources\images\dev_ams_dry_ctr_*, resources\images\hum_level* | Select Name
```

Expected: all 17 files listed.

- [ ] **Step 3: Commit**

```bash
git add resources/images/dev_ams_dry_ctr_* resources/images/hum_level*
git commit -m "assets: add AMS drying control images from BambuStudio

14 images: humidity level icons, drying state images per AMS type,
heating icon, guide illustration, tray status icons."
```

---

### Task 9: `AMSDryControl` UI dialog

**Files:**
- Create: `src/slic3r/GUI/AMSDryControl.hpp`
- Create: `src/slic3r/GUI/AMSDryControl.cpp`

**Interfaces:**
- Produces: `AMSDryCtrWin` dialog class extending `DPIDialog`
- Produces: `FilamentItemPanel`, `AMSFilamentPanel` helper widget classes
- Consumes: `DevFilaSystem`, `MachineObject`, `DevAms`, `DevUtilBackend::GetFilamentDryingPreset()`

**Reference:** `D:\projects\BambuStudio\src\slic3r\GUI\AMSDryControl.hpp` and `AMSDryControl.cpp`

- [ ] **Step 1: Create `AMSDryControl.hpp`**

Create `src/slic3r/GUI/AMSDryControl.hpp`. Port the full header from BambuStudio `AMSDryControl.hpp`, adapting includes for OrcaSlicer paths:

Key adaptations:
- Change `#include "GUI_ObjectLayers.hpp"` to appropriate OrcaSlicer equivalent (check if it exists; if not, it may not be needed or can be replaced with `wx/wx.h`)
- Keep includes for `slic3r/GUI/Widgets/AMSItem.hpp`, `Widgets/Label.hpp`, `Widgets/PopupWindow.hpp`, `wxExtensions.hpp`, `DeviceCore/DevFilaSystem.h`
- Keep the full class declarations for `FilamentItemPanel`, `AMSFilamentPanel`, `AMSDryCtrWin`

The complete header from `D:\projects\BambuStudio\src\slic3r\GUI\AMSDryControl.hpp` (lines 1–252) should be ported with path adjustments. Due to the file's length (~250 lines), copy the full content from the reference and adapt.

- [ ] **Step 2: Create `AMSDryControl.cpp`**

Create `src/slic3r/GUI/AMSDryControl.cpp`. Port from `D:\projects\BambuStudio\src\slic3r\GUI\AMSDryControl.cpp` (lines 1–1860). Key adaptations:

Replace these BambuStudio includes:
```cpp
#include "AMSDryControl.hpp"
#include "DeviceCore/DevFilaSystem.h"
#include "GUI_App.hpp"
#include "I18N.hpp"
#include "slic3r/GUI/DeviceCore/DevExtruderSystem.h"
#include "slic3r/GUI/DeviceCore/DevUpgrade.h"
#include "slic3r/GUI/DeviceCore/DevManager.h"
#include "slic3r/GUI/MsgDialog.hpp"
#include "slic3r/GUI/Widgets/AnimaController.hpp"
#include "slic3r/GUI/Widgets/Label.hpp"
#include "slic3r/GUI/Widgets/ComboBox.hpp"
#include "slic3r/GUI/Widgets/ProgressBar.hpp"
#include "DeviceCore/DevUtilBackend.h"
```

Adapt includes for OrcaSlicer paths. Check which of these already exist:
- `GUI_App.hpp` → existing
- `I18N.hpp` → existing
- `DeviceCore/DevFilaSystem.h` → existing
- `Widgets/Label.hpp`, `Widgets/ComboBox.hpp`, `Widgets/ProgressBar.hpp` → check existence in OrcaSlicer

Since this file is ~1860 lines, port it in full from the BambuStudio reference, adapting only the include paths and namespace references as needed for OrcaSlicer. The implementation logic should be identical to BambuStudio.

Key parts to verify during port:
- `AMS_ITEMS_PANEL_SIZE`, `AMS_CONTROL_DEF_BLOCK_BK_COLOUR`, `AMS_CONTROL_BRAND_COLOUR`, `AMS_CONTROL_DISABLE_COLOUR`, `AMS_CONTROL_WHITE_COLOUR` — these constants are defined in `AMSItem.hpp`. Verify they exist in OrcaSlicer's version.
- `_L()` and `_CTX_utf8()` — I18N macros; verify they work the same in OrcaSlicer
- `StateColor` — widget state color class; verify it exists in OrcaSlicer
- `ScalableBitmap` — verify it exists in OrcaSlicer
- `ComboBox` — OrcaSlicer custom combobox; verify path
- `ProgressBar` — OrcaSlicer custom progress bar; verify path
- `FromDIP()` — DPI scaling helper; should exist in OrcaSlicer
- `encode_path()` — path encoding utility; should exist
- `resources_dir()` — resources directory getter; verify it exists
- `bool is_support_user_preset` on `MachineObject` — verify this field exists

- [ ] **Step 3: Register `AMSDryControl` in CMakeLists**

In `src/slic3r/CMakeLists.txt`, add after the `AMSSetting` entries (around line 30):

```cmake
    GUI/AMSDryControl.cpp
    GUI/AMSDryControl.hpp
```

- [ ] **Step 4: Verify build**

```powershell
cmake --build . --config RelWithDebInfo --target ALL_BUILD -- -m
```

Fix any compilation errors from missing includes or type mismatches between OrcaSlicer and BambuStudio APIs.

- [ ] **Step 5: Commit**

```bash
git add src/slic3r/GUI/AMSDryControl.hpp src/slic3r/GUI/AMSDryControl.cpp
git commit -m "feat: add AMSDryControl dialog for AMS filament drying

Three-page wizard: main status/control page, guide page with
filament tray status, and progress page. Supports N3F and N3S AMS types."
```

---

### Task 10: Wire humidity click to open `AMSDryCtrWin`

**Files:**
- Modify: `src/slic3r/GUI/Widgets/AMSControl.hpp`
- Modify: `src/slic3r/GUI/Widgets/AMSControl.cpp`

**Interfaces:**
- Consumes: `AMSDryCtrWin` dialog class
- Modifies: `EVT_AMS_SHOW_HUMIDITY_TIPS` handler — for N3F/N3S AMS types, opens `AMSDryCtrWin` instead of the popup

- [ ] **Step 1: Add member and include to `AMSControl.hpp`**

In `src/slic3r/GUI/Widgets/AMSControl.hpp`:

Add forward declaration:
```cpp
class AMSDryCtrWin;
```

Add member variable near the existing `m_percent_humidity_dry_popup`:
```cpp
    AMSDryCtrWin* m_dry_ctr_win{nullptr};
```

- [ ] **Step 2: Add include to `AMSControl.cpp`**

```cpp
#include "slic3r/GUI/AMSDryControl.hpp"
```

- [ ] **Step 3: Modify the `EVT_AMS_SHOW_HUMIDITY_TIPS` handler**

In the handler at around line 243, modify the `else` branch (for non-GENERIC_AMS types) to check if the AMS type is N3F/N3S and open the `AMSDryCtrWin` instead of the popup:

```cpp
    Bind(EVT_AMS_SHOW_HUMIDITY_TIPS, [this](wxCommandEvent& evt) {
        uiAmsHumidityInfo *info    = (uiAmsHumidityInfo *) evt.GetClientData();
        if (info)
        {
            if (info->ams_type == AMSModel::GENERIC_AMS)
            {
                wxPoint img_pos = ClientToScreen(wxPoint(0, 0));
                wxPoint popup_pos(img_pos.x - m_Humidity_tip_popup.GetSize().GetWidth() + FromDIP(150), img_pos.y - FromDIP(80));
                m_Humidity_tip_popup.Position(popup_pos, wxSize(0, 0));

                int humidity_value = info->humidity_display_idx;
                if (humidity_value > 0 && humidity_value <= 5) { m_Humidity_tip_popup.set_humidity_level(humidity_value); }
                m_Humidity_tip_popup.Popup();
            }
            else if (info->ams_type == AMSModel::N3F_AMS || info->ams_type == AMSModel::N3S_AMS)
            {
                // Open full drying control dialog for N3F/N3S AMS
                if (!m_dry_ctr_win) {
                    m_dry_ctr_win = new AMSDryCtrWin(this);
                }
                m_dry_ctr_win->set_ams_id(info->ams_id);
                // Get fila system and machine object via the parent chain
                // The dialog will be updated in parse_object()
                m_dry_ctr_win->ShowModal();
            }
            else
            {
                m_percent_humidity_dry_popup->Update(info);

                wxPoint img_pos = ClientToScreen(wxPoint(0, 0));
                wxPoint popup_pos(img_pos.x - m_percent_humidity_dry_popup->GetSize().GetWidth() + FromDIP(150), img_pos.y - FromDIP(80));
                m_percent_humidity_dry_popup->Move(popup_pos);
                m_percent_humidity_dry_popup->ShowModal();
            }
        }

        delete info;
    });
```

Note: The `AMSDryCtrWin` needs `DevFilaSystem` and `MachineObject` references for its `update()` method. The dialog's `update()` should be called before `ShowModal()`. The `MachineObject*` can be obtained from the parent widget chain or stored as a member of `AMSControl`. Check how `AMSControl` currently accesses `MachineObject` (likely through `m_obj` or similar). Pass it to the dialog's `update()` call.

- [ ] **Step 4: Add periodic update for the dialog in `parse_object()`**

In the `parse_object()` method (around line 954), find the existing humidity popup update block and extend it to also update the dry control dialog:

```cpp
    /*update AMS dry control dialog*/
    if (m_dry_ctr_win && m_dry_ctr_win->IsShown())
    {
        // Get the MachineObject and DevFilaSystem from the current device
        // m_dry_ctr_win->update(obj->GetFilaSystem_ptr(), obj);
    }
```

Note: The exact code depends on how `AMSControl` accesses `MachineObject*`. Check existing patterns — it likely has access through `m_obj` or a similar member. The update will need both the `DevFilaSystem` (as `shared_ptr`) and `MachineObject*`.

- [ ] **Step 5: Verify build**

```powershell
cmake --build . --config RelWithDebInfo --target ALL_BUILD -- -m
```

- [ ] **Step 6: Commit**

```bash
git add src/slic3r/GUI/Widgets/AMSControl.hpp src/slic3r/GUI/Widgets/AMSControl.cpp
git commit -m "feat: wire AMS humidity click to open AMSDryControl dialog

For N3F and N3S AMS types, clicking the humidity indicator
now opens the full drying control dialog instead of the popup."
```

---

### Task 11: Update error dialog stop-drying call

**Files:**
- Modify: `src/slic3r/GUI/DeviceErrorDialog.cpp`

**Interfaces:**
- Consumes: `DevFilaSystem::CtrlAmsStopDrying(int)`

- [ ] **Step 1: Update `STOP_DRYING` case in `DeviceErrorDialog.cpp`**

In `src/slic3r/GUI/DeviceErrorDialog.cpp` around line 452, update the stop drying action:

```cpp
    case DeviceErrorDialog::STOP_DRYING: {
        // Use the canonical CtrlAmsStopDrying path
        if (m_obj && m_obj->GetFilaSystem()) {
            // Get the AMS ID — check how the dialog knows which AMS is involved
            // For now, stop all AMS units or use the first one
            m_obj->GetFilaSystem()->CtrlAmsStopDrying(0);
        }
        // Fallback to the old command for backward compatibility
        m_obj->command_ams_drying_stop();
        break;
    }
```

Note: The exact AMS ID to pass depends on the error context. Check how BambuStudio handles this — it may use a specific AMS ID from the error data, or stop all drying. The fallback to `command_ams_drying_stop()` ensures backward compatibility if `CtrlAmsStopDrying` fails or the fila system isn't available.

- [ ] **Step 2: Verify build**

```powershell
cmake --build . --config RelWithDebInfo --target ALL_BUILD -- -m
```

- [ ] **Step 3: Commit**

```bash
git add src/slic3r/GUI/DeviceErrorDialog.cpp
git commit -m "feat: update error dialog stop-drying to use CtrlAmsStopDrying

Keeps command_ams_drying_stop() fallback for backward compatibility."
```

---

### Task 12: Build, verify, and final integration test

**Files:** All modified files

- [ ] **Step 1: Full clean build**

```powershell
cmake --build . --config RelWithDebInfo --target ALL_BUILD -- -m
```

Expected: Zero errors, zero warnings related to the new code.

- [ ] **Step 2: Verify no regressions in existing AMS features**

- Confirm the app launches
- Confirm AMS panel renders correctly for printers without N3F/N3S
- Confirm humidity popup still works for standard AMS and AMS Lite
- Confirm existing `command_ams_drying_stop()` still functions

- [ ] **Step 3: Manual UI smoke test (requires N3F/N3S printer)**

If a printer with N3F or N3S AMS is available:
1. Connect to the printer
2. Click AMS humidity indicator → verify `AMSDryCtrWin` opens
3. Verify humidity/temperature readings match printer data
4. Verify filament combobox is populated
5. Verify temp/time auto-fill when selecting a filament
6. Verify validation warnings for invalid temperatures
7. Verify the dialog closes cleanly

- [ ] **Step 4: Commit any final fixes**

```bash
git add -A
git commit -m "fix: final integration fixes for AMS drying control"
```
