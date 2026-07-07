# AMS Drying Control — Design Spec

**Date:** 2026-07-07
**Source:** Port from BambuStudio `AMSDryControl` feature
**Branch:** `dev/ams-heat`

## Overview

Port the AMS filament drying control feature from BambuStudio into OrcaSlicer. This allows users to start, monitor, and stop AMS-based filament drying directly from the slicer UI. Currently OrcaSlicer can monitor drying state and stop drying, but cannot initiate it. This feature adds the missing start-drying command, the full drying control dialog, and the drying preset lookup infrastructure.

**Target AMS models:** N3F (AMS 2 Pro, max 65°C) and N3S (AMS HT, max 85°C) — the only AMS units with heating hardware.

## Architecture

The feature spans three layers, matching the existing OrcaSlicer `DeviceCore/` pattern:

```
┌─────────────────────────────────────────────────────┐
│  UI Layer                                           │
│  AMSDryControl.hpp/.cpp    (new dialog)             │
│  AMSControl.cpp             (hook: click → dialog)  │
│  DeviceErrorDialog.cpp      (stop drying on error)  │
├─────────────────────────────────────────────────────┤
│  Command/Control Layer                              │
│  DevFilaSystemCtrl.cpp      (start/stop drying)     │
│  DevUtilBackend.h/.cpp      (preset lookup)         │
├─────────────────────────────────────────────────────┤
│  Data Model Layer                                   │
│  DevFilaSystem.h/.cpp       (enums, structs, parse) │
│  DevDefs.h                  (DevAmsType enum)       │
└─────────────────────────────────────────────────────┘
│  Communication Layer (already exists)               │
│  MachineObject::publish_json() → MQTT → printer     │
└─────────────────────────────────────────────────────┘
```

### New files (4 source + headers)

| File | Purpose |
|------|---------|
| `src/slic3r/GUI/AMSDryControl.hpp` | AMS drying control dialog class declarations |
| `src/slic3r/GUI/AMSDryControl.cpp` | Dialog implementation (~1800 lines) |
| `src/slic3r/GUI/DeviceCore/DevFilaSystemCtrl.cpp` | `CtrlAmsStartDryingHour()` and `CtrlAmsStopDrying()` |
| `src/slic3r/GUI/DeviceCore/DevUtilBackend.h` | Static utility class declaring `GetFilamentDryingPreset()` |
| `src/slic3r/GUI/DeviceCore/DevUtilBackend.cpp` | Reads filament drying presets from printer config |

### Modified files

| File | Changes |
|------|---------|
| `DevFilaSystem.h` | Add drying enums/structs to `DevAms`; add `DevFilamentDryingPreset` struct; add ctrl method declarations to `DevFilaSystem`; add `get_ams_drying_preset()` to `DevAmsTray` |
| `DevFilaSystem.cpp` | Parse dry status fields in `DevFilaSystemParser`; implement `IsSupportRemoteDry()`, `AmsIsDrying()`, `get_ams_drying_preset()` |
| `DevDefs.h` | Add `DevAmsType` as a global enum |
| `AMSControl.cpp` | Wire humidity indicator click to open `AMSDryCtrWin` for N3F/N3S AMS |
| `DeviceErrorDialog.cpp` | Update stop-drying to use `DevFilaSystem::CtrlAmsStopDrying()` |
| `DeviceCore/CMakeLists.txt` | Register new source files |

### New image assets (~14)

Humidity level icons (5), drying status per AMS type (8: heating/dehumidifying/error/cooling × N3F/N3S), heating icon, enable/disable indicators, guide image.

## Data Model

### `DevDefs.h` — Global `DevAmsType` enum

Promoted from `DevAms::AmsType` (currently local to the class) to a global enum so `DevFilamentDryingPreset` and `DevUtilBackend` can reference it without depending on `DevAms`:

```cpp
enum DevAmsType : int {
    EXT_SPOOL = 0,
    AMS = 1,
    AMS_LITE = 2,
    N3F = 3,    // AMS 2 Pro
    N3S = 4,    // AMS HT
};
```

### `DevAms` class additions (in `DevFilaSystem.h`)

**New enums:**

| Enum | Values |
|------|--------|
| `DryCtrlMode` | `Off=0, OnTime=1, OnHumidity=2` |
| `DryStatus` | `Off=0, Checking=1, Drying=2, Cooling=3, Stopping=4, Error=5, CannotStopHeatOutofControl=6, PrdTesting=7` |
| `DrySubStatus` | `Off=0, Heating=1, Dehumidify=2` |
| `DryFanStatus` | `Off=0, On=1` |
| `CannotDryReason` | `TaskOccupied=0, InsufficientPower=1, AmsBusy=2, ConsumableAtAmsOutlet=3, InitiatingAmsDrying=4, NotSupportedIn2dMode=5, DryingInProgress=6, Upgrading=7, InsufficientPowerNeedPluginPower=8, FilamentAtAmsOutletManualUnload=10` |

**New struct:**

```cpp
struct DrySettings {
    std::string dry_filament;
    int dry_temp = -1;   // -1 means invalid
    int dry_hour = -1;   // hours
};
```

**New getters on `DevAms`:**

- `std::optional<DryStatus> GetDryStatus() const`
- `std::optional<DrySubStatus> GetDrySubStatus() const`
- `std::optional<DryFanStatus> GetFan1Status() const`
- `std::optional<DryFanStatus> GetFan2Status() const`
- `std::optional<std::vector<CannotDryReason>> GetCannotDryReason() const`
- `std::optional<DrySettings> GetDrySettings() const`
- `bool IsSupportRemoteDry(const MachineObject* obj) const`
- `bool AmsIsDrying()`

**New private members:** `m_dry_status`, `m_dry_sub_status`, `m_dry_fan1_status`, `m_dry_fan2_status`, `m_dry_cannot_reasons`, `m_dry_settings` — all `std::optional<>`.

### `DevFilamentDryingPreset` struct (namespace scope in `DevFilaSystem.h`)

```cpp
struct DevFilamentDryingPreset {
    std::string filament_id;
    std::unordered_set<DevAmsType> ams_limitations;
    std::unordered_map<DevAmsType, float> filament_dev_ams_drying_time_on_idle;       // hours
    std::unordered_map<DevAmsType, float> filament_dev_ams_drying_temperature_on_idle;
    std::unordered_map<DevAmsType, float> filament_dev_ams_drying_time_on_print;      // hours
    std::unordered_map<DevAmsType, float> filament_dev_ams_drying_temperature_on_print;
    float filament_dev_drying_cooling_temperature;
    float filament_dev_drying_softening_temperature;
    float filament_dev_ams_drying_heat_distortion_temperature;
};
```

Populated from filament preset config keys (`filament_dev_ams_drying_temperature`, `filament_dev_ams_drying_time`, `filament_dev_drying_softening_temperature`, etc.).

### `DevAmsTray` addition

```cpp
std::optional<DevFilamentDryingPreset> get_ams_drying_preset() const;
```

Delegates to `DevUtilBackend::GetFilamentDryingPreset(setting_id)`.

### JSON parsing

`DevFilaSystemParser::ParseV1_0()` extended to parse the following fields from the printer's AMS status JSON:

| JSON field | DevAms member |
|------------|---------------|
| `dry_status` | `m_dry_status` (`DryStatus` enum) |
| `dry_sub_status` | `m_dry_sub_status` (`DrySubStatus` enum) |
| `dry_fan1_status` | `m_dry_fan1_status` |
| `dry_fan2_status` | `m_dry_fan2_status` |
| `dry_cannot_reasons` | `m_dry_cannot_reasons` (vector of `CannotDryReason`) |
| `dry_settings` | `m_dry_settings` (`DrySettings` struct) |

## Commands

### `DevFilaSystem::CtrlAmsStartDryingHour()`

Publishes JSON command `"ams_filament_drying"` via `MachineObject::publish_json()`:

```json
{
    "print": {
        "command": "ams_filament_drying",
        "sequence_id": "<seq>",
        "ams_id": <int>,
        "mode": 1,
        "filament": "<type_string>",
        "temp": <int>,
        "duration": <int>,
        "humidity": 0,
        "rotate_tray": <bool>,
        "cooling_temp": <int>,
        "close_power_conflict": false
    }
}
```

### `DevFilaSystem::CtrlAmsStopDrying()`

Same command with `mode: 0` (Off).

### Existing `MachineObject::command_ams_drying_stop()`

Kept for backward compatibility. The error dialog will be updated to call `CtrlAmsStopDrying()` instead, which is the preferred path.

## Backend Utility

### `DevUtilBackend` (new, `DeviceCore/DevUtilBackend.h/.cpp`)

Static utility class. Only method needed for this feature:

```cpp
static std::optional<DevFilamentDryingPreset> GetFilamentDryingPreset(const std::string& fila_id);
```

Iterates `wxGetApp().preset_bundle->filaments` to find the matching filament_id, then reads config keys into a `DevFilamentDryingPreset`. Uses a static map `{"0" → N3F, "1" → N3S}` for the `ams_limitations` string-to-enum conversion.

## UI Dialog

### `AMSDryCtrWin` (extends `DPIDialog`)

Three pages in a `wxSimplebook`:

#### Page 0: Main Page

Split left/right layout:

**Left panel — Status display:**
- Large humidity/drying state image: humidity level icon when idle; heating/dehumidifying/error animation when active
- Status label with animated heating icon ("Idle", "Drying-Heating", "Drying-Dehumidifying")
- Three stat labels: Humidity (%), Temperature (°C), Left Time (HH:MM). Left Time hidden when idle.

**Right panel — Controls.** Three sub-panels shown/hidden based on `DryStatus` and `CannotDryReason`:

| Sub-panel | When shown | Contents |
|-----------|------------|----------|
| Normal state | `DryStatus` is Off or Cooling | Filament type combobox → Temperature input (numeric, validated to AMS limits) → Time input (hours, 1–24) → Validation warning text → **Start** button |
| Cannot dry | `CannotDryReason` is non-empty (excluding only `DryingInProgress`) | Formatted reason text + **Unload** button (only for `ConsumableAtAmsOutlet` reason) |
| Drying error | `DryStatus` is Error | Error message + **Stop** button |
| Drying active | `DryStatus` is Checking/Drying/Stopping | Read-only temp/time display + **Stop** button |

**Temperature validation rules:**
- Hardware limits: N3F 45–65°C, N3S 45–85°C
- Heat distortion check: temp must not exceed `filament_dev_ams_drying_heat_distortion_temperature` when filament is present
- Printing mode: temp must not exceed recommended drying temp when this AMS is actively feeding a print
- Time: 1–24 hours

#### Page 1: Guide Page

Shown after clicking Start on Page 0, before sending the command:
- Instructional text about removing heat-sensitive filament
- `AMSFilamentPanel` showing each tray's filament type with ✅/⚠ icons based on whether drying temp exceeds that filament's softening point
- "Rotate spool when drying" checkbox
- **Back** and **Start** buttons

#### Page 2: Progress Page

Shown while waiting for printer to confirm drying has started:
- Animated progress bar (cycles 0–99% until printer state changes)
- Cycling status messages
- Auto-transitions back to Page 0 when printer reports drying active

### Helper classes (in `AMSDryControl.hpp`)

- **`FilamentItemPanel`** — Renders a single filament item with icon and text, with custom rounded-rectangle border painting
- **`AMSFilamentPanel`** — Container for multiple `FilamentItemPanel` instances, labeled with AMS name
- **`DryingPreset` struct, `DryCtrState` enum, `DryCtrDev` enum** — Local types for tracking preset state

### Dialog lifecycle

- Created on first click of the AMS humidity indicator
- Updated on each `AMSControl::parse_object()` cycle via `update(fila_system, obj)`
- Auto-closes if: AMS is removed from the system, AMS no longer supports remote drying, or AMS ID becomes invalid
- Closed manually via close button or dialog destruction
- On close: stops progress timer, resets to main page, restores button states

## Integration

### Entry point: AMS humidity click → dialog

In `AMSControl.cpp`, the `EVT_AMS_SHOW_HUMIDITY_TIPS` handler currently shows either `AmsHumidityTipPopup` or `uiAmsPercentHumidityDryPopup`. For N3F and N3S AMS types only, replace this with opening `AMSDryCtrWin`:

1. Lazily create `AMSDryCtrWin*` member on `AMSControl` (like `m_percent_humidity_dry_popup` today)
2. Call `set_ams_id()` and `update(fila_system, obj)` before showing
3. Show the dialog modally or modelessly

### Periodic updates

`AMSControl::parse_object()` updates AMS state on a timer. Extend it to:
1. If `m_dry_ctr_win` is shown, call `update()` to refresh readings
2. Update the dialog's AMS ID if the user switches AMS view

### Error dialog

`DeviceErrorDialog.cpp` line 452 calls `m_obj->command_ams_drying_stop()`. Update to use `obj->GetFilaSystem()->CtrlAmsStopDrying(ams_id)` for the correct AMS ID.

### CMakeLists

- `src/slic3r/GUI/DeviceCore/CMakeLists.txt`: add `DevFilaSystemCtrl.cpp`, `DevUtilBackend.h`, `DevUtilBackend.cpp`
- GUI sources list: add `AMSDryControl.hpp`, `AMSDryControl.cpp`

## Testing

### Manual verification

1. **Prerequisite:** Connect to a printer with N3F or N3S AMS hardware
2. Click AMS humidity indicator → verify dialog opens with correct humidity/temperature readings
3. Select a filament from the combobox → verify temp/time auto-fill from preset
4. Enter valid temp/time → verify Start button enables
5. Enter invalid temp (e.g., 100°C for N3F) → verify warning appears and button disables
6. Click Start → verify guide page shows filament tray status
7. Click Start on guide page → verify progress page appears, command is sent
8. Verify printer begins drying → dialog shows active drying state with countdown
9. Click Stop → verify drying stops
10. Test "cannot dry" states (e.g., during print, filament at outlet)

### Code-level checks

- Verify `CtrlAmsStartDryingHour` publishes correct JSON structure
- Verify `CtrlAmsStopDrying` publishes stop command
- Verify `GetFilamentDryingPreset` returns correct values for known filament IDs
- Verify dark mode rendering of all dialog pages

## Constraints

- **N3F/N3S only:** Standard AMS and AMS Lite do not have heating hardware; the dialog is not shown for them
- **Backward compatibility:** Existing `command_ams_drying_stop()` is preserved; new commands are additive
- **Cross-platform:** wxWidgets UI must work on Windows, macOS, Linux
- **Dark mode:** Dialog must support dark mode via `wxGetApp().dark_mode()` and `StateColor::darkModeColorFor()`
- **Profile compatibility:** Existing profiles with `filament_dev_ams_drying_*` keys (Qidi) continue to work; the feature reads the same keys
- **No printer-agent changes needed:** All commands go through existing `publish_json()` → `NetworkAgent` path, which already handles MQTT for connected printers
