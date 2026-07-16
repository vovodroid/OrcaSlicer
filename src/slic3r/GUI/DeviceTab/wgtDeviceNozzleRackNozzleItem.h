//**********************************************************/
/* File: wgtDeviceNozzleRackNozzleItem.h
*  Description: Compatibility header for the single-nozzle-cell widget.
//**********************************************************/

#pragma once

// Orca: transitional shim (removed in resync cluster 8)
// The wgtDeviceNozzleRackNozzleItem class and its EVT_NOZZLE_RACK_NOZZLE_ITEM_SELECTED event now
// live inline in wgtDeviceNozzleRack.{h,cpp} (folded back to the reference shape). This header is
// kept only so the not-yet-resynced GUI/Widgets/MultiNozzleSync includer keeps resolving; it is
// deleted once that consumer is resynced to include wgtDeviceNozzleRack.h directly.
#include "wgtDeviceNozzleRack.h"
