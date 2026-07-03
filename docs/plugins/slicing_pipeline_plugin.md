# Slicing Pipeline Plugins

> This note is a companion to the general Python plugin documentation (see the
> OrcaSlicer wiki for `plugin_development.md` / `plugin_system.md` /
> `plugin_audit_hook.md` — the plugin-doc set was migrated there and no longer
> lives under `docs/` in this repository). It covers only what is specific to
> the `SlicingPipeline` capability: `orca.slicing.SlicingPipelineCapabilityBase`.
> Read it alongside the worked sample at
> [`resources/orca_plugins/InsetEverySlice.py`](../../resources/orca_plugins/InsetEverySlice.py).

A `SlicingPipeline` capability is invoked by OrcaSlicer at several seams inside
`Print::process()`, on the slicing worker thread, so it can read — and in one case,
mutate — the intermediate data the slicer produces between the raw mesh and the
final G-code. It is research/experimental: the read graph is broad, but only one
mutation is fully wired through to the toolpath output today.

```python
class MyCapability(orca.slicing.SlicingPipelineCapabilityBase):
    def get_name(self):
        return "My Capability"
    def execute(self, ctx: orca.slicing.SlicingPipelineContext):
        ...
        return orca.ExecutionResult.success()
```

## When `execute()` fires, and what `ctx.object` is

`ctx.step` is one of the `orca.slicing.Step` values, in the order they occur inside
one `Print::process()` run: `Slice`, `Perimeters`, `EstimateCurledExtrusions`,
`Infill`, `Ironing`, `Contouring`, `SupportMaterial`, `DetectOverhangsForLift`,
`WipeTower`, `SkirtBrim`, `SimplifyPath`. Note that `SimplifyPath` is declared
before `WipeTower` and `SkirtBrim` in the `Step` enum, but fires after them at runtime.

Most steps are **per-object**: `execute()` runs once per `PrintObject` that just
(re)computed that step, and `ctx.object` is a `PrintObjectView` for it. `WipeTower`
and `SkirtBrim` are **print-wide**: they run once per slice, and `ctx.object` is
`None`. Always check both `ctx.step` and `ctx.object` before touching object data —
see `InsetEverySlice.execute()` for the standard guard:

```python
if ctx.step != orca.slicing.Step.Slice or ctx.object is None:
    return orca.ExecutionResult.success()
```

The hook fires **only on genuine recomputation** of that step for that object — an
incremental re-slice that finds a step already cached does not re-invoke `execute()`
for it (see "Persistence and duplicates" below).

## Supported mutations, per step

The read graph (`PrintObjectView` → `LayerView` → `LayerRegionView` →
`SurfaceView`/`PathData`) is available at every step. Mutation is narrower:

| Mutator | Step it makes sense at | Cascade |
|---|---|---|
| `LayerRegionView.set_slices(polygons)` | `Step.Slice` | **Fully supported.** The split slice loop calls `make_perimeters()` immediately after the `Slice` hook, so the new geometry flows into perimeters, infill and the final G-code — the toolpath preview visibly changes. This is the primary, recommended mutation entry point. |
| `LayerRegionView.set_fill_surfaces(polygons)` | `Step.Infill` | **Limited.** Replaces the stored fill-prep surfaces but does **not** regenerate the `fills` toolpaths already built for that region in v1 — the surface data changes, the rendered infill does not (yet). |
| `LayerView.set_lslices(islands)` | any step where a `LayerView` is reachable | **Limited / read-oriented.** Replaces the layer's merged islands and refreshes the `lslices_bboxes` cache so that invariant stays consistent, but no further cascade is documented — treat it as advanced/diagnostic, not a way to redirect downstream computation. |
| `SurfaceView.set_type(surface_type)` | any step where a `SurfaceView` is reachable | **Limited.** Reassigns `surface_type` only; the geometry is untouched, and nothing downstream is automatically regenerated as a result. |

Every other step (`Perimeters`, `EstimateCurledExtrusions`, `Ironing`, `Contouring`,
`SupportMaterial`, `DetectOverhangsForLift`, `SimplifyPath`, `WipeTower`,
`SkirtBrim`) exposes **read-only** access in practice: the views are there, but
nothing calls back into a not-yet-run earlier step, so writes there have no
guaranteed effect on the final output. Treat non-`Slice` steps as inspection
points, and do real geometry edits through `set_slices()` at `Step.Slice`.

**Gotcha:** `set_slices()`/`set_fill_surfaces()` build every replacement `Surface`
from the *first* surface in the collection being replaced (or `stInternal` if the
region had none) — per-surface `surface_type` distinctions among the surfaces you
pass in are **not** preserved individually. If a region's slices mix top/bottom/
internal surfaces and you need to keep that distinction, mutate contours, then
restore per-surface types with `SurfaceView.set_type()` afterward.

## Scaled coordinates are `int64`, and the scale is live

Every point (`ExPolygonView.contour()`/`holes()`, `PathData.points()`) is a
read-only `int64` NumPy array of internal scaled units, not millimeters. Convert
with `orca.slicing.unscale(coord)` — **never** hardcode `1e-6`/`1e6`. The scale
factor is not a fixed constant in this codebase (larger beds use a coarser scale),
so it must be read at call time:

```python
mm_per_unit = orca.slicing.unscale(1)          # read the live scale
one_mm_scaled = int(round(1.0 / mm_per_unit))  # -> scaled-unit equivalent of 1mm
```

`InsetEverySlice` follows exactly this pattern for its 1mm inset.

## Lifetime: every view and array is valid only during `execute(ctx)`

`PrintObjectView`, `LayerView`, `LayerRegionView`, `SurfaceView`, `ExPolygonView`,
and `PathData` are thin, non-owning wrappers over memory owned by the `Print`
being sliced. The NumPy arrays they hand out are zero-copy: they alias that same
memory. All of it is valid **only for the duration of the `execute(ctx)` call that
produced it** — the underlying `std::vector` storage can be reallocated by the very
next pipeline step. Do not stash a view, a `SurfaceView`, or an array in `self.*`
and read it from a later `execute()` call, and do not return one from `execute()`.
Read what you need, copy any plain Python values out (`int()`, `.tolist()`, etc. —
never the array itself) if you must keep them, and let the rest go when the call
returns.

## Persistence and duplicates

A `set_slices()` mutation is written directly into the `PrintObject`'s `Layer`
data, not into some separate plugin-owned overlay:

- **It survives across steps within the same slice** — that's what makes the
  cascade into perimeters/infill/G-code work.
- **It survives an incremental re-slice only while `posSlice` stays cached *and*
  perimeters are not re-run (v1 limitation).** `slice()` backs up the *pre-hook*
  geometry into each layer's `raw_slices` before the `Slice` hook fires, and
  `make_perimeters()` calls `restore_untyped_slices()`, which overwrites
  `slices` from that backup. So a config change that only invalidates a *later*
  step but still re-runs perimeters (e.g. `wall_loops`) silently reverts the
  mutation to the original geometry, while `posSlice` stays cached so the `Slice`
  hook does **not** fire again to re-apply it. Propagating the mutation into
  `raw_slices` so it survives a perimeter re-run is a known v1 limitation; for
  now, force a genuine re-slice (see below) if you need the mutation reapplied.
- **Toggling which plugins are selected always gets a clean slice.** Changing the
  `Slicing Pipeline Plugin` picker selection itself invalidates `posSlice`, so
  selecting or deselecting a plugin forces a genuine re-slice (and re-fires the
  hook, or stops firing it) rather than leaving stale mutated geometry behind.
- **Duplicated (identical) objects share the same `Layer*`.** Mutating the
  instance that actually slices is automatically visible on every duplicate of
  it. An object that must diverge from its duplicates cannot be an exact
  duplicate of them.

## Errors, `FatalError`, and cancellation

`execute()` runs under the GIL, inside a `try`/`catch` on the host side. Any
uncaught Python exception, or returning
`orca.ExecutionResult.failure(orca.PluginResult.FatalError, message)`, is converted
into a `Slic3r::SlicingError` tagged with the plugin's capability name and your
message. That surfaces to the user as a normal (non-fatal) slicing-error
notification — it aborts that slice, but it does not crash the app. Prefer this
over letting exceptions propagate silently, and put anything you need the user to
see in the message.

Check `ctx.cancelled()` if you are doing meaningfully expensive work in a loop
(e.g. a large multi-object print) so a user-initiated cancel is honored promptly
instead of only at the next step boundary; `InsetEverySlice` demonstrates the
check on its per-layer loop even though its own work is cheap.
