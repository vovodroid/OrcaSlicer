# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy"]
#
# [tool.orcaslicer.plugin]
# name = "Twistify"
# description = "Twists, tapers, and wobbles every layer's slice polygons as a function of Z (demo)."
# author = "OrcaSlicer"
# version = "0.01"
# type = "slicing-pipeline"
#
# [tool.orcaslicer.plugin.settings]
# twist_deg_per_mm = "1.0"
# taper_per_mm = "0.0"
# wobble_ampl_mm = "0.0"
# wobble_period_mm = "20.0"
# min_scale = "0.05"
# ///
"""Twistify -- twist/taper/wobble any model at slice time.

At Step.Slice (the one fully-supported mutation seam -- see
docs/plugins/slicing_pipeline_plugin.md), every layer's sliced surfaces are
rotated, uniformly scaled, and optionally swayed about the object's center as a
function of Z, then written back with LayerRegion.set_slices(). The
dedicated slice loop runs make_perimeters() right after this hook, so the
transform cascades into perimeters, infill, and the final G-code -- the toolpath
preview visibly corkscrews, and unlike G-code post-processing hacks the printed
part keeps correct multi-wall perimeters, infill, and flow.

Parameters come from ctx.params -- the [tool.orcaslicer.plugin.settings] table in
the PEP-723 header above. Edit them there (and re-slice) to change the effect; no
code edit or plugin reload is needed. Recipes: twisted vase
(twist 1.0), tapered spire (twist 0.3, taper -0.006), wobbling tower
(twist 0, wobble_ampl 0.8).

The transform uses three of the gap-closing APIs so the plugin stays small and
correct:
  * ctx.object.bounding_box() gives the twist axis (each object twists about its
    own center) -- no footprint reconstruction.
  * set_slices(refresh_lslices=True) re-derives the layer's merged islands, so
    overhang/bridge/skirt/support stay coherent -- no manual set_lslices().
  * a per-entry SurfaceType (third set_slices element) preserves each surface's
    type -- no replace-then-reassign-surface_type two-step.
Because the Slice hook re-snapshots raw_slices afterward, the twist also survives
a later perimeter-only re-slice (e.g. changing wall_loops) instead of reverting.

numpy is REQUIRED at slice time (declared above): the host's geometry accessors
return numpy arrays. The pure-Python fallback in _transform_ring exists only so this
module still imports on numpy-less interpreters (the unit-test harness); it is
unreachable in production. Outputs are built by .copy()-ing the host's zero-copy
read arrays (dtype/shape inherited -- int64 on every platform, immune to Windows'
numpy int32 default), never constructed from scratch.

Physical-print caveats: keep the twist modest (horizontal shift per layer at the
part's outer radius should stay under ~1.4x layer height) or the real print grows
unsupported overhangs -- the preview looks great regardless. The first object
layer is untouched (z_rel = 0), so bed adhesion is unaffected. Twists EVERY
object on the plate (each about its own center).
"""
import math

import orca

try:                      # required in production; guard keeps module importable in the test harness
    import numpy as _np
except ImportError:
    _np = None

# Fallback defaults, overridden per-slice by ctx.params (the settings table in the header).
_DEFAULTS = {
    "twist_deg_per_mm": 1.0,   # signed twist rate; 1 deg/mm corkscrews a 100mm cube by 100 deg
    "taper_per_mm":     0.0,   # relative XY scale change per mm of Z (-0.004 = shrink 0.4%/mm)
    "wobble_ampl_mm":   0.0,   # X sway amplitude in mm (0 disables)
    "wobble_period_mm": 20.0,  # full sway period in mm of Z
    "min_scale":        0.05,  # taper clamp: polygons shrink but can never collapse to a point
}


def _params(ctx):
    """Resolve parameters from ctx.params (string values), falling back to _DEFAULTS."""
    try:
        src = dict(ctx.params)   # ctx.params is a read-only dict of str -> str
    except (AttributeError, TypeError):
        src = {}
    out = {}
    for key, default in _DEFAULTS.items():
        try:
            out[key] = float(src[key])
        except (KeyError, TypeError, ValueError):
            out[key] = default
    return out


def _is_identity(p):
    return p["twist_deg_per_mm"] == 0.0 and p["taper_per_mm"] == 0.0 and p["wobble_ampl_mm"] == 0.0


def _layer_params(z_rel, mm_to_scaled, p):
    """(cos, sin, scale, x_offset_scaled) for one layer. Exact identity at z_rel == 0."""
    theta = math.radians(p["twist_deg_per_mm"] * z_rel)
    s = max(p["min_scale"], 1.0 + p["taper_per_mm"] * z_rel)
    ox = 0.0
    if p["wobble_ampl_mm"] != 0.0 and p["wobble_period_mm"] > 0.0:
        ox = p["wobble_ampl_mm"] * math.sin(2.0 * math.pi * z_rel / p["wobble_period_mm"]) * mm_to_scaled
    return math.cos(theta), math.sin(theta), s, ox


def _transform_ring(ring, cos_t, sin_t, s, cx, cy, ox):
    """Similarity-transform one int64 (N,2) ring about (cx, cy), then shift X by ox.

    Returns a NEW writable int64 (N,2) ndarray with the same point count, or None
    if the ring is degenerate (< 3 points; the host's parse_polygon would reject it).
    Rotation + uniform positive scale preserves orientation and hole containment and
    cannot self-intersect; the host re-normalizes winding on write-back anyway.
    """
    n = ring.shape[0]
    if n < 3:
        return None
    if _np is not None:  # production path (numpy is a declared dependency)
        pts = ring.astype(_np.float64)
        dx = pts[:, 0] - cx
        dy = pts[:, 1] - cy
        out = _np.empty_like(ring)  # inherits int64 -- immune to Windows' int32 default
        out[:, 0] = _np.rint((dx * cos_t - dy * sin_t) * s + cx + ox)
        out[:, 1] = _np.rint((dx * sin_t + dy * cos_t) * s + cy)
        return out
    out = ring.copy()  # defensive fallback; unreachable when the host supplied `ring`
    for i in range(n):
        dx = float(ring[i, 0]) - cx
        dy = float(ring[i, 1]) - cy
        out[i, 0] = int(round((dx * cos_t - dy * sin_t) * s + cx + ox))
        out[i, 1] = int(round((dx * sin_t + dy * cos_t) * s + cy))
    return out


def _transform_expoly(expoly, cos_t, sin_t, s, cx, cy, ox):
    """ExPolygon -> [contour, [holes...]] entry for set_slices.

    Returns None if the outer contour is degenerate; degenerate holes are dropped
    (a <3-point ring is meaningless and would make the host raise ValueError).
    """
    contour = _transform_ring(expoly.contour.points(), cos_t, sin_t, s, cx, cy, ox)
    if contour is None:
        return None
    holes = []
    for hole in expoly.holes:
        th = _transform_ring(hole.points(), cos_t, sin_t, s, cx, cy, ox)
        if th is not None:
            holes.append(th)
    return [contour, holes]


class Twistify(orca.slicing.SlicingPipelineCapabilityBase):
    def get_name(self):
        return "Twistify"

    def execute(self, ctx):
        # Standard guard: Step.Slice is per-object and the only fully-wired mutation seam.
        if ctx.step != orca.slicing.Step.Slice or ctx.object is None:
            return orca.ExecutionResult.success()

        p = _params(ctx)
        # Exact no-op parameters -> leave the pipeline byte-identical by construction.
        if _is_identity(p):
            return orca.ExecutionResult.success("Twistify: identity parameters, nothing to do")

        # Millimeters -> scaled units via the LIVE scale (never hardcode 1e6/1e-6).
        mm_to_scaled = 1.0 / orca.slicing.unscale(1)

        layers = ctx.object.layers()
        if not layers:
            return orca.ExecutionResult.success("Twistify: object has no layers")

        # Twist axis = the object's bounding-box center (scaled coords, same frame as the
        # slice polygons), so each object on the plate twists about its own center.
        min_x, min_y, max_x, max_y = ctx.object.bounding_box()
        cx = (min_x + max_x) / 2.0
        cy = (min_y + max_y) / 2.0
        z0 = float(layers[0].print_z)  # z_rel = 0 on the first layer -> footprint untouched

        layers_touched = 0
        for layer in layers:
            if ctx.cancelled():
                break
            z_rel = float(layer.print_z) - z0
            cos_t, sin_t, s, ox = _layer_params(z_rel, mm_to_scaled, p)
            if cos_t == 1.0 and sin_t == 0.0 and s == 1.0 and ox == 0.0:
                continue  # exact identity (always the first layer): skip set_slices entirely

            for region in layer.regions():
                surfaces = region.slices.surfaces
                if not surfaces:
                    continue  # set_slices() rejects nothing now, but an empty region has nothing to do
                new_surfaces = []
                for surface in surfaces:
                    entry = _transform_expoly(surface.expolygon, cos_t, sin_t, s, cx, cy, ox)
                    if entry is None:
                        continue  # degenerate outer contour: drop this surface
                    # Carry this surface's type as the third entry element so it is preserved
                    # per surface. The plain enum value is read out BEFORE set_slices, since the
                    # Surface reference dangles once the collection is replaced.
                    entry.append(surface.surface_type)
                    new_surfaces.append(entry)
                if not new_surfaces:
                    continue  # every surface degenerate: leave the region untouched
                # refresh_lslices=True re-derives the layer's merged islands + bbox cache from
                # the twisted slices, so overhang/bridge detection and brim/skirt/support stay
                # coherent -- no separate Layer.set_lslices() pass needed.
                region.set_slices(new_surfaces, refresh_lslices=True)

            layers_touched += 1

        name = ctx.object.model_object().name or "object"
        return orca.ExecutionResult.success(
            f"Twistify: transformed {layers_touched} layer(s) of '{name}' "
            f"(twist {p['twist_deg_per_mm']} deg/mm, taper {p['taper_per_mm']}/mm, "
            f"wobble {p['wobble_ampl_mm']} mm)")


@orca.plugin
class TwistifyPackage(orca.base):
    def register_capabilities(self):
        orca.register_capability(Twistify)
