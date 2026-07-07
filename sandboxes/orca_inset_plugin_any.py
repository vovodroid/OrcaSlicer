# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy"]
#
# [tool.orcaslicer.plugin]
# name = "Inset Every Slice"
# description = "Insets every layer's slices by 1mm at the Slice boundary (demo)."
# author = "OrcaSlicer"
# version = "0.01"
# type = "slicing-pipeline"
# ///
"""Inset Every Slice -- a small, WORKING SlicingPipeline sample plugin.

At Step.Slice, for every layer/region of the sliced object, this shrinks each
sliced surface's outer contour by INSET_MM and writes the result back with
LayerRegion.set_slices(). set_slices() at Step.Slice is the fully-supported
mutation-cascade entry point (see docs/plugins/slicing_pipeline_plugin.md next
to this file): the split slice loop runs make_perimeters() right after the
Slice hook, so the change cascades into perimeters, infill and the final
G-code -- the toolpath preview visibly shrinks.

This is a *teaching* sample, not a production-grade offset:
  - The inset is a per-axis contraction toward the contour's bounding-box
    center: each vertex coordinate is pulled toward the center by up to
    INSET_MM, independently on X and Y, and never crosses the center. That is
    an exact inward offset for a convex, axis-aligned contour (e.g. the square
    cross-section of a plain cube) but it is NOT a general polygon offset -- it
    will distort a rotated or non-rectangular contour. A real plugin should
    reach for a proper offset library (e.g. Shapely's buffer(), or Clipper)
    instead.
  - Holes are passed through unchanged. A correct hole inset needs an
    *outward* offset plus re-validating containment against the shrunk outer
    contour, which is more than a short demo should attempt.
  - Degenerate contours (fewer than 3 points, or a shape too small for a 1mm
    inset without inverting) are left unmodified rather than mutated into
    garbage.

numpy is declared as a dependency: the geometry accessors hand back zero-copy
int64 ndarrays, and set_slices() requires genuine ndarrays back (not plain lists),
so building the modified contour needs numpy.
"""
import numpy as np
import orca

INSET_MM = 1.0


def _pull(value, center, amount):
    """Move `value` toward `center` by up to `amount`, never crossing it."""
    if value > center:
        return max(center, value - amount)
    if value < center:
        return min(center, value + amount)
    return center


def _inset_contour(contour, inset_scaled):
    """Axis-aligned inward contraction of an (N,2) int64 contour.

    Returns a new (N,2) int64 array, or None if the contour is degenerate
    (fewer than 3 points) or too small for `inset_scaled` without inverting.
    """
    if contour.shape[0] < 3:
        return None
    xs, ys = contour[:, 0], contour[:, 1]
    min_x, max_x = int(xs.min()), int(xs.max())
    min_y, max_y = int(ys.min()), int(ys.max())
    if (max_x - min_x) <= 2 * inset_scaled or (max_y - min_y) <= 2 * inset_scaled:
        return None  # shape too small on at least one axis: inset would invert it
    cx, cy = (min_x + max_x) // 2, (min_y + max_y) // 2

    out = contour.copy()
    for i in range(contour.shape[0]):
        out[i, 0] = _pull(int(contour[i, 0]), cx, inset_scaled)
        out[i, 1] = _pull(int(contour[i, 1]), cy, inset_scaled)
    return out


class InsetEverySlice(orca.slicing.SlicingPipelineCapabilityBase):
    def get_name(self):
        return "Inset Every Slice"

    def execute(self, ctx):
        if ctx.step != orca.slicing.Step.Slice or ctx.object is None:
            return orca.ExecutionResult.success()

        # Millimeters -> scaled integer units via the *live* scale. SCALING_FACTOR
        # is not a fixed constant (large beds use a coarser scale), so this must be
        # read at call time -- never hardcode 1e6/1e-6.
        inset_scaled = int(round(INSET_MM / orca.slicing.unscale(1)))

        regions_touched = 0
        for layer in ctx.object.layers():
            if ctx.cancelled():
                break
            for region in layer.regions():
                surfaces = region.slices.surfaces
                if not surfaces:
                    continue  # an empty region has nothing to inset

                new_surfaces = []
                for surface in surfaces:
                    expoly = surface.expolygon
                    contour = expoly.contour.points()
                    inset = _inset_contour(contour, inset_scaled)
                    if inset is not None:
                        contour = inset
                    # Holes are passed through unchanged -- see module docstring.
                    new_surfaces.append([contour, [h.points() for h in expoly.holes]])

                region.set_slices(new_surfaces)
                regions_touched += 1

        return orca.ExecutionResult.success(f"inset applied to {regions_touched} region(s)")


@orca.plugin
class InsetEverySlicePackage(orca.base):
    def register_capabilities(self):
        orca.register_capability(InsetEverySlice)
