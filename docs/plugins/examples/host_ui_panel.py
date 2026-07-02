# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy"]
#
# [tool.orcaslicer.plugin]
# name = "Host Inspector Panel"
# description = "A non-modal interactive panel that browses the whole orca.host read-only API."
# author = "OrcaSlicer"
# version = "1.0.0"
# ///
"""Host Inspector — a worked sample for the interactive `orca.host.ui` API that
also walks the entire `orca.host` read-only surface.

Run it from the Plugins dialog. It opens a NON-MODAL window (so OrcaSlicer stays
usable) with three expandable rows — Plater, Presets, Model. Each row shows a one
line summary; click its triangle to reveal the full detail for that section. The
page talks to the plugin through the injected `window.orca` bridge:

  page  --orca.postMessage({command:'refresh'})-->         plugin.on_message()
  page  --orca.postMessage({command:'detail',section})-->  plugin.on_message()
  plugin --win.post({command:'summary'|'detail', ...})-->   page (orca.onMessage)

Detail is fetched lazily — the heavy Model walk (mesh geometry + numpy arrays)
runs only when you expand the Model row. Click "Refresh" after changing the plate
and the summaries update; any section left open re-fetches its detail to stay live.

numpy is declared as a dependency so the zero-copy mesh arrays and 4x4 matrices
are available; the code still degrades gracefully if it is missing.
"""

import orca

try:
    import numpy as np
except Exception:
    np = None


# Soft caps so a heavy scene cannot produce an unusably long detail block. When a
# cap trims output we say so explicitly rather than truncating silently.
MAX_OBJECTS = 25
MAX_VOLUMES = 10
MAX_INSTANCES = 10


# --------------------------------------------------------------------------- #
# small formatting helpers
# --------------------------------------------------------------------------- #
def fmt_vec(v):
    """Format an (x, y, z) tuple / 3-element sequence with mm precision."""
    return "(" + ", ".join(f"{float(c):.3f}" for c in v) + ")"


def fmt_bbox(bb):
    """Format a host.BoundingBox as min / max / size (mm)."""
    if not bb.defined:
        return "<undefined>"
    return f"min{fmt_vec(bb.min)} max{fmt_vec(bb.max)} size{fmt_vec(bb.size)}"


def vol_type_name(volume):
    """Readable name of a ModelVolumeType enum value."""
    t = volume.type()
    return getattr(t, "name", str(t))


class Report:
    """Accumulates indented key/value lines into one block of text."""

    def __init__(self):
        self._lines = []

    def line(self, text=""):
        self._lines.append(text)

    def kv(self, indent, key, value, width=15):
        pad = " " * indent
        self._lines.append(f"{pad}{(key + ':'):<{width}} {value}")

    def text(self):
        return "\n".join(self._lines)


# --------------------------------------------------------------------------- #
# section builders — each guards itself so one failure doesn't sink the report
# --------------------------------------------------------------------------- #
def report_plater(r, plater):
    r.line("[Plater]")
    try:
        r.kv(2, "project dirty", plater.is_project_dirty())
        r.kv(2, "presets dirty", plater.is_presets_dirty())
        r.kv(2, "in snapshot", plater.inside_snapshot_capture())
    except Exception as exc:
        r.kv(2, "error", exc)
    r.line()


def report_presets(r, bundle):
    r.line("[Presets]")
    try:
        pp = bundle.current_print_preset()
        r.kv(2, "process", f"{pp.name}  (system={pp.is_system} dirty={pp.is_dirty})")

        printer = bundle.current_printer_preset()
        r.kv(2, "printer", f"{printer.name}  (system={printer.is_system})")

        r.kv(2, "filaments", bundle.current_filament_preset_names())

        # PresetCollection access: sizes + currently selected names.
        r.kv(2, "collections",
             f"prints={bundle.prints.size()} "
             f"printers={bundle.printers.size()} "
             f"filaments={bundle.filaments.size()}")

        # full_config_value(): a few representative keys, only if present.
        keys = ("layer_height", "nozzle_diameter", "filament_type",
                "printer_model", "sparse_infill_density")
        samples = []
        for key in keys:
            value = bundle.full_config_value(key)
            if value is not None:
                samples.append(f"{key}={value}")
        if samples:
            r.kv(2, "config sample", " | ".join(samples))
        r.kv(2, "config keys", f"{len(bundle.full_config_keys())} total")
    except Exception as exc:
        r.kv(2, "error", exc)
    r.line()


def report_mesh(r, indent, mesh, instance, volume):
    """Detail a host.TriangleMesh: counts, samples, and (numpy) arrays."""
    r.kv(indent, "vertices", mesh.vertex_count())
    r.kv(indent, "triangles", mesh.triangle_count())
    r.kv(indent, "empty", mesh.is_empty())
    r.kv(indent, "manifold", mesh.is_manifold())
    r.kv(indent, "volume", f"{mesh.volume():.3f} mm^3")
    r.kv(indent, "bbox", fmt_bbox(mesh.bounding_box()))
    if not mesh.is_empty():
        # numpy-free element access (always available, bounds-checked).
        r.kv(indent, "vertex[0]", fmt_vec(mesh.vertex(0)))
        r.kv(indent, "triangle[0]", tuple(mesh.triangle(0)))

    if np is None:
        r.kv(indent, "numpy", 'not installed (add dependencies=["numpy"])')
        return

    try:
        V = np.asarray(mesh.vertices())       # (N, 3) float32, read-only, zero-copy
        T = np.asarray(mesh.triangles())      # (M, 3) int32,  read-only, zero-copy
        N = np.asarray(mesh.face_normals())   # (M, 3) float32, computed copy
        r.kv(indent, "np vertices",
             f"shape={V.shape} dtype={V.dtype} "
             f"writeable={V.flags.writeable} zero_copy={V.base is not None}")
        r.kv(indent, "np triangles", f"shape={T.shape} dtype={T.dtype}")
        r.kv(indent, "np normals", f"shape={N.shape} dtype={N.dtype}")

        # World-space bounding box for this volume under `instance`, using the
        # row-vector convention world = [V 1] @ (instance @ volume).T
        if instance is not None and V.size:
            M = instance.matrix() @ volume.matrix()          # 4x4 float64
            homog = np.c_[V.astype(np.float64), np.ones(len(V))]
            world = (homog @ M.T)[:, :3]
            r.kv(indent, "world bbox",
                 f"min{fmt_vec(world.min(0))} max{fmt_vec(world.max(0))}")
    except Exception as exc:
        r.kv(indent, "numpy", f"<error: {exc}>")


def report_volume(r, index, volume, instance):
    r.line(f"    Volume[{index}] '{volume.name}'  type={vol_type_name(volume)}")
    try:
        r.kv(6, "roles",
             f"part={volume.is_model_part()} modifier={volume.is_modifier()} "
             f"negative={volume.is_negative_volume()} "
             f"support_enf={volume.is_support_enforcer()} "
             f"support_blk={volume.is_support_blocker()}")
        r.kv(6, "extruder_id", volume.extruder_id())
        r.kv(6, "offset", fmt_vec(volume.offset()))
        r.kv(6, "rotation", fmt_vec(volume.rotation()))
        r.kv(6, "scale", fmt_vec(volume.scaling_factor()))
        r.kv(6, "mirror", fmt_vec(volume.mirror()))
        r.kv(6, "facets", volume.facets_count())
        r.kv(6, "manifold", volume.is_manifold())
        r.kv(6, "mesh errors", volume.mesh_errors_count())
        r.kv(6, "painted",
             f"support={volume.is_fdm_support_painted()} "
             f"seam={volume.is_seam_painted()} "
             f"mm={volume.is_mm_painted()} "
             f"fuzzy={volume.is_fuzzy_skin_painted()}")
        r.kv(6, "config keys", len(volume.config_keys()))
        r.line("      mesh:")
        report_mesh(r, 8, volume.mesh(), instance, volume)
    except Exception as exc:
        r.kv(6, "error", exc)


def report_instance(r, index, instance):
    r.line(f"    Instance[{index}]")
    try:
        r.kv(6, "printable", instance.printable)
        r.kv(6, "is_printable", instance.is_printable())
        r.kv(6, "offset", fmt_vec(instance.offset()))
        r.kv(6, "rotation", fmt_vec(instance.rotation()))
        r.kv(6, "scale", fmt_vec(instance.scaling_factor()))
        r.kv(6, "mirror", fmt_vec(instance.mirror()))
        r.kv(6, "left_handed", instance.is_left_handed())
        r.kv(6, "world bbox", fmt_bbox(instance.bounding_box()))
    except Exception as exc:
        r.kv(6, "error", exc)


def report_object(r, index, obj):
    r.line(f"  Object[{index}] '{obj.name}'")
    try:
        r.kv(4, "input_file", obj.input_file or "<none>")
        r.kv(4, "module_name", obj.module_name or "<none>")
        r.kv(4, "printable", obj.printable)
        r.kv(4, "volumes", obj.volume_count())
        r.kv(4, "instances", obj.instance_count())
        r.kv(4, "facets", obj.facets_count())
        r.kv(4, "parts", obj.parts_count())
        r.kv(4, "materials", obj.materials_count())
        r.kv(4, "mesh errors", obj.mesh_errors_count())
        r.kv(4, "flags",
             f"multiparts={obj.is_multiparts()} cut={obj.is_cut()} "
             f"custom_layering={obj.has_custom_layering()}")
        r.kv(4, "painted",
             f"support={obj.is_fdm_support_painted()} "
             f"seam={obj.is_seam_painted()} "
             f"mm={obj.is_mm_painted()} "
             f"fuzzy={obj.is_fuzzy_skin_painted()}")
        r.kv(4, "z range", f"[{obj.min_z():.3f}, {obj.max_z():.3f}]")
        r.kv(4, "bbox", fmt_bbox(obj.bounding_box()))
        r.kv(4, "raw bbox", fmt_bbox(obj.raw_mesh_bounding_box()))

        # The first instance is used as the frame for world-space mesh maths.
        instance0 = obj.instance(0) if obj.instance_count() else None

        shown = min(obj.volume_count(), MAX_VOLUMES)
        for vi in range(shown):
            report_volume(r, vi, obj.volume(vi), instance0)
        if obj.volume_count() > shown:
            r.line(f"    ... and {obj.volume_count() - shown} more volume(s)")

        shown = min(obj.instance_count(), MAX_INSTANCES)
        for ii in range(shown):
            report_instance(r, ii, obj.instance(ii))
        if obj.instance_count() > shown:
            r.line(f"    ... and {obj.instance_count() - shown} more instance(s)")
    except Exception as exc:
        r.kv(4, "error", exc)
    r.line()


def report_model(r, model):
    r.line(f"[Model]  id={model.id()}")
    try:
        r.kv(2, "objects", model.object_count())
        r.kv(2, "materials", model.material_count())
        r.kv(2, "current plate", model.current_plate_index())
        r.kv(2, "max_z", f"{model.max_z():.3f} mm")
        r.kv(2, "painted",
             f"support={model.is_fdm_support_painted()} "
             f"seam={model.is_seam_painted()} "
             f"mm={model.is_mm_painted()} "
             f"fuzzy={model.is_fuzzy_skin_painted()}")
        r.kv(2, "designer", repr(model.designer()))
        r.kv(2, "design_id", repr(model.design_id()))
        r.kv(2, "bbox exact", fmt_bbox(model.bounding_box()))
        r.kv(2, "bbox approx", fmt_bbox(model.bounding_box_approx()))
    except Exception as exc:
        r.kv(2, "error", exc)
    r.line()

    count = model.object_count()
    if count == 0:
        r.line("  (no objects on the plate)")
        r.line()
        return

    shown = min(count, MAX_OBJECTS)
    for oi in range(shown):
        report_object(r, oi, model.object(oi))
    if count > shown:
        r.line(f"  ... and {count - shown} more object(s)")
        r.line()


# --------------------------------------------------------------------------- #
# one-line summaries (collapsed row text) — pure formatters
# --------------------------------------------------------------------------- #
def summary_plater(plater):
    return f"project dirty: {'yes' if plater.is_project_dirty() else 'no'}"


def summary_presets(bundle):
    return f"printer: {bundle.current_printer_preset().name}"


def summary_model(model):
    return f"{model.object_count()} object(s) · max_z {model.max_z():.1f} mm"


# --------------------------------------------------------------------------- #
# the page — three expandable section rows, themed, self-contained
# --------------------------------------------------------------------------- #
#
# No hardcoded colors: the host injects a theme matching OrcaSlicer's current
# light/dark mode and exposes it as CSS variables (--orca-bg, --orca-fg,
# --orca-muted, --orca-accent, --orca-border). The page only adds layout and
# reuses those variables, so it follows the active theme automatically.
PAGE = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  header { display:flex; gap:8px; align-items:center; padding:10px 14px;
           border-bottom:1px solid var(--orca-border); }
  header h1 { font-size:14px; margin:0; flex:1; }
  button.secondary { background:transparent; color:var(--orca-fg);
                     border-color:var(--orca-border); }
  .section { border-bottom:1px solid var(--orca-border); }
  .row { display:flex; align-items:center; gap:8px; padding:8px 14px;
         cursor:pointer; user-select:none; }
  .row:hover { background:var(--orca-border); }
  .tri { width:1em; color:var(--orca-muted); }
  .label { font-weight:600; }
  .sum { color:var(--orca-muted); }
  pre.detail { margin:0; padding:8px 14px 14px 32px;
               font:12px ui-monospace,SFMono-Regular,Menlo,monospace;
               white-space:pre-wrap; word-break:break-word; }
</style>
</head>
<body>
  <header>
    <h1>Host Inspector</h1>
    <button onclick="refresh()">Refresh</button>
    <button class="secondary" onclick="orca.close()">Close</button>
  </header>

  <div class="section">
    <div class="row" onclick="toggle('plater')">
      <span class="tri" id="tri-plater">&#9654;</span><span class="label">Plater</span>
      <span class="sum" id="sum-plater">&#8230;</span>
    </div>
    <pre class="detail" id="det-plater" style="display:none"></pre>
  </div>
  <div class="section">
    <div class="row" onclick="toggle('presets')">
      <span class="tri" id="tri-presets">&#9654;</span><span class="label">Presets</span>
      <span class="sum" id="sum-presets">&#8230;</span>
    </div>
    <pre class="detail" id="det-presets" style="display:none"></pre>
  </div>
  <div class="section">
    <div class="row" onclick="toggle('model')">
      <span class="tri" id="tri-model">&#9654;</span><span class="label">Model</span>
      <span class="sum" id="sum-model">&#8230;</span>
    </div>
    <pre class="detail" id="det-model" style="display:none"></pre>
  </div>

  <script>
    var KEYS = ['plater', 'presets', 'model'];
    var expanded = {}, loaded = {};

    function toggle(key) {
      expanded[key] = !expanded[key];
      document.getElementById('tri-' + key).innerHTML = expanded[key] ? '&#9660;' : '&#9654;';
      var det = document.getElementById('det-' + key);
      det.style.display = expanded[key] ? 'block' : 'none';
      if (expanded[key] && !loaded[key]) requestDetail(key);
    }

    function requestDetail(key) {
      document.getElementById('det-' + key).textContent = 'Loading…';
      orca.postMessage({ command: 'detail', section: key });
    }

    function refresh() { orca.postMessage({ command: 'refresh' }); }

    orca.onMessage(function (msg) {
      if (!msg) return;
      if (msg.command === 'summary') {
        var d = msg.data || {};
        KEYS.forEach(function (key) {
          document.getElementById('sum-' + key).textContent = d[key] || '';
          if (expanded[key]) { loaded[key] = false; requestDetail(key); }  // keep open rows live
        });
      } else if (msg.command === 'detail') {
        var det = document.getElementById('det-' + msg.section);
        if (det) det.textContent = msg.text;
        loaded[msg.section] = true;
      }
    });

    refresh();   // initial summaries; rows start collapsed
  </script>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
# the plugin
# --------------------------------------------------------------------------- #
class HostInspectorPanel(orca.script.ScriptPluginCapabilityBase):
    def get_name(self):
        return "Host Inspector"

    def execute(self):
        # Non-modal: returns immediately. The window is host-owned and lives on
        # after execute() returns; on_message keeps firing when the page posts.
        self.win = orca.host.ui.create_window(
            title="Host Inspector",
            html=PAGE,
            width=760,
            height=560,
            on_message=self.on_message,
            on_close=self.on_close,
        )
        return orca.ExecutionResult.success("Host Inspector opened.")

    # Called on the UI thread when the page posts a message.
    def on_message(self, msg):
        msg = msg or {}
        command = msg.get("command")
        if command == "refresh":
            self.win.post({"command": "summary", "data": self.summaries()})
        elif command == "detail":
            section = msg.get("section", "")
            self.win.post({"command": "detail", "section": section,
                           "text": self.detail(section)})

    def on_close(self):
        print("Host Inspector closed")

    @staticmethod
    def summaries():
        """One-line summary per section; each guarded independently so one
        failure (or a not-ready host) shows only that row's error."""
        def safe(fn):
            try:
                return fn()
            except Exception as exc:
                return f"<error: {exc}>"
        return {
            "plater": safe(lambda: summary_plater(orca.host.plater())),
            "presets": safe(lambda: summary_presets(orca.host.preset_bundle())),
            "model": safe(lambda: summary_model(orca.host.model())),
        }

    @staticmethod
    def detail(section):
        """Full monospace report for one section, built on demand."""
        try:
            r = Report()
            if section == "plater":
                report_plater(r, orca.host.plater())
            elif section == "presets":
                report_presets(r, orca.host.preset_bundle())
            elif section == "model":
                report_model(r, orca.host.model())
            else:
                return f"<unknown section: {section}>"
            return r.text()
        except Exception as exc:
            return f"<error: {exc}>"


@orca.plugin
class HostInspectorPlugin(orca.base):
    def register_capabilities(self):
        orca.register_capability(HostInspectorPanel)
