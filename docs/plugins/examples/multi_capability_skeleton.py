# /// script
# requires-python = ">=3.12"
# dependencies = []
#
# [tool.orcaslicer.plugin]
# name = "Capability Skeleton"
# description = "Starter template: one plugin package that registers several different capabilities."
# author = "Your Name"
# version = "1.0.0"
# ///
"""Multi-capability plugin skeleton.

Copy this file into its own folder under ``data_dir()/orca_plugins/<your-plugin>/``
and adapt it. It shows the full shape of a plugin that offers more than one
capability:

  * ExampleScript        - a ``script`` capability (runs from the Plugins dialog)
  * ExamplePostProcess   - a ``post-processing`` capability (edits exported G-code)
  * ExamplePrinterAgent  - a ``printer-connection`` capability (a network printer agent)

A plugin is a *package* (the ``@orca.plugin`` class at the bottom) that registers one
or more *capabilities*. Each capability is an independent class with its own name and
type. To make your own plugin: delete the capabilities you do not need, fill in the
ones you keep, and register only those in ``register_capabilities``.

See ``plugin_development.md`` for the full reference, and ``host_ui_panel.py`` for a
richer worked example built on the ``orca.host`` read-only API.
"""

import json

import orca


# --------------------------------------------------------------------------- #
# Capability 1 - a script capability
#   Runs on the main/UI thread via the Plugins dialog "Run" action. Keep
#   execute() fast: a slow call freezes the UI. Offload heavy work to your own
#   threading.Thread (which must not touch the model) and surface results through
#   an orca.host.ui window (see host_ui_panel.py).
# --------------------------------------------------------------------------- #
class ExampleScript(orca.script.ScriptPluginCapabilityBase):
    def get_name(self):
        # Display name; unique within this plugin; must not contain ';'.
        return "Example Script"

    def on_load(self):
        # Optional. Runs once when the capability is loaded. Default: no-op.
        pass

    def on_unload(self):
        # Optional. Runs once when the capability is unloaded. Default: no-op.
        pass

    def execute(self):
        # TODO: your logic here.
        return orca.ExecutionResult.success("Example Script ran")


# --------------------------------------------------------------------------- #
# Capability 2 - a post-processing (G-code) capability
#   Runs on a background slicing thread during G-code export. Receives a context
#   pointing at the temporary G-code file, which you may rewrite in place.
# --------------------------------------------------------------------------- #
class ExamplePostProcess(orca.gcode.GCodePluginCapabilityBase):
    def get_name(self):
        return "Example Post-process"

    def execute(self, ctx):
        # ctx.gcode_path   - absolute path to the temp G-code being post-processed
        # ctx.output_name  - the output file name
        # ctx.host         - target host when exporting to a network printer
        # ctx.orca_version - OrcaSlicer version string
        # Writing into the folder of ctx.gcode_path is permitted by the audit hook;
        # writing elsewhere outside data_dir() is blocked.
        try:
            with open(ctx.gcode_path, "a", encoding="utf-8") as f:
                f.write(f"\n; processed by Example Post-process for {ctx.output_name}\n")
        except Exception as exc:
            return orca.ExecutionResult.failure(
                orca.PluginResult.RecoverableError,
                f"post-process failed: {exc}")
        return orca.ExecutionResult.success("G-code annotated")


# --------------------------------------------------------------------------- #
# Capability 3 - a printer-connection (agent) capability
#   Registers a network printer agent on load. The host serialises each native
#   agent call into a single JSON request envelope
#   ({command, request_id, dev_id, payload}); you dispatch on request["command"]
#   and return a JSON response envelope string. Delete this whole class if your
#   plugin is not a printer agent.
# --------------------------------------------------------------------------- #
class ExamplePrinterAgent(orca.printer_agent.PrinterAgentBase):
    def get_name(self):
        return "Example Printer Agent"

    def get_agent_info(self):
        return orca.printer_agent.AgentInfo(
            id="example-agent",
            name="Example Printer Agent",
            version="1.0.0",
            description="Skeleton printer agent.",
        )

    def send_command(self, request_json):
        # Parse the request envelope and dispatch on its "command".
        try:
            request = json.loads(request_json or "{}")
        except json.JSONDecodeError:
            request = {}
        command = request.get("command", "")
        request_id = request.get("request_id", "")

        # TODO: handle the commands your device supports and build a real response.
        return json.dumps({
            "request_id": request_id,
            "status": "error",
            "message": f"unhandled command: {command}",
        })

    def send_command_with_progress(self, request_json, update_fn, cancel_fn):
        # Optional. Override only for long-running commands (uploads, prints).
        #   update_fn(stage, percent, message) - push progress to the host UI.
        #   cancel_fn() -> bool                - poll it; abort if it returns True.
        # Default behaviour is to run as a plain send_command.
        return self.send_command(request_json)


# --------------------------------------------------------------------------- #
# The package - exactly one @orca.plugin class per file. register_capabilities()
# declares which capabilities this plugin exposes. A capability you do not pass to
# register_capability() is invisible to OrcaSlicer, even if its class is defined
# above.
# --------------------------------------------------------------------------- #
@orca.plugin
class CapabilitySkeleton(orca.base):
    def register_capabilities(self):
        orca.register_capability(ExampleScript)
        orca.register_capability(ExamplePostProcess)
        orca.register_capability(ExamplePrinterAgent)
