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
#   Registers a network printer agent on load. Unlike the other capabilities, an
#   agent is driven through the native printer-agent surface: the host calls
#   individual operations (connect_printer, start_discovery, start_print, ...)
#   directly on your object. orca.printer_agent.PrinterAgentBase declares ~30
#   pure-virtual operations and EVERY one must be overridden - an operation you
#   leave out raises RuntimeError the moment the host calls it. This skeleton
#   implements just enough to load and be discovered; see
#   resources/orca_plugins/BBLPrinterAgentPlugin.py for a complete working agent
#   and the full method list. Delete this whole class if you are not writing one.
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

    # --- connection ------------------------------------------------------- #
    def connect_printer(self, dev_id, dev_ip, username, password, use_ssl) -> int:
        # TODO: open your transport (MQTT/HTTP/serial/...). Return 0 on success.
        return 0

    def disconnect_printer(self) -> int:
        # TODO: tear the transport down. Return 0 on success.
        return 0

    # --- discovery -------------------------------------------------------- #
    def start_discovery(self, start=True, sending=False) -> bool:
        # TODO: start/stop scanning the network for printers. Return True on success.
        return True

    # --- messaging -------------------------------------------------------- #
    def send_message(self, dev_id, json_str, qos=0, flag=0) -> int:
        # TODO: publish a control message to the device. Return 0 on success.
        return 0

    def get_user_selected_machine(self) -> str:
        return ""

    def set_user_selected_machine(self, dev_id) -> int:
        return 0

    # --- printing --------------------------------------------------------- #
    def start_print(self, params=None, update_fn=None, cancel_fn=None, wait_fn=None) -> int:
        # params is an orca.printer_agent.PrintParams. The host also passes callbacks:
        #   update_fn(stage, percent, message) - report progress to the host UI
        #   cancel_fn() -> bool                - poll it; abort if it returns True
        #   wait_fn(...)                        - host-provided wait hook
        # Return 0 on success.
        return 0

    # --- filament sync ---------------------------------------------------- #
    def get_filament_sync_mode(self):
        return orca.printer_agent.FilamentSyncMode.None_

    def fetch_filament_info(self, dev_id) -> bool:
        return False

    # NOTE: PrinterAgentBase has more pure-virtual operations a real agent must
    # implement, e.g. send_message_to_printer, bind_detect, bind/unbind, ping_bind,
    # check_cert/install_device_cert, request_bind_ticket, start_local_print,
    # start_local_print_with_record, start_sdcard_print, start_send_gcode_to_sdcard,
    # and the host-callback setters (set_server_callback, set_on_message_fn,
    # set_on_printer_connected_fn, set_queue_on_main_fn, ...). See
    # BBLPrinterAgentPlugin.py for the full set and expected signatures.


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
