import os
import sys

from binaryninja import log_info, log_error, show_message_box
from binaryninja.plugin import PluginCommand

plugin_dir = os.path.dirname(os.path.abspath(__file__))
if plugin_dir not in sys.path:
    sys.path.insert(0, plugin_dir)

try:
    from Generated import bin_diff_pb2, bin_diff_pb2_grpc
    from Upload import uploader
    from FunctionView import function_viewer

    IMPORTED = True
except ImportError as e:
    IMPORTED = False
    log_error(f"Could not import all the necessary modules: {e}")


class BinDiffPlugin:
    def __init__(self):
        self.server_address = "localhost:50051"
        self.uploaded_files = {}
        self.uploader = uploader.BinExportUploader(self.server_address)
        self.function_viewer = function_viewer.FunctionViewer(self.server_address)

    def upload_current_file(self, bv):
        file_id = self.uploader.upload_current_binexport(bv)

        if file_id:
            self.uploaded_files[bv.file.filename] = file_id

    def view_functions(self, bv):
        path = bv.file.filename
        if self.uploaded_files.__contains__(path):
            file_id = self.uploaded_files.get(path)
            self.function_viewer.retrieve_and_display_functions(bv, file_id)
            return
        else:
            show_message_box("Error", "This file has not been uploaded to the server "
                                      "or Binary Ninja got restarted and because of that it no longer holds "
                                      "file id to correctly access its contents using the server.\n\n"
                                      "In both cases, please, upload the file first.\n"
                                      "If it has already been uploaded in the past, server will recognize it.")


if IMPORTED:
    plugin = BinDiffPlugin()

    PluginCommand.register(
        "BinDiffPlugin\\Upload Current File",
        "Upload .BinExport for currently open .exe file",
        plugin.upload_current_file
    )

    PluginCommand.register(
        "BinDiffPlugin\\View Functions",
        "View functions from uploaded .BinExport of currently open .exe file",
        plugin.view_functions
    )

    log_info("BinDiffPlugin loaded - 2 commands available")
