import os

import grpc
from Generated import bin_diff_pb2, bin_diff_pb2_grpc

from binaryninja import show_message_box


def validate_current_file(bv):
    if not bv or not bv.file or not bv.file.filename:
        show_message_box("Error", "No file is currently open in Binary Ninja")
        return False

    if not bv.file.filename.endswith('.exe'):
        show_message_box("Error", "This file is not .exe type")
        return False

    return True


def check_binexport_exists(binexport_path):
    if not os.path.exists(binexport_path):
        filename = os.path.basename(binexport_path)
        show_message_box("BinExport File Not Found",
                         f"Could not find .BinExport file:\n{filename}\n\n"
                         f"Please generate the .BinExport file from current .exe in the same directory:\n"
                         f"Expected location:\n{binexport_path}")
        return False
    return True


def read_binexport_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()

        return file_content

    except Exception as e:
        show_message_box("File Read Error", f"Could not read .BinExport file: {e}")
        return None


class BinExportUploader:
    def __init__(self, server_address):
        self.server_address = server_address

    def upload_current_binexport(self, bv):
        if not validate_current_file(bv):
            return None

        binexport_path = bv.file.filename[:-3] + "BinExport"

        if not check_binexport_exists(binexport_path):
            return None

        return self._start_upload(binexport_path)

    def _start_upload(self, binexport_path):
        try:
            file_content = read_binexport_file(binexport_path)
            if file_content is None:
                return None

            file_id = self._upload_to_server(file_content)

            if file_id:
                filename = os.path.basename(binexport_path)
                show_message_box("Success",
                                 f"Successfully uploaded!\n\n"
                                 f"File: {filename}\n")

            return file_id

        except Exception as e:
            show_message_box("Upload Error", f"Upload failed: {e}")

    def _upload_to_server(self, file_content):
        try:
            channel = grpc.insecure_channel(self.server_address)
            stub = bin_diff_pb2_grpc.BinDiffServerStub(channel)

            request = bin_diff_pb2.UploadRequest()
            request.content = file_content
            response = stub.Upload(request, timeout=30)

            if response and response.id:
                return response.id
            else:
                show_message_box("Upload Error", "Upload failed - server returned empty ID")
                return None

        except grpc.RpcError as e:
            show_message_box("Upload Error", f"gRPC upload error: {e.code()} - {e.details()}")
            return None
        except Exception as e:
            show_message_box("Upload Error", f"Upload error: {e}")
            return None
        finally:
            try:
                channel.close()
            except:
                pass
