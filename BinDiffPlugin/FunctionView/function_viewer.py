import grpc
from Generated import bin_diff_pb2, bin_diff_pb2_grpc

from binaryninja import show_message_box

from function_viewer_ui_components import FunctionTableDialog


def show_functions_table(bv, functions):
    try:
        sorted_functions = sorted(functions, key=lambda f: f['address'])

        dialog = FunctionTableDialog(bv, sorted_functions)
        dialog.show()

    except Exception as e:
        show_message_box("Display Error", f"Could not display functions table: {e}")


class FunctionViewer:
    def __init__(self, server_address):
        self.server_address = server_address

    def retrieve_and_display_functions(self, bv, file_id):
        try:
            functions = self._get_functions_from_server(file_id)

            if functions:
                show_functions_table(bv, functions)
            else:
                show_message_box("Fail", f"No functions found for file ID: {file_id}")

        except Exception as e:
            show_message_box("Error", f"Failed to retrieve functions: {e}")

    def _get_functions_from_server(self, file_id):
        try:
            channel = grpc.insecure_channel(self.server_address)
            stub = bin_diff_pb2_grpc.BinDiffServerStub(channel)

            request = bin_diff_pb2.GetRequest()
            request.id = file_id
            response = stub.Get(request, timeout=30)

            if response and response.functions:
                functions = []
                for func_info in response.functions:
                    functions.append({
                        'name': func_info.name,
                        'address': func_info.address
                    })

                return functions
            else:
                return []

        except grpc.RpcError as e:
            show_message_box("Error", f"gRPC get functions error: {e.code()} - {e.details()}")
            return []
        except Exception as e:
            show_message_box("Error", f"Get functions error: {e}")
            return []
        finally:
            try:
                channel.close()
            except:
                pass
