import grpc
from Generated import bin_diff_pb2, bin_diff_pb2_grpc

from binaryninja import show_message_box

from diff_viewer_ui_components import DiffResultDialog


def show_diff_result(primary_bv, secondary_bv, diff_result):
    try:
        dialog = DiffResultDialog(primary_bv, secondary_bv, diff_result)
        dialog.show()

    except Exception as e:
        show_message_box("Display Error", f"Could not display functions table: {e}")


class DiffViewer:
    def __init__(self, server_address):
        self.server_address = server_address

    def retrieve_and_display_diff_result(self, primary_bv, secondary_bv, primary_id, secondary_id):
        try:
            diff_result = self._get_diff_result_from_server(primary_id, secondary_id)

            if diff_result:
                show_diff_result(primary_bv, secondary_bv, diff_result)
            else:
                show_message_box("Fail", f"Could not generate diff for the files with id: "
                                         f"{primary_id} and {secondary_id}")

        except Exception as e:
            show_message_box("Error", f"Failed to retrieve diff: {e}")

    def _get_diff_result_from_server(self, primary_id, secondary_id):
        try:
            channel = grpc.insecure_channel(self.server_address)
            stub = bin_diff_pb2_grpc.BinDiffServerStub(channel)

            request = bin_diff_pb2.DiffRequest()
            request.id_1 = primary_id
            request.id_2 = secondary_id
            response = stub.Diff(request, timeout=50)

            if response and response.matches and response.unmatched_primary and response.unmatched_secondary:
                matches = []
                for match in response.matches:
                    matches.append({
                        'address_primary': match.address_primary,
                        'address_secondary': match.address_secondary,
                        'name_primary': match.name_primary,
                        'name_secondary': match.name_secondary,
                        'similarity': match.similarity,
                        'confidence': match.confidence
                    })

                unmatched_primary = []
                for func in response.unmatched_primary:
                    unmatched_primary.append({
                        'name': func.name,
                        'address': func.address
                    })

                unmatched_secondary = []
                for func in response.unmatched_secondary:
                    unmatched_secondary.append({
                        'name': func.name,
                        'address': func.address
                    })

                return [matches, unmatched_primary, unmatched_secondary]
            else:
                return []

        except grpc.RpcError as e:
            show_message_box("Error", f"gRPC diff files error: {e.code()} - {e.details()}")
            return []
        except Exception as e:
            show_message_box("Error", f"Diff files error: {e}")
            return []
        finally:
            try:
                channel.close()
            except:
                pass
