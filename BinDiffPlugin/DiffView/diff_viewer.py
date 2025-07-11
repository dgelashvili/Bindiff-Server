import grpc
from Generated import bin_diff_pb2, bin_diff_pb2_grpc

from binaryninja import show_message_box


def show_diff_result(primary_bv, secondary_bv, diff_result):
    show_message_box("Result", f"{len(diff_result)}")


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
            response = stub.Diff(request, timeout=30)

            if response and response.matches:
                matches = []
                for match in response.matches:
                    matches.append({
                        'name_primary': match.name_primary,
                        'name_secondary': match.name_secondary,
                        'similarity': match.similarity,
                        'confidence': match.confidence
                    })

                return matches
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
