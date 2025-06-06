// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: bin_diff.proto
#ifndef GRPC_bin_5fdiff_2eproto__INCLUDED
#define GRPC_bin_5fdiff_2eproto__INCLUDED

#include "bin_diff.pb.h"

#include <functional>
#include <grpcpp/generic/async_generic_service.h>
#include <grpcpp/support/async_stream.h>
#include <grpcpp/support/async_unary_call.h>
#include <grpcpp/support/client_callback.h>
#include <grpcpp/client_context.h>
#include <grpcpp/completion_queue.h>
#include <grpcpp/support/message_allocator.h>
#include <grpcpp/support/method_handler.h>
#include <grpcpp/impl/proto_utils.h>
#include <grpcpp/impl/rpc_method.h>
#include <grpcpp/support/server_callback.h>
#include <grpcpp/impl/server_callback_handlers.h>
#include <grpcpp/server_context.h>
#include <grpcpp/impl/service_type.h>
#include <grpcpp/support/status.h>
#include <grpcpp/support/stub_options.h>
#include <grpcpp/support/sync_stream.h>
#include <grpcpp/ports_def.inc>

namespace bin_diff {

class BinDiffServer final {
 public:
  static constexpr char const* service_full_name() {
    return "bin_diff.BinDiffServer";
  }
  class StubInterface {
   public:
    virtual ~StubInterface() {}
    virtual ::grpc::Status Upload(::grpc::ClientContext* context, const ::bin_diff::UploadRequest& request, ::bin_diff::UploadReply* response) = 0;
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::UploadReply>> AsyncUpload(::grpc::ClientContext* context, const ::bin_diff::UploadRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::UploadReply>>(AsyncUploadRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::UploadReply>> PrepareAsyncUpload(::grpc::ClientContext* context, const ::bin_diff::UploadRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::UploadReply>>(PrepareAsyncUploadRaw(context, request, cq));
    }
    virtual ::grpc::Status Diff(::grpc::ClientContext* context, const ::bin_diff::DiffRequest& request, ::bin_diff::DiffReply* response) = 0;
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::DiffReply>> AsyncDiff(::grpc::ClientContext* context, const ::bin_diff::DiffRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::DiffReply>>(AsyncDiffRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::DiffReply>> PrepareAsyncDiff(::grpc::ClientContext* context, const ::bin_diff::DiffRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::DiffReply>>(PrepareAsyncDiffRaw(context, request, cq));
    }
    virtual ::grpc::Status Get(::grpc::ClientContext* context, const ::bin_diff::GetRequest& request, ::bin_diff::GetReply* response) = 0;
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::GetReply>> AsyncGet(::grpc::ClientContext* context, const ::bin_diff::GetRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::GetReply>>(AsyncGetRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::GetReply>> PrepareAsyncGet(::grpc::ClientContext* context, const ::bin_diff::GetRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::GetReply>>(PrepareAsyncGetRaw(context, request, cq));
    }
    class async_interface {
     public:
      virtual ~async_interface() {}
      virtual void Upload(::grpc::ClientContext* context, const ::bin_diff::UploadRequest* request, ::bin_diff::UploadReply* response, std::function<void(::grpc::Status)>) = 0;
      virtual void Upload(::grpc::ClientContext* context, const ::bin_diff::UploadRequest* request, ::bin_diff::UploadReply* response, ::grpc::ClientUnaryReactor* reactor) = 0;
      virtual void Diff(::grpc::ClientContext* context, const ::bin_diff::DiffRequest* request, ::bin_diff::DiffReply* response, std::function<void(::grpc::Status)>) = 0;
      virtual void Diff(::grpc::ClientContext* context, const ::bin_diff::DiffRequest* request, ::bin_diff::DiffReply* response, ::grpc::ClientUnaryReactor* reactor) = 0;
      virtual void Get(::grpc::ClientContext* context, const ::bin_diff::GetRequest* request, ::bin_diff::GetReply* response, std::function<void(::grpc::Status)>) = 0;
      virtual void Get(::grpc::ClientContext* context, const ::bin_diff::GetRequest* request, ::bin_diff::GetReply* response, ::grpc::ClientUnaryReactor* reactor) = 0;
    };
    typedef class async_interface experimental_async_interface;
    virtual class async_interface* async() { return nullptr; }
    class async_interface* experimental_async() { return async(); }
   private:
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::UploadReply>* AsyncUploadRaw(::grpc::ClientContext* context, const ::bin_diff::UploadRequest& request, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::UploadReply>* PrepareAsyncUploadRaw(::grpc::ClientContext* context, const ::bin_diff::UploadRequest& request, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::DiffReply>* AsyncDiffRaw(::grpc::ClientContext* context, const ::bin_diff::DiffRequest& request, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::DiffReply>* PrepareAsyncDiffRaw(::grpc::ClientContext* context, const ::bin_diff::DiffRequest& request, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::GetReply>* AsyncGetRaw(::grpc::ClientContext* context, const ::bin_diff::GetRequest& request, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::bin_diff::GetReply>* PrepareAsyncGetRaw(::grpc::ClientContext* context, const ::bin_diff::GetRequest& request, ::grpc::CompletionQueue* cq) = 0;
  };
  class Stub final : public StubInterface {
   public:
    Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options = ::grpc::StubOptions());
    ::grpc::Status Upload(::grpc::ClientContext* context, const ::bin_diff::UploadRequest& request, ::bin_diff::UploadReply* response) override;
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::UploadReply>> AsyncUpload(::grpc::ClientContext* context, const ::bin_diff::UploadRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::UploadReply>>(AsyncUploadRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::UploadReply>> PrepareAsyncUpload(::grpc::ClientContext* context, const ::bin_diff::UploadRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::UploadReply>>(PrepareAsyncUploadRaw(context, request, cq));
    }
    ::grpc::Status Diff(::grpc::ClientContext* context, const ::bin_diff::DiffRequest& request, ::bin_diff::DiffReply* response) override;
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::DiffReply>> AsyncDiff(::grpc::ClientContext* context, const ::bin_diff::DiffRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::DiffReply>>(AsyncDiffRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::DiffReply>> PrepareAsyncDiff(::grpc::ClientContext* context, const ::bin_diff::DiffRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::DiffReply>>(PrepareAsyncDiffRaw(context, request, cq));
    }
    ::grpc::Status Get(::grpc::ClientContext* context, const ::bin_diff::GetRequest& request, ::bin_diff::GetReply* response) override;
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::GetReply>> AsyncGet(::grpc::ClientContext* context, const ::bin_diff::GetRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::GetReply>>(AsyncGetRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::GetReply>> PrepareAsyncGet(::grpc::ClientContext* context, const ::bin_diff::GetRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::bin_diff::GetReply>>(PrepareAsyncGetRaw(context, request, cq));
    }
    class async final :
      public StubInterface::async_interface {
     public:
      void Upload(::grpc::ClientContext* context, const ::bin_diff::UploadRequest* request, ::bin_diff::UploadReply* response, std::function<void(::grpc::Status)>) override;
      void Upload(::grpc::ClientContext* context, const ::bin_diff::UploadRequest* request, ::bin_diff::UploadReply* response, ::grpc::ClientUnaryReactor* reactor) override;
      void Diff(::grpc::ClientContext* context, const ::bin_diff::DiffRequest* request, ::bin_diff::DiffReply* response, std::function<void(::grpc::Status)>) override;
      void Diff(::grpc::ClientContext* context, const ::bin_diff::DiffRequest* request, ::bin_diff::DiffReply* response, ::grpc::ClientUnaryReactor* reactor) override;
      void Get(::grpc::ClientContext* context, const ::bin_diff::GetRequest* request, ::bin_diff::GetReply* response, std::function<void(::grpc::Status)>) override;
      void Get(::grpc::ClientContext* context, const ::bin_diff::GetRequest* request, ::bin_diff::GetReply* response, ::grpc::ClientUnaryReactor* reactor) override;
     private:
      friend class Stub;
      explicit async(Stub* stub): stub_(stub) { }
      Stub* stub() { return stub_; }
      Stub* stub_;
    };
    class async* async() override { return &async_stub_; }

   private:
    std::shared_ptr< ::grpc::ChannelInterface> channel_;
    class async async_stub_{this};
    ::grpc::ClientAsyncResponseReader< ::bin_diff::UploadReply>* AsyncUploadRaw(::grpc::ClientContext* context, const ::bin_diff::UploadRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReader< ::bin_diff::UploadReply>* PrepareAsyncUploadRaw(::grpc::ClientContext* context, const ::bin_diff::UploadRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReader< ::bin_diff::DiffReply>* AsyncDiffRaw(::grpc::ClientContext* context, const ::bin_diff::DiffRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReader< ::bin_diff::DiffReply>* PrepareAsyncDiffRaw(::grpc::ClientContext* context, const ::bin_diff::DiffRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReader< ::bin_diff::GetReply>* AsyncGetRaw(::grpc::ClientContext* context, const ::bin_diff::GetRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReader< ::bin_diff::GetReply>* PrepareAsyncGetRaw(::grpc::ClientContext* context, const ::bin_diff::GetRequest& request, ::grpc::CompletionQueue* cq) override;
    const ::grpc::internal::RpcMethod rpcmethod_Upload_;
    const ::grpc::internal::RpcMethod rpcmethod_Diff_;
    const ::grpc::internal::RpcMethod rpcmethod_Get_;
  };
  static std::unique_ptr<Stub> NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options = ::grpc::StubOptions());

  class Service : public ::grpc::Service {
   public:
    Service();
    virtual ~Service();
    virtual ::grpc::Status Upload(::grpc::ServerContext* context, const ::bin_diff::UploadRequest* request, ::bin_diff::UploadReply* response);
    virtual ::grpc::Status Diff(::grpc::ServerContext* context, const ::bin_diff::DiffRequest* request, ::bin_diff::DiffReply* response);
    virtual ::grpc::Status Get(::grpc::ServerContext* context, const ::bin_diff::GetRequest* request, ::bin_diff::GetReply* response);
  };
  template <class BaseClass>
  class WithAsyncMethod_Upload : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithAsyncMethod_Upload() {
      ::grpc::Service::MarkMethodAsync(0);
    }
    ~WithAsyncMethod_Upload() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Upload(::grpc::ServerContext* /*context*/, const ::bin_diff::UploadRequest* /*request*/, ::bin_diff::UploadReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestUpload(::grpc::ServerContext* context, ::bin_diff::UploadRequest* request, ::grpc::ServerAsyncResponseWriter< ::bin_diff::UploadReply>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(0, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithAsyncMethod_Diff : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithAsyncMethod_Diff() {
      ::grpc::Service::MarkMethodAsync(1);
    }
    ~WithAsyncMethod_Diff() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Diff(::grpc::ServerContext* /*context*/, const ::bin_diff::DiffRequest* /*request*/, ::bin_diff::DiffReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestDiff(::grpc::ServerContext* context, ::bin_diff::DiffRequest* request, ::grpc::ServerAsyncResponseWriter< ::bin_diff::DiffReply>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(1, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithAsyncMethod_Get : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithAsyncMethod_Get() {
      ::grpc::Service::MarkMethodAsync(2);
    }
    ~WithAsyncMethod_Get() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Get(::grpc::ServerContext* /*context*/, const ::bin_diff::GetRequest* /*request*/, ::bin_diff::GetReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestGet(::grpc::ServerContext* context, ::bin_diff::GetRequest* request, ::grpc::ServerAsyncResponseWriter< ::bin_diff::GetReply>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(2, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  typedef WithAsyncMethod_Upload<WithAsyncMethod_Diff<WithAsyncMethod_Get<Service > > > AsyncService;
  template <class BaseClass>
  class WithCallbackMethod_Upload : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithCallbackMethod_Upload() {
      ::grpc::Service::MarkMethodCallback(0,
          new ::grpc::internal::CallbackUnaryHandler< ::bin_diff::UploadRequest, ::bin_diff::UploadReply>(
            [this](
                   ::grpc::CallbackServerContext* context, const ::bin_diff::UploadRequest* request, ::bin_diff::UploadReply* response) { return this->Upload(context, request, response); }));}
    void SetMessageAllocatorFor_Upload(
        ::grpc::MessageAllocator< ::bin_diff::UploadRequest, ::bin_diff::UploadReply>* allocator) {
      ::grpc::internal::MethodHandler* const handler = ::grpc::Service::GetHandler(0);
      static_cast<::grpc::internal::CallbackUnaryHandler< ::bin_diff::UploadRequest, ::bin_diff::UploadReply>*>(handler)
              ->SetMessageAllocator(allocator);
    }
    ~WithCallbackMethod_Upload() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Upload(::grpc::ServerContext* /*context*/, const ::bin_diff::UploadRequest* /*request*/, ::bin_diff::UploadReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerUnaryReactor* Upload(
      ::grpc::CallbackServerContext* /*context*/, const ::bin_diff::UploadRequest* /*request*/, ::bin_diff::UploadReply* /*response*/)  { return nullptr; }
  };
  template <class BaseClass>
  class WithCallbackMethod_Diff : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithCallbackMethod_Diff() {
      ::grpc::Service::MarkMethodCallback(1,
          new ::grpc::internal::CallbackUnaryHandler< ::bin_diff::DiffRequest, ::bin_diff::DiffReply>(
            [this](
                   ::grpc::CallbackServerContext* context, const ::bin_diff::DiffRequest* request, ::bin_diff::DiffReply* response) { return this->Diff(context, request, response); }));}
    void SetMessageAllocatorFor_Diff(
        ::grpc::MessageAllocator< ::bin_diff::DiffRequest, ::bin_diff::DiffReply>* allocator) {
      ::grpc::internal::MethodHandler* const handler = ::grpc::Service::GetHandler(1);
      static_cast<::grpc::internal::CallbackUnaryHandler< ::bin_diff::DiffRequest, ::bin_diff::DiffReply>*>(handler)
              ->SetMessageAllocator(allocator);
    }
    ~WithCallbackMethod_Diff() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Diff(::grpc::ServerContext* /*context*/, const ::bin_diff::DiffRequest* /*request*/, ::bin_diff::DiffReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerUnaryReactor* Diff(
      ::grpc::CallbackServerContext* /*context*/, const ::bin_diff::DiffRequest* /*request*/, ::bin_diff::DiffReply* /*response*/)  { return nullptr; }
  };
  template <class BaseClass>
  class WithCallbackMethod_Get : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithCallbackMethod_Get() {
      ::grpc::Service::MarkMethodCallback(2,
          new ::grpc::internal::CallbackUnaryHandler< ::bin_diff::GetRequest, ::bin_diff::GetReply>(
            [this](
                   ::grpc::CallbackServerContext* context, const ::bin_diff::GetRequest* request, ::bin_diff::GetReply* response) { return this->Get(context, request, response); }));}
    void SetMessageAllocatorFor_Get(
        ::grpc::MessageAllocator< ::bin_diff::GetRequest, ::bin_diff::GetReply>* allocator) {
      ::grpc::internal::MethodHandler* const handler = ::grpc::Service::GetHandler(2);
      static_cast<::grpc::internal::CallbackUnaryHandler< ::bin_diff::GetRequest, ::bin_diff::GetReply>*>(handler)
              ->SetMessageAllocator(allocator);
    }
    ~WithCallbackMethod_Get() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Get(::grpc::ServerContext* /*context*/, const ::bin_diff::GetRequest* /*request*/, ::bin_diff::GetReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerUnaryReactor* Get(
      ::grpc::CallbackServerContext* /*context*/, const ::bin_diff::GetRequest* /*request*/, ::bin_diff::GetReply* /*response*/)  { return nullptr; }
  };
  typedef WithCallbackMethod_Upload<WithCallbackMethod_Diff<WithCallbackMethod_Get<Service > > > CallbackService;
  typedef CallbackService ExperimentalCallbackService;
  template <class BaseClass>
  class WithGenericMethod_Upload : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithGenericMethod_Upload() {
      ::grpc::Service::MarkMethodGeneric(0);
    }
    ~WithGenericMethod_Upload() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Upload(::grpc::ServerContext* /*context*/, const ::bin_diff::UploadRequest* /*request*/, ::bin_diff::UploadReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
  };
  template <class BaseClass>
  class WithGenericMethod_Diff : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithGenericMethod_Diff() {
      ::grpc::Service::MarkMethodGeneric(1);
    }
    ~WithGenericMethod_Diff() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Diff(::grpc::ServerContext* /*context*/, const ::bin_diff::DiffRequest* /*request*/, ::bin_diff::DiffReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
  };
  template <class BaseClass>
  class WithGenericMethod_Get : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithGenericMethod_Get() {
      ::grpc::Service::MarkMethodGeneric(2);
    }
    ~WithGenericMethod_Get() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Get(::grpc::ServerContext* /*context*/, const ::bin_diff::GetRequest* /*request*/, ::bin_diff::GetReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
  };
  template <class BaseClass>
  class WithRawMethod_Upload : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawMethod_Upload() {
      ::grpc::Service::MarkMethodRaw(0);
    }
    ~WithRawMethod_Upload() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Upload(::grpc::ServerContext* /*context*/, const ::bin_diff::UploadRequest* /*request*/, ::bin_diff::UploadReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestUpload(::grpc::ServerContext* context, ::grpc::ByteBuffer* request, ::grpc::ServerAsyncResponseWriter< ::grpc::ByteBuffer>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(0, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithRawMethod_Diff : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawMethod_Diff() {
      ::grpc::Service::MarkMethodRaw(1);
    }
    ~WithRawMethod_Diff() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Diff(::grpc::ServerContext* /*context*/, const ::bin_diff::DiffRequest* /*request*/, ::bin_diff::DiffReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestDiff(::grpc::ServerContext* context, ::grpc::ByteBuffer* request, ::grpc::ServerAsyncResponseWriter< ::grpc::ByteBuffer>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(1, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithRawMethod_Get : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawMethod_Get() {
      ::grpc::Service::MarkMethodRaw(2);
    }
    ~WithRawMethod_Get() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Get(::grpc::ServerContext* /*context*/, const ::bin_diff::GetRequest* /*request*/, ::bin_diff::GetReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestGet(::grpc::ServerContext* context, ::grpc::ByteBuffer* request, ::grpc::ServerAsyncResponseWriter< ::grpc::ByteBuffer>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(2, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithRawCallbackMethod_Upload : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawCallbackMethod_Upload() {
      ::grpc::Service::MarkMethodRawCallback(0,
          new ::grpc::internal::CallbackUnaryHandler< ::grpc::ByteBuffer, ::grpc::ByteBuffer>(
            [this](
                   ::grpc::CallbackServerContext* context, const ::grpc::ByteBuffer* request, ::grpc::ByteBuffer* response) { return this->Upload(context, request, response); }));
    }
    ~WithRawCallbackMethod_Upload() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Upload(::grpc::ServerContext* /*context*/, const ::bin_diff::UploadRequest* /*request*/, ::bin_diff::UploadReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerUnaryReactor* Upload(
      ::grpc::CallbackServerContext* /*context*/, const ::grpc::ByteBuffer* /*request*/, ::grpc::ByteBuffer* /*response*/)  { return nullptr; }
  };
  template <class BaseClass>
  class WithRawCallbackMethod_Diff : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawCallbackMethod_Diff() {
      ::grpc::Service::MarkMethodRawCallback(1,
          new ::grpc::internal::CallbackUnaryHandler< ::grpc::ByteBuffer, ::grpc::ByteBuffer>(
            [this](
                   ::grpc::CallbackServerContext* context, const ::grpc::ByteBuffer* request, ::grpc::ByteBuffer* response) { return this->Diff(context, request, response); }));
    }
    ~WithRawCallbackMethod_Diff() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Diff(::grpc::ServerContext* /*context*/, const ::bin_diff::DiffRequest* /*request*/, ::bin_diff::DiffReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerUnaryReactor* Diff(
      ::grpc::CallbackServerContext* /*context*/, const ::grpc::ByteBuffer* /*request*/, ::grpc::ByteBuffer* /*response*/)  { return nullptr; }
  };
  template <class BaseClass>
  class WithRawCallbackMethod_Get : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawCallbackMethod_Get() {
      ::grpc::Service::MarkMethodRawCallback(2,
          new ::grpc::internal::CallbackUnaryHandler< ::grpc::ByteBuffer, ::grpc::ByteBuffer>(
            [this](
                   ::grpc::CallbackServerContext* context, const ::grpc::ByteBuffer* request, ::grpc::ByteBuffer* response) { return this->Get(context, request, response); }));
    }
    ~WithRawCallbackMethod_Get() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Get(::grpc::ServerContext* /*context*/, const ::bin_diff::GetRequest* /*request*/, ::bin_diff::GetReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerUnaryReactor* Get(
      ::grpc::CallbackServerContext* /*context*/, const ::grpc::ByteBuffer* /*request*/, ::grpc::ByteBuffer* /*response*/)  { return nullptr; }
  };
  template <class BaseClass>
  class WithStreamedUnaryMethod_Upload : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithStreamedUnaryMethod_Upload() {
      ::grpc::Service::MarkMethodStreamed(0,
        new ::grpc::internal::StreamedUnaryHandler<
          ::bin_diff::UploadRequest, ::bin_diff::UploadReply>(
            [this](::grpc::ServerContext* context,
                   ::grpc::ServerUnaryStreamer<
                     ::bin_diff::UploadRequest, ::bin_diff::UploadReply>* streamer) {
                       return this->StreamedUpload(context,
                         streamer);
                  }));
    }
    ~WithStreamedUnaryMethod_Upload() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable regular version of this method
    ::grpc::Status Upload(::grpc::ServerContext* /*context*/, const ::bin_diff::UploadRequest* /*request*/, ::bin_diff::UploadReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    // replace default version of method with streamed unary
    virtual ::grpc::Status StreamedUpload(::grpc::ServerContext* context, ::grpc::ServerUnaryStreamer< ::bin_diff::UploadRequest,::bin_diff::UploadReply>* server_unary_streamer) = 0;
  };
  template <class BaseClass>
  class WithStreamedUnaryMethod_Diff : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithStreamedUnaryMethod_Diff() {
      ::grpc::Service::MarkMethodStreamed(1,
        new ::grpc::internal::StreamedUnaryHandler<
          ::bin_diff::DiffRequest, ::bin_diff::DiffReply>(
            [this](::grpc::ServerContext* context,
                   ::grpc::ServerUnaryStreamer<
                     ::bin_diff::DiffRequest, ::bin_diff::DiffReply>* streamer) {
                       return this->StreamedDiff(context,
                         streamer);
                  }));
    }
    ~WithStreamedUnaryMethod_Diff() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable regular version of this method
    ::grpc::Status Diff(::grpc::ServerContext* /*context*/, const ::bin_diff::DiffRequest* /*request*/, ::bin_diff::DiffReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    // replace default version of method with streamed unary
    virtual ::grpc::Status StreamedDiff(::grpc::ServerContext* context, ::grpc::ServerUnaryStreamer< ::bin_diff::DiffRequest,::bin_diff::DiffReply>* server_unary_streamer) = 0;
  };
  template <class BaseClass>
  class WithStreamedUnaryMethod_Get : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithStreamedUnaryMethod_Get() {
      ::grpc::Service::MarkMethodStreamed(2,
        new ::grpc::internal::StreamedUnaryHandler<
          ::bin_diff::GetRequest, ::bin_diff::GetReply>(
            [this](::grpc::ServerContext* context,
                   ::grpc::ServerUnaryStreamer<
                     ::bin_diff::GetRequest, ::bin_diff::GetReply>* streamer) {
                       return this->StreamedGet(context,
                         streamer);
                  }));
    }
    ~WithStreamedUnaryMethod_Get() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable regular version of this method
    ::grpc::Status Get(::grpc::ServerContext* /*context*/, const ::bin_diff::GetRequest* /*request*/, ::bin_diff::GetReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    // replace default version of method with streamed unary
    virtual ::grpc::Status StreamedGet(::grpc::ServerContext* context, ::grpc::ServerUnaryStreamer< ::bin_diff::GetRequest,::bin_diff::GetReply>* server_unary_streamer) = 0;
  };
  typedef WithStreamedUnaryMethod_Upload<WithStreamedUnaryMethod_Diff<WithStreamedUnaryMethod_Get<Service > > > StreamedUnaryService;
  typedef Service SplitStreamedService;
  typedef WithStreamedUnaryMethod_Upload<WithStreamedUnaryMethod_Diff<WithStreamedUnaryMethod_Get<Service > > > StreamedService;
};

}  // namespace bin_diff


#include <grpcpp/ports_undef.inc>
#endif  // GRPC_bin_5fdiff_2eproto__INCLUDED
