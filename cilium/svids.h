#pragma once

#include "cilium/api/svids.pb.h"
#include "cilium/api/svids.pb.validate.h"

#include "common/common/logger.h"
#include "common/network/utility.h"
#include "common/protobuf/message_validator_impl.h"
#include "envoy/config/subscription.h"
#include "envoy/event/dispatcher.h"
#include "envoy/local_info/local_info.h"
#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/upstream/cluster_manager.h"

#include "envoy/server/factory_context.h"

namespace Envoy {
namespace Cilium {

class SVIDMap : public Singleton::Instance,
                      public Config::SubscriptionCallbacks,
                      public Config::OpaqueResourceDecoder,
                      public std::enable_shared_from_this<SVIDMap>,
                      public Logger::Loggable<Logger::Id::config> {
 public:
  SVIDMap(Server::Configuration::FactoryContext& context);
  ~SVIDMap() {
    ENVOY_LOG(debug, "Cilium SVIDMap({}): SVIDMap is deleted NOW!",
              name_);
  }

  void startSubscription() { subscription_->start({}); }

  // Config::SubscriptionCallbacks
  void onConfigUpdate(
      const std::vector<Envoy::Config::DecodedResourceRef>& resources,
      const std::string& version_info) override;
  void onConfigUpdate(
      const std::vector<Envoy::Config::DecodedResourceRef>& added_resources,
      const Protobuf::RepeatedPtrField<std::string>& removed_resources,
      const std::string& system_version_info) override {
    // NOT IMPLEMENTED YET.
    UNREFERENCED_PARAMETER(added_resources);
    UNREFERENCED_PARAMETER(removed_resources);
    UNREFERENCED_PARAMETER(system_version_info);
  }
  void onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason,
                            const EnvoyException* e) override;

  // Config::OpaqueResourceDecoder
  ProtobufTypes::MessagePtr decodeResource(
      const ProtobufWkt::Any& resource) override {
  UNREFERENCED_PARAMETER(resource);
    auto typed_message = std::make_unique<cilium::SVIDs>();
    // If the Any is a synthetic empty message (e.g. because the resource field
    // was not set in Resource, this might be empty, so we shouldn't decode.
    if (!resource.type_url().empty()) {
      MessageUtil::anyConvertAndValidate<cilium::SVIDs>(
          resource, *typed_message, validation_visitor_);
    }
    return typed_message;
  }

  std::string resourceName(const Protobuf::Message& resource) override {
    return fmt::format(
        "{}",
        dynamic_cast<const cilium::SVIDs&>(resource).identity());
  }

  std::string getSpiffeID(uint64_t id) const {
    if (spiffeids_.count(id) == 0) {
      return std::string("");
    }

    return spiffeids_.at(id);
  }

  std::string getTrustedCA(uint64_t id) const {
    return trusted_ca_.at(id);
  }

  std::string getCrt(uint64_t id) const {
     return crt_.at(id);
  }

  std::string getKey(uint64_t id) const {
    return key_.at(id);
  }

  Server::Configuration::TransportSocketFactoryContext& getContext() const {
    return transport_socket_factory_context_;
  }

 private:
  ProtobufMessage::ValidationVisitor& validation_visitor_;
  Stats::ScopePtr scope_;
  std::unique_ptr<Envoy::Config::Subscription> subscription_;
  static uint64_t instance_id_;
  std::string name_;

  // TODO(Mauricio): spiffeids are not much relevant but they are nice to show
  // debug info
  // TODO(Mauricio): std::maps are used to implement the prototype. Probably
  // a thread local structure has to be used.
  std::map<uint64_t, std::string> spiffeids_;

  std::map<uint64_t, std::string> trusted_ca_;
  std::map<uint64_t, std::string> crt_;
  std::map<uint64_t, std::string> key_;

  Server::Configuration::TransportSocketFactoryContext&
      transport_socket_factory_context_;
};

}  // namespace Cilium
}  // namespace Envoy
