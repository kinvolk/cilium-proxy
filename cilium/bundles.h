#pragma once

#include "cilium/api/bundles.pb.h"
#include "cilium/api/bundles.pb.validate.h"

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

class BundlesMap : public Singleton::Instance,
                      public Config::SubscriptionCallbacks,
                      public Config::OpaqueResourceDecoder,
                      public std::enable_shared_from_this<BundlesMap>,
                      public Logger::Loggable<Logger::Id::config> {
 public:
  BundlesMap(Server::Configuration::FactoryContext& context);
  ~BundlesMap() {
    ENVOY_LOG(debug, "Cilium BundlesMap({}): BundlesMap is deleted NOW!",
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
    auto typed_message = std::make_unique<cilium::Bundles>();
    // If the Any is a synthetic empty message (e.g. because the resource field
    // was not set in Resource, this might be empty, so we shouldn't decode.
    if (!resource.type_url().empty()) {
      MessageUtil::anyConvertAndValidate<cilium::Bundles>(
          resource, *typed_message, validation_visitor_);
    }
    return typed_message;
  }

  std::string resourceName(const Protobuf::Message& resource) override {
    return fmt::format(
        "{}",
        dynamic_cast<const cilium::Bundles&>(resource).trust_domain_name());
  }

  std::string getBundles(const std::string &trust_domain_name) const {
    // TODO(Mauricio): What to return when bundle is not found?
    if (bundles_.count(trust_domain_name) == 0) {
      return std::string("");
    }

    return bundles_.at(trust_domain_name);
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

  // TODO(Mauricio): std::maps are used to implement the prototype. Probably
  // a thread local structure has to be used.
  std::map<std::string, std::string> bundles_;

  Server::Configuration::TransportSocketFactoryContext&
      transport_socket_factory_context_;
};

}  // namespace Cilium
}  // namespace Envoy
