#include "cilium/bundles.h"

#include <string>
#include <unordered_set>

#include "cilium/grpc_subscription.h"
#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Cilium {

uint64_t BundlesMap::instance_id_ = 0;

BundlesMap::BundlesMap(Server::Configuration::FactoryContext& context)
  : validation_visitor_(ProtobufMessage::getNullValidationVisitor()),
  transport_socket_factory_context_(
          context.getTransportSocketFactoryContext()) {
  instance_id_++;
  name_ = "cilium.bundlesmap." + fmt::format("{}", instance_id_) + ".";
  scope_ = context.scope().createScope(name_);

  ENVOY_LOG(debug, "BundlesMap({}) created.", name_);

  subscription_ =
      subscribe("type.googleapis.com/cilium.Bundles", context.localInfo(),
                context.clusterManager(), context.dispatcher(),
                context.api().randomGenerator(), *scope_, *this, *this);
}

void BundlesMap::onConfigUpdate(
    const std::vector<Envoy::Config::DecodedResourceRef>& resources,
    const std::string& version_info) {
  ENVOY_LOG(debug,
            "BundlesMap::onConfigUpdate({}), {} resources, version: {}",
            name_, resources.size(), version_info);

  std::unordered_set<std::string> keeps;
  std::vector<std::string> to_be_deleted;

  // Add/Update entries
  for (const auto& resource : resources) {
    const auto& config = dynamic_cast<const cilium::Bundles&>(
        resource.get().resource());
    ENVOY_LOG(debug,
              "Received Bundle for trust domain {} in onConfigUpdate() "
              "version {}",
              config.trust_domain_name(), version_info);

    auto trust_domain_name = config.trust_domain_name();

    keeps.insert(trust_domain_name);


    bundles_[trust_domain_name] = config.bundle();
  }

  // Delete entries
  for (const auto& pair : bundles_) {
    if (keeps.find(pair.first) == keeps.end()) {
      to_be_deleted.emplace_back(pair.first);
    }
  }

  for (const auto& id : to_be_deleted) {
      bundles_.erase(id);
  }
}

void BundlesMap::onConfigUpdateFailed(
    Envoy::Config::ConfigUpdateFailureReason, const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
}

}  // namespace Cilium
}  // namespace Envoy
