#include "cilium/svids.h"

#include <string>
#include <unordered_set>

#include "cilium/grpc_subscription.h"
#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Cilium {

uint64_t SVIDMap::instance_id_ = 0;

SVIDMap::SVIDMap(Server::Configuration::FactoryContext& context)
  : validation_visitor_(ProtobufMessage::getNullValidationVisitor()),
  transport_socket_factory_context_(
          context.getTransportSocketFactoryContext()) {
  instance_id_++;
  name_ = "cilium.svidmap." + fmt::format("{}", instance_id_) + ".";
  scope_ = context.scope().createScope(name_);

  ENVOY_LOG(debug, "SVIDMap({}) created.", name_);

  subscription_ =
      subscribe("type.googleapis.com/cilium.SVIDs", context.localInfo(),
                context.clusterManager(), context.dispatcher(),
                context.api().randomGenerator(), *scope_, *this, *this);
}

void SVIDMap::onConfigUpdate(
    const std::vector<Envoy::Config::DecodedResourceRef>& resources,
    const std::string& version_info) {
  ENVOY_LOG(debug,
            "SVIDMap::onConfigUpdate({}), {} resources, version: {}",
            name_, resources.size(), version_info);

  std::unordered_set<uint64_t> keeps;
  std::vector<uint64_t> to_be_deleted;

  // Add/Update entries
  for (const auto& resource : resources) {
    const auto& config = dynamic_cast<const cilium::SVIDs&>(
        resource.get().resource());
    ENVOY_LOG(debug,
              "Received SVIDs for policy {} in onConfigUpdate() "
              "version {}",
              config.identity(), version_info);
    // TODO(Mauricio): Handle multiple svids
    if (config.svids_size() > 0) {
      const auto& x509svid = config.svids(0);
      auto id = config.identity();

      keeps.insert(id);

      spiffeids_[id] = x509svid.spiffe_id();

      trusted_ca_[id] = x509svid.bundle();
      crt_[id] = x509svid.x509_svid();
      key_[id] = x509svid.x509_svid_key();
    }
    // TODO(Mauricio): delete entry if there are not svids?
  }

  // Delete entries
  for (const auto& pair : spiffeids_) {
    if (keeps.find(pair.first) == keeps.end()) {
      to_be_deleted.emplace_back(pair.first);
    }
  }

  for (const auto& id : to_be_deleted) {
      spiffeids_.erase(id);

      trusted_ca_.erase(id);
      crt_.erase(id);
      key_.erase(id);
  }
}

void SVIDMap::onConfigUpdateFailed(
    Envoy::Config::ConfigUpdateFailureReason, const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
}

}  // namespace Cilium
}  // namespace Envoy
