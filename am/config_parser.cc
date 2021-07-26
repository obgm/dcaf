#include <algorithm>
#include <filesystem>
#include <map>
#include <set>
#include <stdexcept>
#include <vector>

#include "dcaf/dcaf.h"
#include "config_parser.hh"

static inline bool
odd(unsigned int n) {
  return (n & 1) != 0;
}

static inline char
hex2char(char c) {
  if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  else if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  else
    return c - '0';
}

namespace am_config {

std::string
getDefaultConfigFile(void) {
  char *home = getenv("HOME");
  std::filesystem::path root;
  std::error_code err;
  
  if (home) { /* check if $HOME/.amrc or $HOME/.local/dcaf/amrc exists */
    /* these are the paths under $HOME to search for the config file */
    static const char *local_searchpaths[] = { ".amrc", ".local/dcaf/amrc" };

    for (size_t idx=0; idx < sizeof(local_searchpaths)/sizeof(local_searchpaths[0]); idx++) {
      std::filesystem::path path{root/home/local_searchpaths[idx]};
      if (std::filesystem::exists(path, err)) {
        return path;
      }
    }
  }
  else if (std::filesystem::exists(root/"etc/amrc", err)) {
    return root/"etc/amrc";
  }
  return "";
}

/* explicitly define destructor to avoid inlining warning */
parser::~parser(void) {
}

/**
 * Adds key/value pairs from @p mapNode into the result map
 * @p result. Maps that are nested using the special key "<<" are
 * added recursively.
 *
 * @param[in]  mapNode The map to flatten.
 * @param[out] result  Where key/value pairs from @p mapNode are inserted.
 */
template <typename K, typename V, typename C, typename A>
static void flatten(const YAML::Node &mapNode, std::map<K, V, C, A> &result) {
  if (!mapNode.IsMap())
    return;

  for (const auto &entry : mapNode) {
    const auto &key = entry.first.as<K>();
    if (entry.second.IsScalar()) {
      result[key] = entry.second.as<V>();
      std::cout << key << ": " << result[key] << std::endl;
    }
    else if (key == "<<" && entry.second.IsMap()) {
      flatten(entry.second, result);
    }
  }
}

void
parser::readHosts(void) {
  if (auto host = (*config_root)["host"]) {

    if (host.IsMap()) {
      for (const auto &entry : host) {
        flatten(entry.second, hosts[entry.first.as<std::string>()]);
      }
    }
  }
}

template <typename F>
static int find_and_set(const std::map<std::string, std::string> &entry, const std::string &what, F &field) {
  const auto &elem{entry.find(what)};

  if (elem != entry.end()) {
    field = std::stoi(elem->second);
    return 1;
  }
  return 0;
}

void
parser::readEndpoints(void) {
  if (auto ep = (*config_root)["endpoints"]) {
    using Entry = std::map<std::string, std::string>;
    std::vector<Entry> interfaces;

    if (ep.IsMap()) { /* single entry */
      interfaces.push_back(Entry{});
      flatten(ep, interfaces.back());
    } else if (ep.IsSequence()) { /* list */
      for (const auto &entry : ep) {
        if (entry.IsMap()) {
          interfaces.push_back(Entry{});
          flatten(entry, interfaces.back());
        }
      }
    }

    /* prepare Endpoint objects from list of interfaces */
    for (const auto &iface : interfaces) {
      const auto &addr = iface.find("interface");
      if (addr == iface.end()) {
        continue;
      }

      Endpoint endpoint;
      bool have_port = false;
      endpoint.interface = addr->second;
      have_port += find_and_set(iface, "udp",  endpoint.ports[0]);
      have_port += find_and_set(iface, "dtls", endpoint.ports[1]);
      have_port += find_and_set(iface, "tcp",  endpoint.ports[2]);
      have_port += find_and_set(iface, "tls",  endpoint.ports[3]);

      /* set all entries to default values if no field has been set */
      if (have_port == 0) {
        endpoint.ports[0] = endpoint.ports[2] = DCAF_DEFAULT_COAP_PORT;
        endpoint.ports[1] = endpoint.ports[3] = DCAF_DEFAULT_COAPS_PORT;
      }

      endpoints.push_back(endpoint);
    }
  }
}

void
parser::readGroups(void) {
  if (auto groups= (*config_root)["groups"]) {

    if (groups.IsSequence()) {
      for (const auto &group : groups) {
        if (group.IsMap()) {
          auto name = group["name"];
          auto members = group["members"];
          if (name.IsDefined()) {
            std::cout << "Group: " << name.as<std::string>() << std::endl;
          }
          if (members.IsSequence()) {
            for (const auto &member : members) {
              if (member.IsScalar()) {
                // TODO: check if tagged with "!cert"
                std::cout << "Member: " << member.as<std::string>() << std::endl;
              } else if (member.IsMap()) {
                // TODO: get name, key
              }
            }
          }
        }
      }
    }
  }
}

static const char *methodNames[] = { "GET", "POST", "PUT", "DELETE", "FETCH", "PATCH", "IPATCH" };

static uint8_t
methodToInt(const std::string &s) {
  for (size_t idx = 0; idx < sizeof(methodNames)/sizeof(methodNames[0]); idx++) {
    if (s == methodNames[idx]) {
      return 1 << idx;
    }
  }
  return 0;
}

Rule::~Rule(void) {
}

void parser::readRules(void) {
  if (auto rules= (*config_root)["rules"]) {

    if (rules.IsSequence()) {
      for (const auto &rule : rules) {
        if (rule.IsMap()) {
          auto uri = rule["resource"];
          auto methods = rule["methods"];
          auto allow = rule["allow"];
          if (uri.IsDefined() && methods.IsDefined() && allow.IsDefined()) {
            Rule r{uri.as<std::string>()};
            uint32_t mtd = Rule::Method::GET;

            if (methods.IsScalar()) {
              mtd = methodToInt(methods.as<std::string>());
            }
            else if (methods.IsSequence()) {
              for (const auto &m : methods) {
                mtd |= methodToInt(m.as<std::string>());
              }
            }
            if (mtd) {
              r.methods = mtd;
              rulebase.insert({ r.resource, r });
            }
          }
        }
      }
    }
  }
}

struct Key {
  std::string name;
  std::unique_ptr<std::string> psk;
  std::unique_ptr<std::string> rpk;

  Key(const std::string &n) : name(n) {}
};

// FIXME: make convert::decode()
static std::unique_ptr<Key>
createKey(const YAML::Node &keyNode) {
  auto name = keyNode["name"];
  auto psk = keyNode["psk"];
  auto rpk = keyNode["rpk"];

  if (name.IsDefined()) {
    std::unique_ptr<Key> key = std::make_unique<Key>(name.as<std::string>());
    if (key) {
      if (psk.IsDefined()) {
        key->psk = std::make_unique<std::string>(psk.as<std::string>());
      }
      if (rpk.IsDefined()) {
        key->rpk = std::make_unique<std::string>(rpk.as<std::string>());
      }
    }
    return key;
  }
  return nullptr;
}

void
parser::readKeys(void) {
  if (!config_root)
    return;

  if (auto ks = (*config_root)["keystore"]) {

    if (ks.IsSequence()) {
      for (const auto &entry : ks) {
        auto key = createKey(entry);
        if (key) {
          std::cout << "Key: " << key->name;
          if (key->psk) {
            std::cout << " (PSK: " << *key->psk << ")";
          }
          if (key->rpk) {
            std::cout << " (RPK: " << *key->rpk << ")";
          }

          std::cout << std::endl;
          if (key->psk) {
            keys[key->name] = { key_t::PSK, *key->psk };
          }
          if (key->rpk) {
            keys[key->name] = { key_t::RPK, *key->rpk };
          }
        }
      }
    }
  }
}

bool parser::parse(std::istream& input) { (void)input; return false; }

bool parser::parseFile(const std::string &filename) {
  try {
    std::unique_ptr<YAML::Node> node = std::make_unique<YAML::Node>(YAML::LoadFile(filename));
    if (node) {
      config_root = std::move(node);
      readKeys();
      readEndpoints();
      readHosts();
      readGroups();
      readRules();
    }
  }
  catch (const YAML::BadFile& ex) {
    std::cerr << ex.what() << std::endl;
    return false;
  }
  catch (const YAML::ParserException& ex) {
    std::cerr << ex.what() << std::endl;
    return false;
  }
  return true;
}

} /* namespace am_config */
