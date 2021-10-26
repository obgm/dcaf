#ifndef _CONFIG_PARSER_HH
#define _CONFIG_PARSER_HH 1

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <set>
#include <vector>

#include <yaml-cpp/yaml.h>

namespace am_config {

std::string getDefaultConfigFile(void);

using Allowed = std::vector<std::string>;

struct Rule {
  enum Method : uint8_t { GET=0x01, POST=0x02, PUT=0x04, DELETE=0x08, FETCH=0x10, PATCH=0x20, IPATCH=0x40 };
  
  std::string resource;
  uint32_t methods;
  Allowed allowed;

  Rule(const std::string &r, uint32_t m = Method::GET) : resource(r), methods(m) {}
  ~Rule(void);
};

struct Endpoint {
  std::string interface;
  uint16_t ports[4] = {0, 0, 0, 0}; /* UDP, DTLS, TCP, TLS */
};

using Rules = std::multimap<std::string, Rule>;

class parser {
public:
  enum class key_t : unsigned char { PSK, RPK };
  typedef std::tuple<key_t, std::string> key_type;
  using KeyMap = std::map<std::string, key_type>;

  using HostConfig = std::map<std::string, std::string>;
  using Hosts = std::map<std::string, HostConfig>;
  using Endpoints = std::vector<Endpoint>;
  using Groups = std::map<std::string, std::set<std::string>>;
  
  ~parser(void);

  bool parse(std::istream& input);
  bool parseFile(const std::string &filename);

  bool have_config(void) const { return (bool)config_root; }
  KeyMap keys;
  Hosts hosts;
  Rules rulebase;
  Endpoints endpoints;
  Groups groups;
protected:
  std::unique_ptr<YAML::Node> config_root;

  void readKeys(void);
  void readEndpoints(void);
  void readHosts(void);
  void readGroups(void);
  void readRules(void);
};

} /* namespace am_config */

#endif /* _CONFIG_PARSER_HH */
