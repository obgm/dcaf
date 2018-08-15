#ifndef _CONFIG_PARSER_HH
#define _CONFIG_PARSER_HH 1

#include <iostream>
#include <map>

#include <lug/lug.hpp>

namespace am_config {
class parser {
public:
  enum class key_t : unsigned char { PSK, RPK };
  enum class method_t : unsigned char { GET,  POST, PUT, DELETE, FETCH, PATCH, IPATCH };
  typedef std::tuple<key_t, std::string> key_type;
  using KeyMap = std::map<std::string, key_type>;

  parser();

  bool parse(std::istream& input);

  KeyMap keys;
private:
  lug::grammar grammar;
  lug::environment environment;
};

} /* namespace am_config */

#endif /* _CONFIG_PARSER_HH */
