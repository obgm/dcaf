#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>

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

parser::parser() {
  using namespace lug::language;
  using namespace std;

  lug::variable<std::string_view> id_{environment}, sv_{environment};
  lug::variable<parser::key_type> keytype_{environment};
  lug::variable<parser::method_t> method_{environment}, m_{environment};
  lug::variable<std::string_view> endpoint_{environment};

  lug::variable<std::set<std::string_view> > ep_{environment};

  using Wildcard = std::string_view;

  rule AMConfig;
    rule UnicodeEscape  = lexeme[ chr('u') > "[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]"_rx ];
    rule Escape         = lexeme[ "\\" > ("[/\\bfnrt]"_rx | UnicodeEscape) ];
    rule String         = lexeme[ "\"" > capture(sv_)[*(u8"[^\"\\\u0000-\u001F]"_rx | Escape)] > "\"" ] <[&]{ return *sv_; };
    rule Identifier     = lexeme[ capture(id_)["[a-z]"_irx > *("[0-9a-z_]"_irx) ] ] <[&]{ return *id_; };
    rule Hex            = lexeme[ capture(sv_)[+("[0-9a-f]"_irx "[0-9a-f]"_irx)] ] <[&]{ return *sv_; };
    rule Keytype        =  "psk"_isx > ((sv_%Hex      <[&]() {
        std::string key;
        int n = -1;
        /* sv_->size() is always even due to rule Hex */
        for (auto c : *sv_) {
          if (n >= 0) {
            key += (n + hex2char(c)) & 0xff;
            n = -1;
          } else {
            n = hex2char(c) << 4;
          }
        }
        *keytype_ = std::tuple{key_t::PSK, key};
        })
      | (sv_%String <[&]() { *keytype_ = std::tuple{key_t::PSK, std::string(*sv_)}; })
                                        ) <[&]() { return *keytype_; };
    rule KeyObject      = "key"_sx > sv_%String > ~"as"_sx > keytype_%Keytype
      <[&]{ keys[std::string(*sv_)] = *keytype_; };
    rule Configure      = "configure"_sx > KeyObject;
    rule Group          = "add"_sx > "key"_sx > sv_%String > "to"_sx > "group"_sx > id_%Identifier;
    rule Method         =
      ("GET"_isx      <[]() { return method_t::GET; })
      | ("POST"_isx   <[]() { return method_t::POST; })
      | ("PUT"_isx    <[]() { return method_t::PUT; })
      | ("DELETE"_isx <[]() { return method_t::DELETE; })
      | ("FETCH"_isx  <[]() { return method_t::FETCH; })
      | ("PATCH"_isx  <[]() { return method_t::PATCH; })
      | ("IPATCH"_isx <[]() { return method_t::IPATCH; });
    rule Methods        = (method_%Method 
                           >~(chr('|') > m_%Methods)) <[&](){ unsigned char m = static_cast<unsigned char>(*m_); return static_cast<method_t>(m | (1 << static_cast<unsigned char>(*method_))); };
    rule Command        = (chr('*') | Methods);
    rule Subject        = (chr('*') | String | Identifier);
    rule Endpoint       = ((chr('*') <[]() { return Wildcard();  })
                           | (sv_%String <[&sv_]() { return *sv_;  })
                           | (id_%Identifier <[&id_]() { return *id_;  }));
    rule Endpoints       = (endpoint_%Endpoint 
                            >(~(chr(',') > *(" "_sx) > ep_%Endpoints)))
      <[&ep_,&endpoint_](){ ep_->insert(*endpoint_); return *ep_; };
    rule Permission     = "allow"_sx > method_%Command > "from"_sx > Subject > "on"_sx > ep_%Endpoints <[&]() { std::cout << "With your permission, boss: " << static_cast<int>(*method_)
                                                                                                                      << " on endpoints";
      std::for_each(ep_->cbegin(), ep_->cend(), [](auto &e) { std::cout << " " << e; });
      std::cout << endl;
                                                                                                    };
    rule Statement      = (Configure | Group | Permission) > (eol | chr(';'));
    AMConfig            = *Statement;
    grammar = start(AMConfig);
}

bool parser::parse(std::istream& input) {
  if (input && lug::parse(input, grammar, environment)) {
    return true;
  }
  return false;
}

} /* namespace am_config */
