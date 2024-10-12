// This file is generated by tools/codegen.sh
// DO NOT EDIT IT.

// clang-format off

//  To parse this JSON data, first install
//
//      json.hpp  https://github.com/nlohmann/json
//
//  Then include this file, and then do
//
//     BuilderProjectModules.hpp data = nlohmann::json::parse(jsonString);

#pragma once

#include <optional>
#include <nlohmann/json.hpp>
#include "linglong/api/types/v1/helper.hpp"

namespace linglong {
namespace api {
namespace types {
namespace v1 {
/**
* items of modules of builder project
*/

using nlohmann::json;

/**
* items of modules of builder project
*/
struct BuilderProjectModules {
/**
* module install files
*/
std::string files;
/**
* module name
*/
std::string name;
};
}
}
}
}

// clang-format on
