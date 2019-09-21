package = "kong-plugin-redis-auth"
version = "0.1.0"

source = {
  url = "git://github.com/jooonwood/kong-plugin-redis-auth",
  tag = "0.1.0"
}

supported_platforms = {"linux", "macosx"}
description = {
  summary = "use redis key auth in Kong",
  license = "MIT",
}

dependencies = {
  --"kong >= 0.13.0",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.redis-auth.handler"] = "kong/plugins/redis-auth/handler.lua",
    ["kong.plugins.redis-auth.schema"] = "kong/plugins/redis-auth/schema.lua",
  }
}
