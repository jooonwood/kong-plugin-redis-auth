local helpers = require "spec.helpers"
local redis = require "resty.redis"
local version = require "version"


local PLUGIN_NAME = "redis-auth"
local REDIS_HOST = helpers.redis_host
local REDIS_PORT = 6379

local function redis_connect()
  local red = redis:new()
  red:set_timeout(2000)
  assert(red:connect(REDIS_HOST, REDIS_PORT))
  local red_version = string.match(red:info(), 'redis_version:([%g]+)\r\n')
  return red, assert(version(red_version))
end

local function add_redis_data(red)
  assert(red:sadd("redis-auth:services:needauth", "notpublic", 2))
  assert(red:zadd("redis-auth:sessions", 1, "apikey-needauth-1"))
  assert(red:zadd("redis-auth:sessions", 2, "apikey-needauth-2"))
  assert(red:set("redis-auth:users:1", '{ "id":1 ,"username":"user1"  }'))
  assert(red:set("redis-auth:users:1", '{ "id":2 ,"username":"user2"  }'))
end

for _, strategy in helpers.each_strategy() do
  describe(PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()
    local client
    local bp
    local red

    lazy_setup(function()

      bp = helpers.get_db_utils(strategy, nil, { PLUGIN_NAME })
      red = redis_connect()
      add_redis_data(red)
      -- Inject a test route. No need to create a service, there is a default
      -- service which will echo the request.
      -- add the plugin to test to the route we created
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = bp.routes:insert({
          hosts = { "test1.com" },
        }),
        config = {
          consumer_keys = { "id", "username" },
          redis_host = REDIS_HOST,
          anonymous = true,
          anonymous_consumer = '{ "id":2000, "username":"hello", "custom_id":1000 }',
          anonymous_paths = { "/delay/1", "/anything" }
        },
      }

      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = bp.routes:insert({
          hosts = { "needauth.com" },
          service   = bp.services:insert {
            name = "needauth",
          },
        }),
        config = {
          consumer_keys = { "id", "username" },
          redis_host = REDIS_HOST
        },
      }

      -- start kong
      assert(helpers.start_kong({
        -- set the strategy
        database   = strategy,
        -- use the custom test template to create a local mock server
        nginx_conf = "spec/fixtures/custom_nginx.template",
        -- make sure our plugin gets loaded
        plugins = "bundled," .. PLUGIN_NAME,
      }))
    end)

    lazy_teardown(function()
      if client then
        client:close()
      end
      if red then
        red:close()
      end
      helpers.stop_kong(nil, true)
    end)

    before_each(function()
      client = helpers.proxy_client()
    end)

    after_each(function()
      if client then client:close() end
    end)



    describe("request", function()
      it("request no apikey", function()
        local r = client:get("/request", {
          headers = {
            host = "test1.com"
          }
        })
        -- validate that the request succeeded, response status 200
        assert.response(r).has.status(401)
      end)
    end)

    describe("request", function()
      it("request unauthorized apikey", function()
        local r = client:get("/request", {
          headers = {
            host = "test1.com"
          },
          query = {
            apikey = "error"
          }
        })
        -- validate that the request succeeded, response status 200
        assert.response(r).has.status(401)
      end)
    end)
      
    describe("request", function()
      it("request public path /anything", function()
        local r = client:get("/anything", {
          headers = {
            host = "test1.com"
          }
        })
        -- validate that the request succeeded, response status 200
        assert.response(r).has.status(200)
      end)
    end)

    describe("request", function()
      it("request public path /delay/1", function()
        local r = client:get("/delay/1", {
          headers = {
            host = "test1.com"
          }
        })
        -- validate that the request succeeded, response status 200
        assert.response(r).has.status(200)
      end)
    end)

    describe("request", function()
      it("request unauthorized path /delay/10", function()
        local r = client:get("/delay/10", {
          headers = {
            host = "test1.com"
          }
        })
        -- validate that the request succeeded, response status 200
        assert.response(r).has.status(401)
      end)
    end)

    describe("request", function()
      it("gets a 'anonymous' header", function()
        local res = client:get("/anything", {
          headers = {
            host = "test1.com"
          }
        })
        local id = assert.request(res).has.header("x-consumer-id")
        assert.equal(id, "2000")
        local username = assert.request(res).has.header("x-consumer-username")
        assert.equal(username, "hello")
      end)
    end)

    describe("request", function()
      it("request needauth path 403", function()
        local r = client:get("/request", {
          headers = {
            host = "needauth.com"
          },
          query = {
            apikey = "apikey-needauth-1"
          }
        })
        -- validate that the request succeeded, response status 200
        assert.response(r).has.status(403)
      end)
    end)

    describe("request", function()
      it("request needauth path 200", function()
        local r = client:get("/request", {
          headers = {
            host = "needauth.com"
          },
          query = {
            apikey = "apikey-needauth-2"
          }
        })
        -- validate that the request succeeded, response status 200
        assert.response(r).has.status(200)
      end)
    end)

  end)
end
