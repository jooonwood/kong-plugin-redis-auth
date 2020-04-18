local helpers = require "spec.helpers"
local cjson   = require "cjson"
local redis_host = helpers.redis_host
local redis_port = 6379


local PLUGIN_NAME = "redis-auth"


for _, strategy in helpers.each_strategy() do
  describe(PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()
    local client

    lazy_setup(function()

      local bp = helpers.get_db_utils(strategy, nil, { PLUGIN_NAME })

      -- Inject a test route. No need to create a service, there is a default
      -- service which will echo the request.
      local route1 = bp.routes:insert({
        hosts = { "test1.com" },
      })
      -- add the plugin to test to the route we created
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route1.id },
        config = {
          redis_host = redis_host,
          anonymous = true,
          anonymous_consumer = '{ "id":2000, "username":"hello", "custom_id":1000 }',
          anonymous_paths = { "/public", "/anything" }
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
      it("request public path", function()
        local r = client:get("/anything", {
          headers = {
            host = "test1.com"
          }
        })
        -- validate that the request succeeded, response status 200
        assert.response(r).has.status(200)
      end)
    end)

    describe("response", function()
      it("gets a 'anonymous' header", function()
        local res = client:get("/anything", {
          headers = {
            host = "test1.com"
          }
        })
        assert.request(res).has.header("x-consumer-id")
      end)
    end)

  end)
end
