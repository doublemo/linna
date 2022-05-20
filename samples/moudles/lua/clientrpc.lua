local na = require("linna")
local du = require("debug_utils")


local function rpc(_context, payload)
    na.event("foo", {bar = "baz"}, 12345, false)
    print_r("test lua rpc", 1)
    return payload
end
na.register_rpc(rpc, "clientrpc.rpc")

local function rpc_error(_context, _payload)
    error("Some error occured.")
end
na.register_rpc(rpc_error, "clientrpc.rpc_error")

local function rpc_get(_context, _payload)
    local response = {
        message = "PONG"
    }
    return na.json_encode(response)
end
na.register_rpc(rpc_get, "clientrpc.rpc_get")