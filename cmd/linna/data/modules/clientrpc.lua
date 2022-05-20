local na = require("linna")
local du = require("debug_utils")


local function rpc(context, payload)
    na.event("foo", {bar = "baz"}, 12345, false)
    print("texxt --- env:\n" .. du.print_r(context.env))
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