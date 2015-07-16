carbon_proto = Proto("carbon", "Carbon (Graphite) plaintext protocol")

local pf_key    = ProtoField.string("carbon.key", "Key")
local pf_value  = ProtoField.float("carbon.value", "Value")
local pf_tstamp = ProtoField.float("carbon.epoch", "Epoch")

carbon_proto.fields = {pf_key, pf_value, pf_tstamp}

function carbon_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "CARBON"

    local data = buffer(0):string()
    local results = 0
    local subtree = tree:add(carbon_proto, buffer(), "Carbon Plaintext Data")
    for line in data:gmatch("[^\n]+") do
        local result = {}
        for match in line:gmatch("[^%s]+") do
            table.insert(result, match)
        end
        if #result == 3 then
            results = results + 1
            local leaf = subtree:add(pf_key, buffer(), result[1])
            leaf:set_text("Key: " .. result[1])
            leaf:add(pf_value, buffer(), result[2]):set_text("Value: " .. result[2])
            leaf:add(pf_tstamp, buffer(), result[3]):set_text("Epoch: " .. result[3])
        end
    end
    subtree:append_text(", Results: " .. results)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(2003, carbon_proto)
