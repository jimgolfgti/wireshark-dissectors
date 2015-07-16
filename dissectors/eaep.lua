eaep_proto = Proto("eaep", "EAEP protocol")

local pf_ver    = ProtoField.string("eaep.ver", "Version")
local pf_host   = ProtoField.string("eaep.host", "Host")
local pf_app    = ProtoField.string("eaep.app", "Application")
local pf_event  = ProtoField.string("eaep.event", "Event")
local pf_key    = ProtoField.string("eaep.key", "Key")
local pf_value  = ProtoField.string("eaep.value", "Value")

eaep_proto.fields = {pf_ver, pf_host, pf_app, pf_event, pf_key, pf_value}

function eaep_proto.dissector(buffer, pinfo, tree)
	if buffer:len() == 0 then return end
	if buffer(0, 4):string() ~= "EAEP" then return end

    local data = buffer(0):string()
    local lines = {}
    for line in data:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end
    
    if lines[#lines] ~= "---" then return end
    table.remove(lines)
    
    pinfo.cols.protocol = "EAEP"
    local subtree = tree:add(eaep_proto, buffer(), "EAEP Data")

    -- The Header
    local header = table.remove(lines, 1)
    local version = header:match("^EAEP (%d+%.%d+)")
    subtree:add(pf_ver, buffer(), version):set_text("Version: " .. version)
    local timestamp = header:match("%s([%d%:%-%.]+)$")
    subtree:add(buffer(), timestamp):set_text("TimeStamp: " .. timestamp)
    
    -- The Event
    local eventheader = table.remove(lines, 1)
    local host = eventheader:match("^(.+)%s.+%s.+$")
    subtree:add(pf_host, buffer(), host):set_text("Host: " .. host)
    local app = eventheader:match("^.+%s(.+)%s.+$")
    subtree:add(pf_app, buffer(), app):set_text("Application: " .. app)
    local event = eventheader:match("^.+%s.+%s(.+)$")
    subtree:add(pf_event, buffer(), event):set_text("Event: " .. event)

    -- The Parameters
    local paramstree = subtree:add(buffer(), "Parameters")
    local results = 0
    for index, line in ipairs(lines) do
		local paramtree = paramstree:add(buffer(), index)
		paramtree:set_text("Index: " .. index)
        for k, v in line:gmatch("([%w%p]+)=([%w%p]+)") do
            results = results + 1
            paramtree:add(pf_key, buffer(), k):set_text("Key: " .. k)
            paramtree:add(pf_value, buffer(), v):set_text("Value: " .. v)
        end
    end
    paramstree:append_text(", Count: " .. results)
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(3322, eaep_proto)
udp_table:add(5124, eaep_proto)
udp_table:add(60601, eaep_proto)
udp_table:add(60602, eaep_proto)
