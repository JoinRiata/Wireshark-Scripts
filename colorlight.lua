-- ColorLight 5A 75B Protocol Dissector
-- Save this script as colorlight.lua

-- Create a new protocol
local colorlight_proto = Proto("ColorLight", "ColorLight 5A 75B Protocol")

-- Define the protocol fields
local f = colorlight_proto.fields

-- Pixel Data Frame Fields (0x5500, 0x5501)
f.pixel_row_number = ProtoField.uint16("colorlight.pixel_row_number", "Row Number", base.DEC)
f.pixel_offset = ProtoField.uint16("colorlight.pixel_offset", "Pixel Offset", base.DEC, nil, nil, "Little-endian")
f.pixel_count = ProtoField.uint16("colorlight.pixel_count", "Pixel Count", base.DEC, nil, nil, "Little-endian")
f.pixel_unknown1 = ProtoField.uint8("colorlight.pixel_unknown1", "Unknown1", base.HEX)
f.pixel_unknown2 = ProtoField.uint8("colorlight.pixel_unknown2", "Unknown2", base.HEX)
f.pixel_data = ProtoField.bytes("colorlight.pixel_data", "Pixel Data")

-- Dissector function
function colorlight_proto.dissector(buffer, pinfo, tree)
    -- Since the dissector is registered in 'ethertype', buffer starts after the EtherType field
    local data_length = buffer:len()
    if data_length < 1 then return end

    -- Obtain the EtherType from pinfo.match_uint
    local ethertype = pinfo.match_uint
    -- Debug print
    print(string.format("EtherType from pinfo.match_uint: 0x%04X", ethertype))

    -- Set protocol column
    pinfo.cols.protocol = "ColorLight"

    -- Add protocol to tree
    local subtree = tree:add(colorlight_proto, buffer(), "ColorLight Protocol Data")

    local data_offset = 0 -- Data starts at offset 0

    if ethertype == 0x5500 or ethertype == 0x5501 then
        -- Pixel Data Frame
        pinfo.cols.info = "Pixel Data Frame"

        local row_number_msb = ethertype - 0x5500
        local row_number_lsb = buffer(data_offset,1):uint()
        local row_number = (row_number_msb * 256) + row_number_lsb
        subtree:add(f.pixel_row_number, buffer(data_offset,1), row_number)
        data_offset = data_offset + 1

        -- Pixel Offset (little-endian)
        if buffer:len() >= data_offset + 2 then
            local pixel_offset = buffer(data_offset, 2):le_uint()
            subtree:add_le(f.pixel_offset, buffer(data_offset,2), pixel_offset)
            data_offset = data_offset + 2
        else
            return
        end

        -- Pixel Count (little-endian)
        if buffer:len() >= data_offset + 2 then
            local pixel_count = buffer(data_offset, 2):le_uint()
            subtree:add_le(f.pixel_count, buffer(data_offset,2), pixel_count)
            data_offset = data_offset + 2
        else
            return
        end

        -- Unknown bytes
        if buffer:len() >= data_offset + 2 then
            subtree:add(f.pixel_unknown1, buffer(data_offset,1))
            data_offset = data_offset +1
            subtree:add(f.pixel_unknown2, buffer(data_offset,1))
            data_offset = data_offset +1
        else
            return
        end

        -- Pixel Data
        local pixel_data_length = buffer:len() - data_offset
        if pixel_data_length > 0 then
            subtree:add(f.pixel_data, buffer(data_offset, pixel_data_length))
        end

    else
        -- Handle other frame types if needed
        pinfo.cols.info = string.format("ColorLight Keep-Alive Frame? (Not sure)", ethertype)
    end
end

-- Register the dissector for specific EtherTypes
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x0107, colorlight_proto)
for i = 0x0A00, 0x0AFF do
    eth_table:add(i, colorlight_proto)
end
eth_table:add(0x5500, colorlight_proto)
eth_table:add(0x5501, colorlight_proto)
eth_table:add(0x0700, colorlight_proto)
eth_table:add(0x0805, colorlight_proto)
