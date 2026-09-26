-- A Wireshark Lua dissector template for a game's own protocol, to go with a
-- capture made by procpcap. Fill in the fields for the protocol you are studying.
--
-- procpcap writes LINKTYPE_RAW, so Wireshark already decodes IP, TCP and UDP. A
-- dissector like this one takes over the payload above them: the bytes your game
-- actually sends. Start by watching the mean payload entropy in procpcap's stats
-- line. Low entropy is plaintext or a simple binary format you can lay out here;
-- entropy near 8 means the payload is encrypted or compressed, and there is
-- nothing to dissect until you find the key.
--
-- To use it:
--   1. Edit GAME_PORT below to the UDP port your capture shows.
--   2. Copy this file into Wireshark's plugin folder
--      (Help > About Wireshark > Folders > Personal Lua Plugins), or load it with
--      Tools > Lua > Evaluate.
--   3. Open the pcapng from procpcap. Each packet's PID and process name are in
--      the packet comment (the pcapng opt_comment), shown in the details pane.

local GAME_PORT = 27015

local game = Proto("gameproto", "Example Game Protocol")

-- Declare the fields. These are placeholders; replace them with the real layout.
local f_opcode = ProtoField.uint8("gameproto.opcode", "Opcode", base.HEX)
local f_seq    = ProtoField.uint16("gameproto.seq", "Sequence", base.DEC)
local f_length = ProtoField.uint16("gameproto.length", "Payload length", base.DEC)
local f_body   = ProtoField.bytes("gameproto.body", "Body")

game.fields = { f_opcode, f_seq, f_length, f_body }

function game.dissector(tvb, pinfo, tree)
    local n = tvb:len()
    if n < 5 then
        return 0 -- not enough for the header; let Wireshark keep the raw bytes
    end

    pinfo.cols.protocol = game.name
    local subtree = tree:add(game, tvb(), "Example Game Protocol")

    -- TODO: adjust offsets and sizes to the real packet format.
    subtree:add(f_opcode, tvb(0, 1))
    subtree:add(f_seq, tvb(1, 2))
    subtree:add(f_length, tvb(3, 2))
    if n > 5 then
        subtree:add(f_body, tvb(5, n - 5))
    end

    return n
end

-- Bind the dissector to the game's UDP port. Use get_dissector_table("tcp.port")
-- instead for a TCP protocol.
local udp_port = DissectorTable.get("udp.port")
udp_port:add(GAME_PORT, game)
