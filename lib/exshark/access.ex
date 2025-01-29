defprotocol ExShark.PacketAccess do
  @doc """
  Gets a value from a packet by protocol and field name.
  """
  def get(packet, key)
end

defimpl ExShark.PacketAccess, for: ExShark.Packet do
  def get(packet, {protocol, field}) when is_atom(protocol) and is_atom(field) do
    ExShark.Packet.get_protocol_field(packet, protocol, field)
  end

  def get(_, _), do: nil
end
