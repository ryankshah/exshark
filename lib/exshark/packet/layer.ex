defmodule ExShark.Packet.Layer do
  @moduledoc """
  Represents a protocol layer with support for raw values.
  """
  defstruct [:name, :fields, :data, raw_mode: false]

  def new(name, fields, data \\ nil) do
    %__MODULE__{
      name: name,
      fields: fields || %{},
      data: data,
      raw_mode: false
    }
  end

  def get_field(%__MODULE__{} = layer, field) do
    field_name = "#{layer.name}.#{field}"
    raw_field = "#{field_name}.raw"

    cond do
      layer.raw_mode && Map.has_key?(layer.fields, raw_field) ->
        Map.get(layer.fields, raw_field)

      Map.has_key?(layer.fields, field_name) ->
        Map.get(layer.fields, field_name)

      true ->
        nil
    end
  end
end
