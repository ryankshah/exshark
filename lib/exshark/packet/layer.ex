defmodule ExShark.Packet.Layer do
  @moduledoc """
  Represents a protocol layer with support for raw values.
  """
  defstruct [:name, :fields, :data, raw_mode: false]

  @doc """
  Creates a new Layer struct with the given name and fields.
  """
  def new(name, fields, data \\ nil) do
    %__MODULE__{
      name: name,
      fields: normalize_fields(fields),
      data: data,
      raw_mode: false
    }
  end

  @doc """
  Gets a field value from the layer, handling both raw and normal modes.
  """
  def get_field(%__MODULE__{} = layer, field) when is_atom(field) do
    name = to_string(layer.name)
    normalized_field = normalize_field_name(name, field)
    raw_field = normalized_field <> ".raw"

    cond do
      layer.raw_mode && Map.has_key?(layer.fields, raw_field) ->
        Map.get(layer.fields, raw_field)

      Map.has_key?(layer.fields, normalized_field) ->
        Map.get(layer.fields, normalized_field)

      # Try direct field access as fallback
      Map.has_key?(layer.fields, to_string(field)) ->
        Map.get(layer.fields, to_string(field))

      true ->
        nil
    end
  end

  @doc """
  Updates the raw mode of the layer.
  """
  def update_mode(%__MODULE__{} = layer, mode) when is_boolean(mode) do
    %{layer | raw_mode: mode}
  end

  @doc """
  Returns all available fields for the layer.
  """
  def fields(%__MODULE__{} = layer) do
    layer.fields
    |> Map.keys()
    |> Enum.map(&String.replace(&1, "#{layer.name}.", ""))
    |> Enum.uniq()
  end

  # Private Functions

  defp normalize_fields(nil), do: %{}

  defp normalize_fields(fields) when is_map(fields) do
    fields
    |> Enum.map(fn {k, v} -> {normalize_key(k), v} end)
    |> Enum.into(%{})
  end

  defp normalize_fields(_), do: %{}

  defp normalize_key(key) when is_binary(key) do
    key
    |> String.replace(~r/[_]+/, ".")
    |> String.replace(~r/\.+/, ".")
    |> String.trim(".")
  end

  defp normalize_key(key), do: to_string(key)

  defp normalize_field_name(layer_name, field) do
    field_str = to_string(field)

    if String.contains?(field_str, layer_name) do
      field_str
    else
      "#{layer_name}.#{field_str}"
    end
  end
end
