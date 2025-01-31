defmodule ExShark.AsyncCapture do
  @moduledoc """
  Handles asynchronous packet processing with callbacks.
  """
  use Task

  @doc ~S"""
  Applies a callback function to each packet in a capture file.
  """
  def apply_on_packets(file_path, callback, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, :infinity)

    task =
      Task.Supervisor.async_nolink(ExShark.TaskSupervisor, fn ->
        process_packets(file_path, callback, opts)
      end)

    try do
      case Task.await(task, timeout) do
        :ok -> :ok
        {:error, reason} -> raise "Callback failed: #{inspect(reason)}"
      end
    catch
      :exit, {:timeout, _} -> raise "Timeout after #{timeout}ms"
      :exit, reason -> raise "Task failed: #{inspect(reason)}"
    end
  end

  @doc """
  Similar to apply_on_packets/3 but handles async callbacks.
  Returns a list of processed results.
  """
  def apply_on_packets_async(file_path, callback, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, :infinity)

    task =
      Task.Supervisor.async_nolink(ExShark.TaskSupervisor, fn ->
        process_async_packets(file_path, callback, timeout, opts)
      end)

    try do
      results = Task.await(task, timeout)
      {:ok, results}
    catch
      :exit, {:timeout, _} -> raise "Timeout after #{timeout}ms"
      :exit, reason -> raise "Task failed: #{inspect(reason)}"
    end
  end

  defp process_async_packets(file_path, callback, timeout, opts) do
    file_path
    |> ExShark.read_file(opts)
    |> Enum.map(fn packet ->
      try do
        case callback.(packet) do
          {:ok, task} when is_struct(task, Task) ->
            case Task.await(task, timeout) do
              result -> result
            end

          {:ok, result} ->
            result

          {:error, reason} ->
            {:error, reason}

          other ->
            {:error, "Unexpected callback return: #{inspect(other)}"}
        end
      rescue
        e -> {:error, Exception.message(e)}
      catch
        :exit, reason -> {:error, "Task exited: #{inspect(reason)}"}
      end
    end)
  end

  defp process_packets(file_path, callback, opts) do
    file_path
    |> ExShark.read_file(opts)
    |> Enum.each(fn packet ->
      case callback.(packet) do
        {:ok, _} -> :ok
        :ok -> :ok
        {:error, reason} -> raise "Callback failed: #{inspect(reason)}"
        other -> raise "Unexpected callback return: #{inspect(other)}"
      end
    end)

    :ok
  rescue
    e -> {:error, Exception.message(e)}
  end

  @doc """
  Starts a live asynchronous capture with a callback function.
  """
  def capture_live(callback, opts \\ []) do
    interface = Keyword.get(opts, :interface, "any")
    packet_count = Keyword.get(opts, :packet_count)
    capture_opts = Keyword.merge(opts, interface: interface, packet_count: packet_count)

    ExShark.capture(capture_opts)
    |> Stream.each(fn packet ->
      Task.Supervisor.start_child(ExShark.TaskSupervisor, fn ->
        try do
          case callback.(packet) do
            {:ok, _} ->
              :ok

            :ok ->
              :ok

            {:error, reason} ->
              require Logger
              Logger.warning("Callback failed: #{inspect(reason)}")

            other ->
              require Logger
              Logger.warning("Unexpected callback return: #{inspect(other)}")
          end
        rescue
          e ->
            require Logger
            Logger.warning("Callback error: #{Exception.message(e)}")
        end
      end)
    end)
    |> Stream.run()
  end

  @doc """
  Stops all ongoing async captures.
  """
  def stop_all do
    Task.Supervisor.children(ExShark.TaskSupervisor)
    |> Enum.each(&Task.Supervisor.terminate_child(ExShark.TaskSupervisor, &1))
  end
end
