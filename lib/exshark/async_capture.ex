defmodule ExShark.AsyncCapture do
  @moduledoc """
  Handles asynchronous packet processing with callbacks.
  """
  use Task

  @doc ~S"""
  Applies a callback function to each packet in a capture file.

  ## Options
    * `:timeout` - Maximum time in milliseconds to wait for completion (default: :infinity)
    * `:filter` - Display filter string
    * `:fields` - List of fields to extract

  ## Example
      ExShark.AsyncCapture.apply_on_packets("capture.pcap", fn p ->
        IO.puts("Processing packet #{p.frame_info.number}")
        {:ok, nil}
      end, timeout: 5000)
  """
  def apply_on_packets(file_path, callback, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, :infinity)

    task =
      Task.Supervisor.async(ExShark.TaskSupervisor, fn ->
        process_packets(file_path, callback, opts)
      end)

    try do
      case Task.yield(task, timeout) || Task.shutdown(task) do
        {:ok, result} -> result
        nil -> raise "Timeout after #{timeout}ms"
      end
    catch
      :exit, reason ->
        case reason do
          {:timeout, _} -> raise "Timeout after #{timeout}ms"
          _ -> raise "Task failed: #{inspect(reason)}"
        end
    end
  end

  @doc """
  Similar to apply_on_packets/3 but handles async callbacks.
  """
  def apply_on_packets_async(file_path, callback, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, :infinity)

    task =
      Task.Supervisor.async(ExShark.TaskSupervisor, fn ->
        process_async_packets(file_path, callback, timeout, opts)
      end)

    try do
      case Task.yield(task, timeout) || Task.shutdown(task) do
        {:ok, results} -> {:ok, results}
        nil -> raise "Timeout after #{timeout}ms"
      end
    catch
      :exit, reason ->
        case reason do
          {:timeout, _} -> raise "Timeout after #{timeout}ms"
          _ -> raise "Task failed: #{inspect(reason)}"
        end
    end
  end

  defp process_async_packets(file_path, callback, timeout, opts) do
    task_supervisor = ExShark.TaskSupervisor

    stream_result =
      file_path
      |> ExShark.read_file(opts)
      |> Task.Supervisor.async_stream_nolink(
        task_supervisor,
        fn pkt ->
          try do
            case callback.(pkt) do
              {:ok, task} when is_struct(task, Task) ->
                {:ok, Task.await(task, timeout)}

              {:ok, result} ->
                {:ok, result}

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
        end,
        timeout: timeout,
        ordered: true
      )
      |> Enum.to_list()

    {:ok, stream_result}
  end

  defp process_packets(file_path, callback, opts) do
    try do
      file_path
      |> ExShark.read_file(opts)
      |> Enum.each(fn pkt ->
        try do
          case callback.(pkt) do
            {:ok, _} -> :ok
            :ok -> :ok
            {:error, reason} -> raise "Callback failed: #{inspect(reason)}"
            other -> raise "Unexpected callback return: #{inspect(other)}"
          end
        rescue
          e -> raise "Callback error: #{Exception.message(e)}"
        end
      end)

      :ok
    rescue
      e ->
        error_msg = Exception.message(e)
        reraise "Failed to process packets: #{error_msg}", __STACKTRACE__
    catch
      :exit, reason ->
        reraise "Failed to process packets: Task exited - #{inspect(reason)}", __STACKTRACE__
    end
  end

  @doc """
  Starts a live asynchronous capture with a callback function.

  ## Options
    * `:interface` - Network interface to capture on (default: "any")
    * `:filter` - Display filter string
    * `:timeout` - Maximum time to wait for each callback (default: 5000)
  """
  def capture_live(callback, opts \\ []) do
    capture_opts = Keyword.put_new(opts, :timeout, 5000)
    task_supervisor = ExShark.TaskSupervisor

    ExShark.capture(capture_opts)
    |> Stream.each(fn pkt ->
      Task.Supervisor.start_child(task_supervisor, fn ->
        try do
          case callback.(pkt) do
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
