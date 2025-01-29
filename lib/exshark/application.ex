defmodule ExShark.Application do
  @moduledoc false
  use Application

  def start(_type, _args) do
    children = [
      {Task.Supervisor, name: ExShark.TaskSupervisor}
    ]

    opts = [strategy: :one_for_one, name: ExShark.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
