defmodule Sniper.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Sniper.Pool, []},
      {Sniper.Monitor, []}
    ]
    Supervisor.start_link(children, strategy: :one_for_one, name: Sniper.Supervisor)
  end
end
