defmodule Sniper.Config do
  def load do
    path = "./config.json"
    unless File.exists?(path) do
      IO.puts("[ERROR] config.json bulunamadi!")
      System.halt(1)
    end
    Jason.decode!(File.read!(path))
  end

  def monitor_tokens(cfg) do
    path = cfg["list_path"] || "./list.txt"
    if File.exists?(path) do
      tokens =
        File.read!(path)
        |> String.split(~r/[\r\n]+/)
        |> Enum.map(&String.trim/1)
        |> Enum.filter(&(String.length(&1) > 25))
        |> Enum.uniq()
      if tokens != [], do: tokens, else: [cfg["token"]]
    else
      [cfg["token"]]
    end
  end
end
