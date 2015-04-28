#!/usr/local/bin/fish
go build ../server
and if go build ../client
  for i in (seq (awk '/NumNodes/ {print $2}' config))
    set x (math $i - 1)
    ./server $x config  nodes clients pubkeys $x.secret &
  end

  for i in (seq (awk '/NumClients/ {print $2}' config))
    ./client (math $i - 1) config nodes clients pubkeys &
  end
end
sleep (awk '/Timeout/ {print $2}' config)
for j in (jobs -p)
  kill $j
end