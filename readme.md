Requires either wireguard installed and in system path or python cryptography package installed (for key generation). Will target wireguard-tools by default, but if you specify wireguard-quick options, those will be included in the generated config files. 

Example usage:
```
> ./wireguard-wizard.py -f example/example_graph.json init
> ./wireguard-wizard.py -f example/example_graph.json add MyServer 192.168.3.1 --endpoint 12.34.56.78 --listen-port 59898 --keepalive 5 
> ./wireguard-wizard.py -f example/example_graph.json bulk-add 4 
> ./wireguard-wizard.py -f example/example_graph.json list
  MyServer (server)  ip=192.168.3.1/32  peers=[*]
  192.168.3.1 (client)  ip=192.168.3.1/32  peers=[*]
  192.168.3.2 (client)  ip=192.168.3.2/32  peers=[*]
  192.168.3.3 (client)  ip=192.168.3.3/32  peers=[*]
  192.168.3.4 (client)  ip=192.168.3.4/32  peers=[*]
> ./wireguard-wizard.py -f example/example_graph.json generate
(see example/configs)
```

Docs:
```
usage: wireguard-wizard [-h] [-f FILE] {init,add,bulk-add,list,remove,generate}

Manage WireGuard network graphs and generate config files.

positional arguments:
  {init,add,bulk-add,list,remove,generate}
    init                Create a new empty graph file
    add                 Add a host to the graph
    bulk-add            Add N clients with auto-assigned IPs
    list                List all hosts in the graph
    remove              Remove a host from the graph
    generate            Generate .conf files from the graph

options:
  -h, --help            show this help message and exit
  -f, --file FILE       Path to the graph JSON file (default: graph.json)
```

Python utility functions provided: 
```
gen_private_key()
derive_public_key(privatekey)
load_graph(filepath_and_name)
save_graph(filepath_and_name, graph)
add_host(graph, 
  name=,
  ip=,
  subnet='/32',
  endpoint=None,
  private_key=AUTO_GENERATED_PRIVATE_KEY or user supplied,
  public_key=AUTO_GENERATED_PUBLIC_KEY or user supplied,
  peers=[{name:"*"}] # use [ {name : "peer_name", keep_alive : "5" }, ... ] if you don't want to have every node be a peer
  Table=None,
  MTU=None,
  DNS=None,
  PreUp=None,
  PostDown=None
)
gen_config_files(graph)
```