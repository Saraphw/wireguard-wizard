#!/usr/bin/env python3

import subprocess, json, os, shutil, sys, base64, argparse
"""
Wireguard graph structure: bipartite between 'servers' (devices with an externally accessible
port) and 'clients' (devices w/o one). Connections between servers are allowed.

Components of each entry

full options: 
[Interface]
PrivateKey = 
Address = wg-quick only
ListenPort = 
DNS = wg-quick only
MTU =  (usually none - maximum transmissible unit) wg-quick only
Table = (usually ommitted, defaults to auto. something to do with routing tables) wg-quick only
PreUp = "" wg-quick only
PostDown = "" wg-quick only

[Peer]
PublicKey = 
AllowedIps = CIDR ranges (does outbound routing and manages where packets are allowed to come from)
Endpoint = 12.34.56.78:58888 (ip address)
PersistentKeepalive = 5 #s, I think
PresharedKey = 
"""

def gen_private_key() -> str:
    if shutil.which("wg"):
        return subprocess.run(["wg", "genkey"], capture_output=True, text=True,
                              check=True).stdout.strip()
    try:
        from cryptography.hazmat.primitives import serialization as s
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    except ImportError:
        sys.exit("Need either the `wg` binary or `pip install cryptography` for key generation.")
    raw = X25519PrivateKey.generate().private_bytes(
        s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    return base64.b64encode(raw).decode()


def derive_public_key(private_key: str) -> str:
    if shutil.which("wg"):
        return subprocess.run(["wg", "pubkey"], input=private_key + "\n",
                              capture_output=True, text=True, check=True).stdout.strip()
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    priv = X25519PrivateKey.from_private_bytes(base64.b64decode(private_key))
    return base64.b64encode(
        priv.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)).decode()



def load_graph(file):
    with open(file, 'r') as f: 
        out = json.load(f)
    return out

def save_graph(file, graph):
    with open(file, 'w+') as f:
        json.dump(graph, f)


def add_host(graph, **kwargs):
    pkey = kwargs.get("private_key", gen_private_key())
    graph[kwargs.get("name")] = {
        "ip" : kwargs.get("ip") + kwargs.get("subnet", "/32"), 
        "endpoint" : kwargs.get("endpoint", None),
        "listen_port" : kwargs.get("listen_port", None),
        "private_key" : pkey,
        "public_key" : kwargs.get("public_key", derive_public_key(pkey)),
        "peers" : kwargs.get("peers", [{"name" : "*"}]),
        "Table" : kwargs.get("Table", None),
        "MTU" : kwargs.get("MTU", None),
        "PreUp" : kwargs.get("PreUp", None),
        "PostDown" : kwargs.get("PostDown", None),
        "DNS" : kwargs.get("DNS", None)
    }
    return graph

def write_interface(name, host, wgquick = False):
    itext = "[Interface]\nPrivateKey = " + host["private_key"] + "\n"
    if wgquick:
        itext += "Adress = " + host["ip"] + "\n"
    if(host.get("listen_port") is not None):
            itext += "ListenPort = " + host["listen_port"] + "\n\n"
    for param in ["DNS", "MTU", "Table", "PreUp", "PostDown"]:
            if host.get(param):
                itext += param + " = " + host.get(param) + "\n"
    return itext

def write_peer(name, peer, keep_alive): 
    peer_text = "[Peer]" + " # " + name + "\n"
    peer_text += "PublicKey = " + peer["public_key"] + "\n"
    peer_text += "AllowedIps = " + peer["ip"] + "\n"
    if peer.get("endpoint"):
        peer_text += "Endpoint = " + peer["endpoint"] + ":" + peer["listen_port"] + "\n"
        peer_text += "PersistentKeepalive = " + keep_alive + "\n"
    return peer_text

def gen_config_files(graph):
    for hostname in graph.keys():
        host = graph.get(hostname)
        is_server = host.get("endpoint", False)
        ftext = write_interface(hostname, host) + "\n"
        if len((host["peers"])) == 1 and host["peers"][0].get("name") == "*":
            if is_server:
                peers = [{"name" : name} for name in graph.keys() if name != hostname]
            else:
                peers = [{"name" : name} for name in graph.keys() if (graph[name].get("endpoint")) and name != hostname]
        else:
            peers = host["peers"]
        for connection in peers:
                peer = graph.get(connection['name'], None)
                if not peer:
                    print("Error finding peer " + str(connection) + " in host " + hostname)
                    continue
                ftext += write_peer(connection['name'], peer, connection.get("keepalive", "25")) + "\n"
        with open(hostname + ".conf", "w+") as f:
            f.write(ftext)
    return


def bulk_add_clients(graph, N, name="client_", ipsubnet="192.168.3."):
    # TODO preprocess ipsubnet
    i = 1
    for _ in range(N):
        while(name + str(i) in graph.keys()) and i < 256:
            i += 1
        graph = add_host(graph, 
            name = name + str(i),
            ip = ipsubnet + str(i),
            subnet = "/32"
        )
        i += 1
    return graph



def cmd_init(args):
    if os.path.exists(args.file):
        print(f"Error: {args.file} already exists. Use --force to overwrite.")
        if not args.force:
            sys.exit(1)
    save_graph(args.file, {})
    print(f"Initialized empty graph at {args.file}")


def cmd_add(args):
    graph = load_graph(args.file)
    kwargs = {
        "name": args.name,
        "ip": args.ip,
        "subnet": args.subnet,
    }
    if args.endpoint:
        kwargs["endpoint"] = args.endpoint
    if args.listen_port:
        kwargs["listen_port"] = args.listen_port
    if args.private_key:
        kwargs["private_key"] = args.private_key
    if args.public_key:
        kwargs["public_key"] = args.public_key
    if args.keepalive:
        kwargs["keepalive"] = args.keepalive
    if args.pre_up:
        kwargs["PreUp"] = args.pre_up
    if args.post_down:
        kwargs["PostDown"] = args.post_down
    if args.mtu:
        kwargs["MTU"] = args.mtu
    if args.table:
        kwargs["Table"] = args.table
    if args.dns:
        kwargs["DNS"] = args.dns

    graph = add_host(graph, **kwargs)
    save_graph(args.file, graph)
    print(f"Added host '{args.name}' to {args.file}")


def cmd_bulk_add(args):
    graph = load_graph(args.file)
    graph = bulk_add_clients(graph, args.count, args.subnet_prefix)
    save_graph(args.file, graph)
    print(f"Added {args.count} clients with prefix {args.subnet_prefix}")


def cmd_list(args):
    graph = load_graph(args.file)
    if not graph:
        print("No hosts defined.")
        return
    for name, host in graph.items():
        role = "server" if host.get("endpoint") else "client"
        peers = ", ".join(p["name"] for p in host.get("peers", []))
        print(f"  {name} ({role})  ip={host['ip']}  peers=[{peers}]")


def cmd_remove(args):
    graph = load_graph(args.file)
    if args.name not in graph:
        print(f"Error: host '{args.name}' not found.")
        sys.exit(1)
    del graph[args.name]
    # Remove this host from any peer lists
    for host in graph.values():
        host["peers"] = [p for p in host.get("peers", []) if p.get("name") != args.name]
    save_graph(args.file, graph)
    print(f"Removed host '{args.name}'")


def cmd_generate(args):
    graph = load_graph(args.file)
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        os.chdir(args.output_dir)
    gen_config_files(graph)
    out = args.output_dir or "current directory"
    print(f"Config files written to {out}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="wg-wizard",
        description="Manage WireGuard network graphs and generate config files.",
    )
    parser.add_argument(
        "-f", "--file", default="graph.json", metavar="FILE",
        help="Path to the graph JSON file (default: graph.json)"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="Create a new empty graph file")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing file")
    p_init.set_defaults(func=cmd_init)

    # add
    p_add = sub.add_parser("add", help="Add a host to the graph")
    p_add.add_argument("name", help="Unique name for this host")
    p_add.add_argument("ip", help="HOST IP address (without subnet, e.g. 192.168.3.1)")
    p_add.add_argument("--subnet", default="/32", help="Subnet mask (default: /32)")
    p_add.add_argument("--endpoint", help="Public IP or hostname (makes this host a server)")
    p_add.add_argument("--listen-port", dest="listen_port", help="UDP listen port")
    p_add.add_argument("--private-key", dest="private_key", help="Override private key. If not specified, one is generated automatically")
    p_add.add_argument("--public-key", dest="public_key", help="Override public key. If not specified, one is generated automatically")
    p_add.add_argument("--keepalive", help="PersistentKeepalive value in seconds")
    p_add.add_argument("--pre-up", dest="pre_up", help="PreUp command")
    p_add.add_argument("--post-down", dest="post_down", help="PostDown command")
    p_add.add_argument("--mtu", help="MTU override")
    p_add.add_argument("--table", help="Routing table setting")
    p_add.add_argument("--dns", help="DNS server(s)")
    p_add.set_defaults(func=cmd_add)

    # bulk-add
    p_bulk = sub.add_parser("bulk-add", help="Add N clients with auto-assigned IPs")
    p_bulk.add_argument("count", type=int, help="Number of clients to add")
    p_bulk.add_argument(
        "--subnet-prefix", dest="subnet_prefix",
        default="192.168.3.", help="IP prefix (default: 192.168.3.)"
    )
    p_bulk.set_defaults(func=cmd_bulk_add)

    # list
    p_list = sub.add_parser("list", help="List all hosts in the graph")
    p_list.set_defaults(func=cmd_list)

    # remove
    p_remove = sub.add_parser("remove", help="Remove a host from the graph")
    p_remove.add_argument("name", help="Name of the host to remove")
    p_remove.set_defaults(func=cmd_remove)

    # generate
    p_gen = sub.add_parser("generate", help="Generate .conf files from the graph")
    p_gen.add_argument(
        "-o", "--output-dir", dest="output_dir",
        help="Directory to write config files into (default: current directory)"
    )
    p_gen.set_defaults(func=cmd_generate)

    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)