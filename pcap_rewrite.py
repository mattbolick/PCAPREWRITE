import subprocess
import os
import re
import ipaddress
import argparse
import pickle

def rewrite_pcap(pcap_file, server_subnet_str=None, server_mac=None, client_subnet_str=None, client_mac=None, tcpprep_auto_mode="first"):
    """
    Rewrites a pcap file using tcpprep and tcprewrite, remapping IP addresses
    and MAC addresses for server-client pairs.  Uses distinct temp files for
    *every* tcprewrite call.

    Args:
        pcap_file: Path to the input pcap file.
        server_subnet_str: New server subnet (e.g., "192.168.1.0/24").
        server_mac: Destination MAC for server->client packets.
        client_subnet_str: New client subnet (e.g., "10.0.0.0/24").
        client_mac: Destination MAC for client->server packets.
        tcpprep_auto_mode: "first" (try auto, then manual), "only" (only auto), or "none" (skip auto).

    Returns:
        str: Path to the rewritten pcap file, or None if an error occurred.
    """

    # --- Input Validation and Prompting ---
    if not os.path.exists(pcap_file):
        print(f"ERROR: File not found: {pcap_file}")
        return None

    if server_subnet_str is None:
        server_subnet_str = input("Enter the new server subnet (e.g., 192.168.1.0/24): ")
    if server_mac is None:
        server_mac = input("Enter the destination MAC address for server->client packets (e.g., 00:11:22:33:44:55): ")
    if client_subnet_str is None:
        client_subnet_str = input("Enter the new client subnet (e.g., 10.0.0.0/24): ")
    if client_mac is None:
        client_mac = input("Enter the destination MAC address for client->server packets (e.g., AA:BB:CC:DD:EE:FF): ")

    try:
        server_subnet = ipaddress.ip_network(server_subnet_str, strict=False)
        client_subnet = ipaddress.ip_network(client_subnet_str, strict=False)
        if not all(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac) for mac in [server_mac, client_mac]):
            print("ERROR: Invalid MAC address format.  Use format like 00:11:22:33:44:55")
            return None
    except ValueError as e:
        print(f"ERROR: Invalid subnet or MAC address: {e}")
        return None

    # --- File Path Setup ---
    base_filename = os.path.splitext(os.path.basename(pcap_file))[0]
    tcpprep_cache_file = f"{base_filename}.cache"
    rewritten_pcap_file = f"{base_filename}_rewritten.pcap"
    pairs_file = f"{base_filename}_pairs.pkl"

    if os.path.exists(rewritten_pcap_file):
        os.remove(rewritten_pcap_file)

    # --- tcpprep (Optional) ---
    if tcpprep_auto_mode in ("first", "only"):
        try:
            tcpprep_command = ["tcpprep", "-i", pcap_file, "-o", tcpprep_cache_file, "-a", "first"]
            subprocess.run(tcpprep_command, check=True, capture_output=True, text=True)
            print("tcpprep completed successfully (auto mode).")
        except subprocess.CalledProcessError as e:
            print(f"tcpprep (auto mode) failed:\n {e.stderr}")
            if tcpprep_auto_mode == "only":
                return None

    # --- ALWAYS run tshark to get IP pairs ---
    print("Identifying client/server pairs using tshark...")
    server_client_pairs = {}
    next_server_ip = server_subnet.network_address + 11
    next_client_ip = client_subnet.network_address + 11

    try:
        tshark_command = ["tshark", "-r", pcap_file, "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-Y", "ip"]
        result = subprocess.run(tshark_command, capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split('\n')

        for line in lines:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) != 2:
                print(f"WARNING: Skipping invalid tshark line: {line}")
                continue
            src_ip, dst_ip = parts[0], parts[1]

            try:
                ipaddress.ip_address(src_ip)
                ipaddress.ip_address(dst_ip)
            except ValueError:
                print(f"WARNING: Skipping invalid IP addresses: {src_ip}, {dst_ip}")
                continue

            pair_key = tuple(sorted((src_ip, dst_ip)))

            if pair_key not in server_client_pairs:
                server_client_pairs[pair_key] = {'server': str(next_server_ip), 'client': str(next_client_ip), 'processed': False}
                next_server_ip += 1
                if next_server_ip not in server_subnet:
                    next_server_ip = server_subnet.network_address + 11
                    if next_server_ip >= server_subnet.broadcast_address:
                        print("WARNING: Server subnet exhausted. Reusing addresses.")
                next_client_ip += 1
                if next_client_ip not in client_subnet:
                    next_client_ip = client_subnet.network_address + 11
                    if next_client_ip >= client_subnet.broadcast_address:
                        print("WARNING: Client subnet exhausted. Reusing addresses.")

    except subprocess.CalledProcessError as e:
        print(f"tshark command failed: {e}")
        return None

     # --- Save server_client_pairs for debugging ---
    try:
        with open(pairs_file, "wb") as f:
            pickle.dump(server_client_pairs, f)
        print(f"Server-client pairs saved to: {pairs_file}")
    except Exception as e:
        print(f"Error saving pairs to file: {e}")

    # --- Iterative tcprewrite ---
    current_input_file = pcap_file
    processed_count = 0
    rewrite_step = 0 #for unique file names

    try:
        for pair, ip_mapping in server_client_pairs.items():
            if ip_mapping['processed']:  # Shouldn't happen, but good practice
                continue

            original_server_ip, original_client_ip = pair
            if original_server_ip > original_client_ip:
                original_server_ip, original_client_ip = original_client_ip, original_server_ip
            new_server_ip = ip_mapping['server']
            new_client_ip = ip_mapping['client']

            # --- Server IP (src) ---
            temp_file = f"{base_filename}_temp_{processed_count}_{rewrite_step}.pcap"
            rewrite_step += 1
            tcprewrite_command = [
                "tcprewrite",
                "--infile", current_input_file,
                "--outfile", temp_file,
                "--enet-dmac=" + f"{client_mac},{server_mac}",
                "--skipbroadcast",
                "--fixcsum",
                f"--srcipmap={original_server_ip}:{new_server_ip}",
                "--cachefile", tcpprep_cache_file
            ]
            print(f"Running: {' '.join(tcprewrite_command)}")
            subprocess.run(tcprewrite_command, check=True, capture_output=True, text=True)
            if current_input_file != pcap_file:
                os.remove(current_input_file)  # Delete previous input file
            current_input_file = temp_file #update current input


            # --- Server IP (dst) ---
            temp_file = f"{base_filename}_temp_{processed_count}_{rewrite_step}.pcap"
            rewrite_step += 1
            tcprewrite_command = [
                "tcprewrite",
                "--infile", current_input_file,
                "--outfile", temp_file,
                "--enet-dmac=" + f"{client_mac},{server_mac}",
                "--skipbroadcast",
                "--fixcsum",
                f"--dstipmap={original_client_ip}:{new_client_ip}",
                "--cachefile", tcpprep_cache_file
            ]
            print(f"Running: {' '.join(tcprewrite_command)}")
            subprocess.run(tcprewrite_command, check=True, capture_output=True, text=True)
            os.remove(current_input_file) #delete previous input
            current_input_file = temp_file  # Update

            # --- Client IP (src) ---
            temp_file = f"{base_filename}_temp_{processed_count}_{rewrite_step}.pcap"
            rewrite_step += 1
            tcprewrite_command = [
                "tcprewrite",
                "--infile", current_input_file,
                "--outfile", temp_file,
                "--enet-dmac=" + f"{client_mac},{server_mac}",
                "--skipbroadcast",
                "--fixcsum",
                f"--srcipmap={original_client_ip}:{new_client_ip}",
                "--cachefile", tcpprep_cache_file
            ]
            print(f"Running: {' '.join(tcprewrite_command)}")
            subprocess.run(tcprewrite_command, check=True, capture_output=True, text=True)
            os.remove(current_input_file) #delete previous
            current_input_file = temp_file  # Update

            # --- Client IP (dst) ---
            temp_file = f"{base_filename}_temp_{processed_count}_{rewrite_step}.pcap"
            rewrite_step += 1
            tcprewrite_command = [
                "tcprewrite",
                "--infile", current_input_file,
                "--outfile", temp_file,
                "--enet-dmac=" + f"{client_mac},{server_mac}",
                "--skipbroadcast",
                "--fixcsum",
                f"--dstipmap={original_server_ip}:{new_server_ip}",
                "--cachefile", tcpprep_cache_file
            ]
            print(f"Running: {' '.join(tcprewrite_command)}")
            subprocess.run(tcprewrite_command, check=True, capture_output=True, text=True)
            os.remove(current_input_file) #delete previous
            current_input_file = temp_file

            server_client_pairs[pair]['processed'] = True
            processed_count += 1 #increment after pair processed.

    except subprocess.CalledProcessError as e:
        print(f"tcprewrite failed during iterative rewrite:\n {e.stderr}")
        return None

    # --- Final Output File ---
    #  Use the *last* temp_file as the input for the final rename
    if os.path.exists(current_input_file):  #current_input_file should be last temp file
        os.rename(current_input_file, rewritten_pcap_file)
        print(f"Rewritten pcap file saved to: {rewritten_pcap_file}")
        return rewritten_pcap_file
    else:
        print("ERROR: Final temporary file not found. Rewriting failed.")
        return None



def main():
    parser = argparse.ArgumentParser(description="Rewrite a pcap file using tcpprep and tcprewrite.")
    parser.add_argument("pcap_file", help="Path to the input pcap file.")
    parser.add_argument("--server_subnet", help="New server subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("--server_mac", help="Destination MAC for server->client packets (e.g., 00:11:22:33:44:55)")
    parser.add_argument("--client_subnet", help="New client subnet (e.g., 10.0.0.0/24)")
    parser.add_argument("--client_mac", help="Destination MAC for client->server packets (e.g., AA:BB:CC:DD:EE:FF)")
    parser.add_argument("--auto", choices=["first", "only", "none"], default="first",
                        help="tcpprep auto mode: 'first' (try auto, then manual), 'only' (only auto), 'none' (skip auto)")

    args = parser.parse_args()

    rewritten_file = rewrite_pcap(args.pcap_file, args.server_subnet, args.server_mac,
                                  args.client_subnet, args.client_mac, args.auto)

    if rewritten_file:
        print(f"Rewritten pcap file saved to: {rewritten_file}")
    else:
        print("Rewriting failed.")

if __name__ == "__main__":
    main()
