#!/bin/bash
# OPC UA module - browse, read, write

rt_opcua() {
  local target
  target=$(IP_PICKER "OPC UA server" "192.168.1.10")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  if ! in_scope "$target"; then
    LOG red "Target $target not in scope"
    return 1
  fi
  
  local port
  port=$(NUMBER_PICKER "Port" 4840)
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local choice
  choice=$(menu_pick "OPC UA: $target:$port" \
    "Get Endpoints" \
    "Browse Root" \
    "Browse Node" \
    "Read Node Value" \
    "Write Node Value" \
    "Check Security")
  
  case "$choice" in
    1) opcua_endpoints "$target" "$port" ;;
    2) opcua_browse "$target" "$port" "i=84" ;; # Root
    3) opcua_browse_custom "$target" "$port" ;;
    4) opcua_read "$target" "$port" ;;
    5) opcua_write "$target" "$port" ;;
    6) opcua_security "$target" "$port" ;;
    0|"") return ;;
  esac
}

opcua_endpoints() {
  local target="$1" port="$2"
  local url="opc.tcp://$target:$port"
  local outfile
  outfile="$ARTIFACT_DIR/opcua_endpoints_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Getting OPC UA endpoints: $url"
  
  {
    echo "=== OPC UA Endpoints: $url ==="
    echo ""
    
    if have python3; then
      python3 -c "
from opcua import Client
try:
    client = Client('$url', timeout=10)
    endpoints = client.connect_and_get_server_endpoints()
    for ep in endpoints:
        print(f'Endpoint: {ep.EndpointUrl}')
        print(f'  Security Mode: {ep.SecurityMode}')
        print(f'  Security Policy: {ep.SecurityPolicyUri}')
        print()
except Exception as e:
    print(f'Error: {e}')
" 2>&1
    elif [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      laptop_exec "python3 -c \"
from opcua import Client
client = Client('$url', timeout=10)
endpoints = client.connect_and_get_server_endpoints()
for ep in endpoints:
    print(f'Endpoint: {ep.EndpointUrl}')
    print(f'  Security Mode: {ep.SecurityMode}')
    print(f'  Security Policy: {ep.SecurityPolicyUri}')
\""
    else
      LOG "python3 with opcua library required"
    fi
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

opcua_browse() {
  local target="$1" port="$2" node_id="$3"
  local url="opc.tcp://$target:$port"
  local outfile
  outfile="$ARTIFACT_DIR/opcua_browse_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Browsing OPC UA node: $node_id"
  
  {
    echo "=== OPC UA Browse: $url ==="
    echo "Node: $node_id"
    echo ""
    
    python3 -c "
from opcua import Client, ua
try:
    client = Client('$url', timeout=10)
    client.connect()
    node = client.get_node('$node_id')
    children = node.get_children()
    for child in children[:30]:  # Limit
        try:
            name = child.get_browse_name()
            print(f'{child.nodeid} - {name.Name}')
        except:
            print(f'{child.nodeid} - (error reading name)')
    client.disconnect()
except Exception as e:
    print(f'Error: {e}')
" 2>&1
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}

opcua_browse_custom() {
  local target="$1" port="$2"
  
  local node_id
  node_id=$(TEXT_PICKER "Node ID" "i=84")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  opcua_browse "$target" "$port" "$node_id"
}

opcua_read() {
  local target="$1" port="$2"
  local url="opc.tcp://$target:$port"
  
  local node_id
  node_id=$(TEXT_PICKER "Node ID to read" "ns=2;s=TagName")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG blue "Reading OPC UA node: $node_id"
  
  python3 -c "
from opcua import Client
try:
    client = Client('$url', timeout=10)
    client.connect()
    node = client.get_node('$node_id')
    value = node.get_value()
    print(f'Value: {value}')
    print(f'Type: {type(value).__name__}')
    client.disconnect()
except Exception as e:
    print(f'Error: {e}')
" 2>&1
}

opcua_write() {
  local target="$1" port="$2"
  local url="opc.tcp://$target:$port"
  
  if ! check_passive; then return 1; fi
  if ! confirm_danger "WRITE to OPC UA node on $target. This may affect process!"; then
    return 1
  fi
  
  local node_id
  node_id=$(TEXT_PICKER "Node ID" "ns=2;s=TagName")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  local value
  value=$(TEXT_PICKER "Value" "0")
  case $? in "$DUCKYSCRIPT_CANCELLED"|"$DUCKYSCRIPT_REJECTED"|"$DUCKYSCRIPT_ERROR") return ;; esac
  
  LOG red "WRITING to $node_id = $value"
  
  python3 -c "
from opcua import Client, ua
try:
    client = Client('$url', timeout=10)
    client.connect()
    node = client.get_node('$node_id')
    # Try to infer type and write
    current = node.get_value()
    if isinstance(current, bool):
        node.set_value(bool(int('$value')))
    elif isinstance(current, int):
        node.set_value(int('$value'))
    elif isinstance(current, float):
        node.set_value(float('$value'))
    else:
        node.set_value('$value')
    print('Write successful')
    client.disconnect()
except Exception as e:
    print(f'Error: {e}')
" 2>&1
}

opcua_security() {
  local target="$1" port="$2"
  local url="opc.tcp://$target:$port"
  local outfile
  outfile="$ARTIFACT_DIR/opcua_security_${target}_$(ts).txt"
  ensure_dir "$ARTIFACT_DIR"
  
  LOG blue "Checking OPC UA security configuration..."
  
  {
    echo "=== OPC UA Security Check: $url ==="
    echo ""
    
    python3 -c "
from opcua import Client
try:
    client = Client('$url', timeout=10)
    endpoints = client.connect_and_get_server_endpoints()
    
    insecure = []
    for ep in endpoints:
        mode = str(ep.SecurityMode)
        policy = ep.SecurityPolicyUri.split('#')[-1] if ep.SecurityPolicyUri else 'None'
        
        if 'None' in mode or 'None' in policy:
            insecure.append(f'{ep.EndpointUrl}: {mode}, {policy}')
    
    if insecure:
        print('[!] INSECURE ENDPOINTS FOUND:')
        for i in insecure:
            print(f'    {i}')
    else:
        print('[+] All endpoints require security')
        
except Exception as e:
    print(f'Error: {e}')
" 2>&1
  } | tee "$outfile"
  
  LOG green "Results: $outfile"
}
