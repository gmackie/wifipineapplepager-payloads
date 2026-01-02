#!/bin/bash
set -euo pipefail

# Automated Attack Chains
# Pre-defined attack sequences that combine multiple modules

attack_chains_menu() {
  local choice
  choice=$(menu_pick "Attack Chains" \
    "recon_full:Full Recon Chain" \
    "cred_harvest:Credential Harvesting Chain" \
    "network_pivot:Network Pivot Chain" \
    "ot_assess:OT Assessment Chain" \
    "wireless_pwn:Wireless Pwn Chain" \
    "custom:Custom Chain Builder")
  
  case "$choice" in
    recon_full)    chain_full_recon ;;
    cred_harvest)  chain_cred_harvest ;;
    network_pivot) chain_network_pivot ;;
    ot_assess)     chain_ot_assessment ;;
    wireless_pwn)  chain_wireless_pwn ;;
    custom)        chain_custom_builder ;;
    *)             return 1 ;;
  esac
}

# Full reconnaissance chain
chain_full_recon() {
  LOG blue "=== Full Reconnaissance Chain ==="
  LOG "This chain performs comprehensive network reconnaissance"
  LOG ""
  LOG "Steps:"
  LOG "  1. ARP scan for live hosts"
  LOG "  2. Port scan discovered hosts"
  LOG "  3. Service identification"
  LOG "  4. OT device fingerprinting"
  LOG "  5. SMB enumeration (if port 445 found)"
  LOG "  6. Generate asset inventory"
  LOG ""
  
  CONFIRMATION_DIALOG "Run full recon chain?"
  if [[ $? -ne "$DUCKYSCRIPT_USER_CONFIRMED" ]]; then
    LOG "Chain cancelled"
    return 0
  fi
  
  local chain_log="$ARTIFACT_DIR/chain_recon_$(ts).log"
  
  {
    echo "=== Full Recon Chain Started ==="
    echo "Time: $(date)"
    echo ""
    
    # Step 1: ARP Scan
    echo ">>> Step 1: ARP Scan"
    LOG blue "[1/6] Running ARP scan..."
    if have arp-scan; then
      local iface
      iface=$(ip route | grep default | awk '{print $5}' | head -1)
      arp-scan -I "$iface" --localnet 2>&1 | tee "$ARTIFACT_DIR/chain_arp_$(ts).txt"
    elif have nmap; then
      nmap -sn "$TARGET_NETWORK" 2>&1 | tee "$ARTIFACT_DIR/chain_arp_$(ts).txt"
    fi
    echo ""
    
    # Extract live hosts
    local hosts_file="$ARTIFACT_DIR/chain_hosts.txt"
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$ARTIFACT_DIR/chain_arp_"*.txt 2>/dev/null | sort -u > "$hosts_file" || true
    local host_count
    host_count=$(wc -l < "$hosts_file" 2>/dev/null || echo 0)
    echo "Found $host_count live hosts"
    echo ""
    
    # Step 2: Port Scan
    echo ">>> Step 2: Port Scan"
    LOG blue "[2/6] Port scanning $host_count hosts..."
    if have nmap && [[ "$host_count" -gt 0 ]]; then
      nmap -sS -F -iL "$hosts_file" -oG "$ARTIFACT_DIR/chain_ports_$(ts).gnmap" 2>&1 | tee -a "$chain_log"
    fi
    echo ""
    
    # Step 3: Service ID
    echo ">>> Step 3: Service Identification"
    LOG blue "[3/6] Identifying services..."
    if have nmap && [[ "$host_count" -gt 0 ]]; then
      nmap -sV --version-light -iL "$hosts_file" -oN "$ARTIFACT_DIR/chain_services_$(ts).txt" 2>&1 | head -100
    fi
    echo ""
    
    # Step 4: OT Fingerprinting
    echo ">>> Step 4: OT Device Fingerprinting"
    LOG blue "[4/6] Fingerprinting OT devices..."
    local ot_ports_found
    ot_ports_found=$(grep -E "502/open|44818/open|2222/open|4840/open|102/open" "$ARTIFACT_DIR/chain_ports_"*.gnmap 2>/dev/null | wc -l || echo 0)
    echo "Found $ot_ports_found potential OT services"
    
    # Check MAC OUIs
    if [[ -f "$SCRIPT_DIR/../wordlists/ics-oui.txt" ]]; then
      echo ""
      echo "OT Vendor MACs detected:"
      while read -r line; do
        local oui="${line%%,*}"
        if grep -qi "$oui" "$ARTIFACT_DIR/chain_arp_"*.txt 2>/dev/null; then
          echo "  [+] $line"
        fi
      done < "$SCRIPT_DIR/../wordlists/ics-oui.txt"
    fi
    echo ""
    
    # Step 5: SMB Enumeration
    echo ">>> Step 5: SMB Enumeration"
    LOG blue "[5/6] Enumerating SMB..."
    local smb_hosts
    smb_hosts=$(grep "445/open" "$ARTIFACT_DIR/chain_ports_"*.gnmap 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -5 || true)
    if [[ -n "$smb_hosts" ]]; then
      for host in $smb_hosts; do
        echo "--- SMB: $host ---"
        if have crackmapexec; then
          crackmapexec smb "$host" --shares 2>&1 || true
        elif have smbclient; then
          smbclient -N -L "//$host" 2>&1 || true
        fi
      done
    else
      echo "No SMB hosts found"
    fi
    echo ""
    
    # Step 6: Generate Inventory
    echo ">>> Step 6: Generating Asset Inventory"
    LOG blue "[6/6] Compiling inventory..."
    {
      echo "=== Asset Inventory ==="
      echo "Generated: $(date)"
      echo "Network: $TARGET_NETWORK"
      echo ""
      echo "Live Hosts: $host_count"
      cat "$hosts_file" 2>/dev/null || true
      echo ""
      echo "Open Services:"
      grep "open" "$ARTIFACT_DIR/chain_ports_"*.gnmap 2>/dev/null | head -50 || true
    } > "$ARTIFACT_DIR/chain_inventory_$(ts).txt"
    
    echo ""
    echo "=== Chain Complete ==="
    echo "Duration: Started at $(head -2 "$chain_log" | tail -1)"
    echo "Artifacts saved to: $ARTIFACT_DIR/chain_*"
    
  } 2>&1 | tee -a "$chain_log"
  
  LOG green "Full recon chain complete!"
  LOG "Log: $chain_log"
}

# Credential harvesting chain
chain_cred_harvest() {
  LOG blue "=== Credential Harvesting Chain ==="
  LOG "This chain attempts passive and active credential capture"
  LOG ""
  LOG "Steps:"
  LOG "  1. Default credential check (OT devices)"
  LOG "  2. SNMP community enumeration"
  LOG "  3. SMB null session check"
  LOG "  4. Start Responder (if laptop mode)"
  LOG "  5. Monitor for captured hashes"
  LOG ""
  
  if ! confirm_danger "Run credential harvesting chain?"; then
    return 0
  fi
  
  local chain_log="$ARTIFACT_DIR/chain_creds_$(ts).log"
  
  {
    echo "=== Credential Harvesting Chain ==="
    echo "Time: $(date)"
    echo ""
    
    # Step 1: Default creds
    echo ">>> Step 1: Default Credential Check"
    LOG blue "[1/5] Checking default credentials..."
    # Run against known hosts with OT ports
    if [[ -f "$SCRIPT_DIR/../wordlists/ot-defaults.csv" ]]; then
      local target_count=0
      while read -r host; do
        if [[ "$target_count" -ge 10 ]]; then
          echo "(limiting to 10 hosts)"
          break
        fi
        echo "Checking: $host"
        # Check common protocols
        for port in 80 443 23 22; do
          if nc -z -w1 "$host" "$port" 2>/dev/null; then
            echo "  Port $port open - check manually"
          fi
        done
        ((target_count++)) || true
      done < <(cat "$ARTIFACT_DIR"/*hosts*.txt 2>/dev/null | sort -u | head -20)
    fi
    echo ""
    
    # Step 2: SNMP enumeration
    echo ">>> Step 2: SNMP Community Enumeration"
    LOG blue "[2/5] Enumerating SNMP..."
    if have snmpwalk && [[ -f "$SCRIPT_DIR/../wordlists/snmp-communities.txt" ]]; then
      while read -r host; do
        while read -r community; do
          local result
          result=$(snmpwalk -v2c -c "$community" "$host" system.sysDescr.0 2>/dev/null | head -1 || true)
          if [[ -n "$result" ]]; then
            echo "[+] $host: community '$community' works"
            echo "    $result"
          fi
        done < "$SCRIPT_DIR/../wordlists/snmp-communities.txt"
      done < <(cat "$ARTIFACT_DIR"/*hosts*.txt 2>/dev/null | sort -u | head -10)
    else
      echo "snmpwalk not available or no hosts file"
    fi
    echo ""
    
    # Step 3: SMB null session
    echo ">>> Step 3: SMB Null Session Check"
    LOG blue "[3/5] Testing null sessions..."
    while read -r host; do
      echo -n "$host: "
      if have smbclient; then
        if smbclient -N -L "//$host" 2>&1 | grep -q "Sharename"; then
          echo "NULL SESSION ALLOWED"
        else
          echo "blocked"
        fi
      fi
    done < <(cat "$ARTIFACT_DIR"/*hosts*.txt 2>/dev/null | sort -u | head -10)
    echo ""
    
    # Step 4: Responder
    echo ">>> Step 4: Responder"
    LOG blue "[4/5] Checking Responder availability..."
    if [[ "$LAPTOP_ENABLED" -eq 1 ]]; then
      if laptop_exec "which responder" 2>/dev/null; then
        echo "Responder available on laptop"
        echo "To start: responder -I <interface> -wrf"
        echo ""
        CONFIRMATION_DIALOG "Start Responder on laptop?"
        if [[ $? -eq "$DUCKYSCRIPT_USER_CONFIRMED" ]]; then
          local iface
          iface=$(laptop_exec "ip route | grep default | awk '{print \$5}' | head -1")
          LOG "Starting Responder on $iface..."
          laptop_exec "cd /tmp && nohup responder -I '$iface' -wrf > responder.log 2>&1 &" || true
          echo "Responder started in background"
        fi
      else
        echo "Responder not found on laptop"
      fi
    else
      echo "Laptop mode not enabled"
    fi
    echo ""
    
    # Step 5: Summary
    echo ">>> Step 5: Summary"
    LOG blue "[5/5] Generating summary..."
    {
      echo "=== Credential Harvest Summary ==="
      echo "Time: $(date)"
      echo ""
      echo "Findings:"
      grep -rh "\[+\]" "$ARTIFACT_DIR"/chain_creds_*.log 2>/dev/null || echo "  (none captured yet)"
    } | tee "$ARTIFACT_DIR/chain_creds_summary_$(ts).txt"
    
  } 2>&1 | tee "$chain_log"
  
  LOG green "Credential harvesting chain complete!"
}

# OT Assessment chain
chain_ot_assessment() {
  LOG blue "=== OT Assessment Chain ==="
  LOG "Comprehensive OT/ICS security assessment"
  LOG ""
  LOG "Steps:"
  LOG "  1. OT device discovery (MAC OUI + ports)"
  LOG "  2. Protocol identification"
  LOG "  3. Device enumeration per protocol"
  LOG "  4. Default credential check"
  LOG "  5. Generate OT asset report"
  LOG ""
  
  if ! confirm_danger "Run OT assessment chain?"; then
    return 0
  fi
  
  local chain_log="$ARTIFACT_DIR/chain_ot_$(ts).log"
  
  {
    echo "=== OT Assessment Chain ==="
    echo "Time: $(date)"
    echo "Network: $TARGET_NETWORK"
    echo ""
    
    # Step 1: Discovery
    echo ">>> Step 1: OT Device Discovery"
    LOG blue "[1/5] Discovering OT devices..."
    
    # Scan for OT ports
    local ot_ports="102,502,1089,1090,1091,2222,4840,4843,20000,34962,34963,34964,44818,47808,55000,55001,55002,55003"
    if have nmap; then
      nmap -sS -p"$ot_ports" "$TARGET_NETWORK" -oG "$ARTIFACT_DIR/chain_ot_ports_$(ts).gnmap" 2>&1 | tee -a "$chain_log"
    fi
    echo ""
    
    # Step 2: Protocol ID
    echo ">>> Step 2: Protocol Identification"
    LOG blue "[2/5] Identifying protocols..."
    
    local protocols_found=""
    if grep -q "502/open" "$ARTIFACT_DIR/chain_ot_ports_"*.gnmap 2>/dev/null; then
      protocols_found="$protocols_found Modbus"
    fi
    if grep -q "44818/open" "$ARTIFACT_DIR/chain_ot_ports_"*.gnmap 2>/dev/null; then
      protocols_found="$protocols_found EtherNet/IP"
    fi
    if grep -q "4840/open\|4843/open" "$ARTIFACT_DIR/chain_ot_ports_"*.gnmap 2>/dev/null; then
      protocols_found="$protocols_found OPC-UA"
    fi
    if grep -q "102/open" "$ARTIFACT_DIR/chain_ot_ports_"*.gnmap 2>/dev/null; then
      protocols_found="$protocols_found S7comm"
    fi
    if grep -q "47808/open" "$ARTIFACT_DIR/chain_ot_ports_"*.gnmap 2>/dev/null; then
      protocols_found="$protocols_found BACnet"
    fi
    if grep -q "20000/open" "$ARTIFACT_DIR/chain_ot_ports_"*.gnmap 2>/dev/null; then
      protocols_found="$protocols_found DNP3"
    fi
    
    echo "Protocols found:$protocols_found"
    echo ""
    
    # Step 3: Device Enumeration
    echo ">>> Step 3: Device Enumeration"
    LOG blue "[3/5] Enumerating devices..."
    
    # Modbus
    if echo "$protocols_found" | grep -q "Modbus"; then
      echo "--- Modbus Devices ---"
      for host in $(grep "502/open" "$ARTIFACT_DIR/chain_ot_ports_"*.gnmap 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'); do
        echo "Device: $host"
        if have mbpoll; then
          mbpoll -a 1 -t 3 -r 1 -c 1 "$host" 2>&1 | head -5 || true
        fi
      done
    fi
    
    # EtherNet/IP
    if echo "$protocols_found" | grep -q "EtherNet/IP"; then
      echo "--- EtherNet/IP Devices ---"
      for host in $(grep "44818/open" "$ARTIFACT_DIR/chain_ot_ports_"*.gnmap 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'); do
        echo "Device: $host"
        # Would use pycomm3 here
      done
    fi
    echo ""
    
    # Step 4: Default Creds
    echo ">>> Step 4: Default Credential Check"
    LOG blue "[4/5] Checking default credentials..."
    
    if [[ -f "$SCRIPT_DIR/../wordlists/ot-defaults.csv" ]]; then
      echo "OT default credential database loaded"
      echo "Vendors covered:"
      cut -d, -f1 "$SCRIPT_DIR/../wordlists/ot-defaults.csv" | sort -u | head -10
    fi
    echo ""
    
    # Step 5: Report
    echo ">>> Step 5: OT Asset Report"
    LOG blue "[5/5] Generating report..."
    
    {
      echo "=== OT Security Assessment Report ==="
      echo "Date: $(date)"
      echo "Assessor: Red Team Toolkit"
      echo "Scope: $TARGET_NETWORK"
      echo ""
      echo "== Executive Summary =="
      echo "Protocols Discovered:$protocols_found"
      local device_count
      device_count=$(grep -c "open" "$ARTIFACT_DIR/chain_ot_ports_"*.gnmap 2>/dev/null || echo 0)
      echo "OT Devices Found: $device_count"
      echo ""
      echo "== Detailed Findings =="
      cat "$ARTIFACT_DIR/chain_ot_ports_"*.gnmap 2>/dev/null || true
      echo ""
      echo "== Recommendations =="
      echo "1. Segment OT network from IT network"
      echo "2. Implement protocol-aware firewalls"
      echo "3. Change default credentials"
      echo "4. Enable logging and monitoring"
      echo "5. Implement change management"
    } > "$ARTIFACT_DIR/ot_assessment_report_$(ts).txt"
    
    echo "Report saved to: $ARTIFACT_DIR/ot_assessment_report_$(ts).txt"
    
  } 2>&1 | tee "$chain_log"
  
  LOG green "OT assessment chain complete!"
}

# Wireless attack chain
chain_wireless_pwn() {
  LOG blue "=== Wireless Pwn Chain ==="
  LOG "Full wireless attack sequence"
  LOG ""
  LOG "Steps:"
  LOG "  1. Passive reconnaissance"
  LOG "  2. Target selection"
  LOG "  3. Handshake capture"
  LOG "  4. Deauth (if needed)"
  LOG "  5. Crack attempt"
  LOG ""
  
  if ! confirm_danger "Run wireless attack chain?"; then
    return 0
  fi
  
  LOG "This chain requires manual interaction"
  LOG "Use the Wireless menu modules individually"
  LOG ""
  LOG "Recommended sequence:"
  LOG "  1. Wireless > Passive Recon (identify targets)"
  LOG "  2. Wireless > Handshake Capture (wait for client or use deauth)"
  LOG "  3. Wireless > WPA Crack (if handshake captured)"
  LOG ""
  
  PROMPT "Press any button to continue to Wireless menu"
}

# Network pivot chain
chain_network_pivot() {
  LOG blue "=== Network Pivot Chain ==="
  LOG "Establish network position for lateral movement"
  LOG ""
  LOG "Steps:"
  LOG "  1. ARP scan local segment"
  LOG "  2. Identify gateway/VLAN"
  LOG "  3. Check for routing"
  LOG "  4. Identify pivot targets"
  LOG "  5. Set up port forwarding"
  LOG ""
  
  if ! confirm_danger "Run network pivot chain?"; then
    return 0
  fi
  
  local chain_log="$ARTIFACT_DIR/chain_pivot_$(ts).log"
  
  {
    echo "=== Network Pivot Chain ==="
    echo "Time: $(date)"
    echo ""
    
    # Step 1: Local network
    echo ">>> Step 1: Local Network Analysis"
    LOG blue "[1/5] Analyzing local network..."
    echo "--- Interfaces ---"
    ip addr 2>/dev/null || ifconfig 2>/dev/null || true
    echo ""
    echo "--- Routes ---"
    ip route 2>/dev/null || netstat -rn 2>/dev/null || true
    echo ""
    echo "--- ARP Table ---"
    ip neigh 2>/dev/null || arp -a 2>/dev/null || true
    echo ""
    
    # Step 2: Gateway/VLAN
    echo ">>> Step 2: Gateway Analysis"
    LOG blue "[2/5] Identifying gateways..."
    local gw
    gw=$(ip route | grep default | awk '{print $3}' | head -1)
    echo "Default Gateway: $gw"
    if [[ -n "$gw" ]]; then
      echo "Gateway reachable: $(ping -c1 -W1 "$gw" 2>/dev/null && echo "yes" || echo "no")"
    fi
    echo ""
    
    # Step 3: Routing check
    echo ">>> Step 3: Routing Check"
    LOG blue "[3/5] Checking routing..."
    echo "Checking access to common internal ranges:"
    for range in "10.0.0.1" "172.16.0.1" "192.168.0.1" "192.168.1.1"; do
      echo -n "  $range: "
      if ping -c1 -W1 "$range" 2>/dev/null | grep -q "1 received"; then
        echo "reachable"
      else
        echo "unreachable"
      fi
    done
    echo ""
    
    # Step 4: Pivot targets
    echo ">>> Step 4: Pivot Targets"
    LOG blue "[4/5] Identifying pivot targets..."
    echo "Hosts with management ports:"
    if have nmap; then
      nmap -sS -p22,3389,5985,5986 --open "$TARGET_NETWORK" 2>&1 | grep -E "^Nmap|open" || true
    fi
    echo ""
    
    # Step 5: Port forwarding
    echo ">>> Step 5: Port Forwarding Options"
    LOG blue "[5/5] Port forwarding setup..."
    echo "Available methods:"
    if have socat; then echo "  - socat (available)"; fi
    if have ssh; then echo "  - SSH tunneling (available)"; fi
    if have chisel; then echo "  - Chisel (available)"; fi
    echo ""
    echo "Example: socat TCP-LISTEN:8080,fork TCP:<target>:80"
    echo "Example: ssh -L 8080:<target>:80 user@jumphost"
    
  } 2>&1 | tee "$chain_log"
  
  LOG green "Network pivot chain complete!"
}

# Custom chain builder
chain_custom_builder() {
  LOG blue "=== Custom Chain Builder ==="
  LOG "Build your own attack sequence"
  LOG ""
  
  local steps=()
  local step_count=0
  
  while true; do
    local choice
    choice=$(menu_pick "Add Step (${#steps[@]} added)" \
      "arp_scan:ARP Scan" \
      "port_scan:Port Scan" \
      "service_id:Service ID" \
      "smb_enum:SMB Enum" \
      "web_scan:Web Scan" \
      "snmp_enum:SNMP Enum" \
      "run:>> Run Chain <<" \
      "cancel:Cancel")
    
    case "$choice" in
      run)
        if [[ ${#steps[@]} -eq 0 ]]; then
          LOG "No steps added"
          continue
        fi
        break
        ;;
      cancel)
        return 0
        ;;
      *)
        steps+=("$choice")
        LOG "Added: $choice (${#steps[@]} steps total)"
        ;;
    esac
  done
  
  LOG blue "Running custom chain with ${#steps[@]} steps..."
  
  local chain_log="$ARTIFACT_DIR/chain_custom_$(ts).log"
  
  {
    echo "=== Custom Chain ==="
    echo "Steps: ${steps[*]}"
    echo "Time: $(date)"
    echo ""
    
    local step_num=0
    for step in "${steps[@]}"; do
      ((step_num++))
      echo ">>> Step $step_num: $step"
      LOG blue "[$step_num/${#steps[@]}] Running $step..."
      
      case "$step" in
        arp_scan)
          if have arp-scan; then
            local iface
            iface=$(ip route | grep default | awk '{print $5}' | head -1)
            arp-scan -I "$iface" --localnet 2>&1 || true
          elif have nmap; then
            nmap -sn "$TARGET_NETWORK" 2>&1 || true
          fi
          ;;
        port_scan)
          if have nmap; then
            nmap -sS -F "$TARGET_NETWORK" 2>&1 || true
          fi
          ;;
        service_id)
          if have nmap; then
            nmap -sV --version-light "$TARGET_NETWORK" 2>&1 | head -50 || true
          fi
          ;;
        smb_enum)
          if have crackmapexec; then
            crackmapexec smb "$TARGET_NETWORK" --shares 2>&1 || true
          fi
          ;;
        web_scan)
          echo "Web scan requires target URL - skipping in chain"
          ;;
        snmp_enum)
          if have snmpwalk; then
            for host in $(cat "$ARTIFACT_DIR"/*hosts*.txt 2>/dev/null | head -5); do
              snmpwalk -v2c -c public "$host" system.sysDescr.0 2>/dev/null || true
            done
          fi
          ;;
      esac
      echo ""
    done
    
    echo "=== Chain Complete ==="
  } 2>&1 | tee "$chain_log"
  
  LOG green "Custom chain complete!"
  LOG "Log: $chain_log"
}
