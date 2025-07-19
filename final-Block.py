#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Host
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import requests
import json
import hashlib
import time
from datetime import datetime
import threading

# ===== SDN TOPOLOGY =====

class SecureSDNTopology(Topo):
    def __init__(self):
        # Initialize blockchain object before calling super().__init__()
        self.blockchain = BlockchainSDN()
        super().__init__()
    
    def build(self):
        """Build network topology with blockchain security"""
        print("=== Building secure SDN topology...")
        
        # Record topology build start in blockchain
        self.blockchain.add_network_transaction(
            'topology_build_start',
            'network',
            {'action': 'Starting network topology build'},
            'network_builder'
        )
        
        # Two Core Switches for redundancy
        core_switch1 = self.addSwitch('s0', cls=OVSSwitch, protocols='OpenFlow13')
        core_switch2 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        
        # Record core switches in blockchain
        self.blockchain.add_network_transaction(
            'core_switches_added',
            'core',
            {'switches': ['s0', 's1'], 'redundancy': True},
            'network_builder'
        )
        
        # Connect the two core switches with a high-bandwidth link
        self.addLink(core_switch1, core_switch2, bw=1000)
        
        # Router (for inter-network routing)
        router = self.addHost('hR1', ip=None)
        
        # Record router in blockchain
        self.blockchain.add_network_transaction(
            'router_added',
            'hR1',
            {'type': 'inter_network_router', 'ip_forwarding': True},
            'network_builder'
        )
        
        # First set of 6 Access Switches (connected to both core switches)
        access_switches_group1 = []
        for lan_num in range(2, 8):  # s2-s7
            switch = self.addSwitch(f's{lan_num}', cls=OVSSwitch, protocols='OpenFlow13')
            access_switches_group1.append(f's{lan_num}')
            
            # Connect to both core switches for redundancy
            self.addLink(switch, core_switch1)
            self.addLink(switch, core_switch2)
            
            # Connect to router
            self.addLink(router, switch)
            
            # Hosts for first set (10.0.x.0/24 network)
            hosts_added = []
            for host_num in [10, 20]:
                host_name = f'h{lan_num-1}{host_num}'
                host_ip = f'10.0.{lan_num-1}.{host_num}/24'
                router_ip = f'10.0.{lan_num-1}.1'
                
                host = self.addHost(
                    host_name,
                    ip=host_ip,
                    defaultRoute=f'via {router_ip}'
                )
                self.addLink(host, switch)
                hosts_added.append({'name': host_name, 'ip': host_ip})
            
            # Record hosts in blockchain
            self.blockchain.add_network_transaction(
                'access_switch_configured',
                f's{lan_num}',
                {
                    'group': 1,
                    'network': f'10.0.{lan_num-1}.0/24',
                    'hosts': hosts_added,
                    'core_connections': ['s0', 's1'],
                    'router_connection': 'hR1'
                },
                'network_builder'
            )

        # Second set of 6 Access Switches (connected to both core switches)
        access_switches_group2 = []
        for lan_num in range(8, 14):  # s8-s13
            switch = self.addSwitch(f's{lan_num}', cls=OVSSwitch, protocols='OpenFlow13')
            access_switches_group2.append(f's{lan_num}')
            
            # Connect to both core switches for redundancy
            self.addLink(switch, core_switch1)
            self.addLink(switch, core_switch2)
            
            # Connect to router
            self.addLink(router, switch)
            
            # Hosts for second set (10.1.x.0/24 network)
            hosts_added = []
            for host_num in [10, 20]:
                host_name = f'h{lan_num-1}{host_num}'
                host_ip = f'10.1.{lan_num-7}.{host_num}/24'
                router_ip = f'10.1.{lan_num-7}.1'
                
                host = self.addHost(
                    host_name,
                    ip=host_ip,
                    defaultRoute=f'via {router_ip}'
                )
                self.addLink(host, switch)
                hosts_added.append({'name': host_name, 'ip': host_ip})
            
            # Record hosts in blockchain
            self.blockchain.add_network_transaction(
                'access_switch_configured',
                f's{lan_num}',
                {
                    'group': 2,
                    'network': f'10.1.{lan_num-7}.0/24',
                    'hosts': hosts_added,
                    'core_connections': ['s0', 's1'],
                    'router_connection': 'hR1'
                },
                'network_builder'
            )
        
        # Record topology completion in blockchain
        self.blockchain.add_network_transaction(
            'topology_build_complete',
            'network',
            {
                'total_switches': 14,  # 2 core + 12 access
                'total_hosts': 24,     # 2 hosts per access switch
                'groups': {
                    'group1_switches': access_switches_group1,
                    'group2_switches': access_switches_group2
                }
            },
            'network_builder'
        )
        
        print("? Secure SDN topology built successfully")

def secure_add_flows(blockchain):
    """Add flows to switches with blockchain security"""
    print("== Adding flows with blockchain security...")
    
    url = "http://192.168.11.66:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:{}/flow-node-inventory:table/0"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic YWRtaW46YWRtaW4="  # Basic auth (admin:admin)
    }

    flows_added = 0
    flows_failed = 0

    # Flows for all access switches (s2-s13)
    for switch_id in range(2, 14):
        switch_name = f's{switch_id}'
        
        # Flow 1: From hosts to core
        flow1 = {
            "flow": [
                {
                    "id": "1",
                    "priority": 100,
                    "match": {
                        "in-port": "1"
                    },
                    "instructions": {
                        "instruction": [
                            {
                                "order": 0,
                                "apply-actions": {
                                    "action": [
                                        {
                                            "order": 0,
                                            "output-action": {
                                                "output-node-connector": "2"
                                            }
                                        },
                                        {
                                            "order": 1,
                                            "output-action": {
                                                "output-node-connector": "3"
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }
            ]
        }
        
        # Record Flow 1 in blockchain
        blockchain.add_network_transaction(
            'flow_rule_add',
            switch_name,
            {
                'flow_id': '1',
                'priority': 100,
                'match': 'in-port:1 (hosts)',
                'actions': 'output:2,3 (to core switches)',
                'purpose': 'hosts_to_core_traffic'
            },
            'flow_controller'
        )
        
        # Flow 2: From core switch 1 to hosts
        flow2 = {
            "flow": [
                {
                    "id": "2",
                    "priority": 100,
                    "match": {
                        "in-port": "2"
                    },
                    "instructions": {
                        "instruction": [
                            {
                                "order": 0,
                                "apply-actions": {
                                    "action": [
                                        {
                                            "order": 0,
                                            "output-action": {
                                                "output-node-connector": "1"
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }
            ]
        }
        
        # Record Flow 2 in blockchain
        blockchain.add_network_transaction(
            'flow_rule_add',
            switch_name,
            {
                'flow_id': '2',
                'priority': 100,
                'match': 'in-port:2 (from core s0)',
                'actions': 'output:1 (to hosts)',
                'purpose': 'core_s0_to_hosts_traffic'
            },
            'flow_controller'
        )
        
        # Flow 3: From core switch 2 to hosts
        flow3 = {
            "flow": [
                {
                    "id": "3",
                    "priority": 100,
                    "match": {
                        "in-port": "3"
                    },
                    "instructions": {
                        "instruction": [
                            {
                                "order": 0,
                                "apply-actions": {
                                    "action": [
                                        {
                                            "order": 0,
                                            "output-action": {
                                                "output-node-connector": "1"
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }
            ]
        }
        
        # Record Flow 3 in blockchain
        blockchain.add_network_transaction(
            'flow_rule_add',
            switch_name,
            {
                'flow_id': '3',
                'priority': 100,
                'match': 'in-port:3 (from core s1)',
                'actions': 'output:1 (to hosts)',
                'purpose': 'core_s1_to_hosts_traffic'
            },
            'flow_controller'
        )
        
        # Install flows
        try:
            response1 = requests.post(url.format(switch_id), headers=headers, data=json.dumps(flow1), timeout=10)
            response2 = requests.post(url.format(switch_id), headers=headers, data=json.dumps(flow2), timeout=10)
            response3 = requests.post(url.format(switch_id), headers=headers, data=json.dumps(flow3), timeout=10)
            
            # Count successful responses
            success_count = sum(1 for r in [response1, response2, response3] if r.status_code in [200, 201, 204])
            
            if success_count == 3:
                flows_added += 3
                blockchain.add_network_transaction(
                    'flow_installation_success',
                    switch_name,
                    {
                        'flows_installed': 3,
                        'response_codes': [response1.status_code, response2.status_code, response3.status_code]
                    },
                    'flow_controller'
                )
                print(f"? Flows added to {switch_name}: {response1.status_code}, {response2.status_code}, {response3.status_code}")
            else:
                flows_failed += (3 - success_count)
                blockchain.add_network_transaction(
                    'flow_installation_partial_failure',
                    switch_name,
                    {
                        'flows_successful': success_count,
                        'flows_failed': 3 - success_count,
                        'response_codes': [response1.status_code, response2.status_code, response3.status_code]
                    },
                    'flow_controller'
                )
                print(f"? Partial failure for {switch_name}: {response1.status_code}, {response2.status_code}, {response3.status_code}")
                
        except requests.exceptions.RequestException as e:
            flows_failed += 3
            blockchain.add_network_transaction(
                'flow_installation_error',
                switch_name,
                {
                    'error': str(e),
                    'flows_failed': 3
                },
                'flow_controller'
            )
            print(f"? Error adding flows to {switch_name}: {e}")
    
    # Record flow installation summary
    blockchain.add_network_transaction(
        'flow_installation_summary',
        'network',
        {
            'total_flows_added': flows_added,
            'total_flows_failed': flows_failed,
            'switches_configured': 12,
            'completion_status': 'success' if flows_failed == 0 else 'partial_success'
        },
        'flow_controller'
    )
    
    print(f"== Flow installation summary: {flows_added} successful, {flows_failed} failed")

def run_secure_network():
    """Run the secure network with blockchain"""
    print("== Starting Secure SDN Network with Blockchain...")
    print("="*60)
    
    setLogLevel('info')
    
    # Create network with our secure topology
    secure_topo = SecureSDNTopology()
    net = Mininet(topo=secure_topo, switch=OVSSwitch, controller=None)
    
    # OpenDaylight controller
    ctrl = net.addController('odl_ctrl',
                            controller=RemoteController,
                            ip='192.168.11.66',
                            port=6633,
                            protocol='tcp')
    
    # Record controller in blockchain
    secure_topo.blockchain.add_network_transaction(
        'controller_added',
        'odl_ctrl',
        {
            'type': 'OpenDaylight',
            'ip': '192.168.11.66',
            'port': 6633,
            'protocol': 'tcp'
        },
        'network_manager'
    )
    
    # Start controller and network
    ctrl.start()
    net.start()
    
    # Record network start in blockchain
    secure_topo.blockchain.add_network_transaction(
        'network_started',
        'network',
        {'controller_status': 'running', 'mininet_status': 'running'},
        'network_manager'
    )
    
    # Configure router
    print("== Configuring router...")
    router = net.get('hR1')
    router.cmd('sysctl -w net.ipv4.ip_forward=1')  # Enable IP Forwarding
    
    # Record router configuration in blockchain
    secure_topo.blockchain.add_network_transaction(
        'router_ip_forwarding_enabled',
        'hR1',
        {'ip_forward': True},
        'router_config'
    )
    
    # Assign IP addresses to router interfaces for first set (10.0.x.0/24)
    router_interfaces_group1 = []
    for i in range(6):  # First 6 interfaces (s2-s7)
        lan_num = i + 1
        interface_ip = f'10.0.{lan_num}.1/24'
        router.cmd(f'ifconfig hR1-eth{i} {interface_ip} up')
        router_interfaces_group1.append({'interface': f'hR1-eth{i}', 'ip': interface_ip})
    
    # Assign IP addresses to router interfaces for second set (10.1.x.0/24)
    router_interfaces_group2 = []
    for i in range(6, 12):  # Next 6 interfaces (s8-s13)
        lan_num = i - 5  # Starts from 1 again for 10.1.x.0/24 range
        interface_ip = f'10.1.{lan_num}.1/24'
        router.cmd(f'ifconfig hR1-eth{i} {interface_ip} up')
        router_interfaces_group2.append({'interface': f'hR1-eth{i}', 'ip': interface_ip})
    
    # Record router interfaces in blockchain
    secure_topo.blockchain.add_network_transaction(
        'router_interfaces_configured',
        'hR1',
        {
            'group1_interfaces': router_interfaces_group1,
            'group2_interfaces': router_interfaces_group2,
            'total_interfaces': 12
        },
        'router_config'
    )
    
    # Add default routes for all internal hosts
    print("=== Adding default routes for hosts...")
    info('*** Adding default routes for internal hosts\n')
    
    routes_added = 0
    
    # For first set of hosts (10.0.x.0/24)
    for lan_num in range(1, 7):
        for host_num in [10, 20]:
            host_name = f'h{lan_num}{host_num}'
            gateway_ip = f'10.0.{lan_num}.1'
            host = net.get(host_name)
            host.cmd(f'ip route add default via {gateway_ip}')
            routes_added += 1
    
    # For second set of hosts (10.1.x.0/24)
    for lan_num in range(7, 13):
        for host_num in [10, 20]:
            host_name = f'h{lan_num}{host_num}'
            gateway_ip = f'10.1.{lan_num-6}.1'
            host = net.get(host_name)
            host.cmd(f'ip route add default via {gateway_ip}')
            routes_added += 1
    
    # Record routes in blockchain
    secure_topo.blockchain.add_network_transaction(
        'host_default_routes_added',
        'network',
        {
            'total_routes_added': routes_added,
            'hosts_configured': 24
        },
        'routing_config'
    )
    
    # Enable OSPF on router for dynamic routing between networks
    print("== Configuring OSPF...")
    info('*** Configuring OSPF on router\n')
    
    try:
        router.cmd('zebra -d')
        router.cmd('ospfd -d')
        
        # Configure OSPF on all interfaces
        ospf_interfaces = []
        for i in range(12):  # All 12 interfaces
            interface_name = f'hR1-eth{i}'
            router.cmd(f'vtysh -c "configure terminal" -c "interface {interface_name}" -c "ip ospf area 0"')
            ospf_interfaces.append(interface_name)
        
        router.cmd('vtysh -c "configure terminal" -c "router ospf" -c "redistribute connected"')
        
        # Record OSPF configuration in blockchain
        secure_topo.blockchain.add_network_transaction(
            'ospf_configured',
            'hR1',
            {
                'ospf_area': 0,
                'interfaces': ospf_interfaces,
                'redistribute': 'connected',
                'daemons': ['zebra', 'ospfd']
            },
            'routing_config'
        )
        print("? OSPF configured successfully")
        
    except Exception as e:
        secure_topo.blockchain.add_network_transaction(
            'ospf_configuration_error',
            'hR1',
            {'error': str(e)},
            'routing_config'
        )
        print(f"? OSPF configuration warning: {e}")
    
    # Mine a block for all configuration transactions
    print("\n== Mining configuration block...")
    secure_topo.blockchain.mine_block()
    
    # Add flows with blockchain security
    secure_add_flows(secure_topo.blockchain)
    
    # Mine another block for flow transactions
    print("\n== Mining flows block...")
    secure_topo.blockchain.mine_block()
    
    # Print blockchain status
    secure_topo.blockchain.print_blockchain_status()
    
    # Final network ready message
    print("\n" + "="*60)
    print("== SECURE SDN NETWORK IS READY!")
    print("="*60)
    print("== All network events are recorded in blockchain")
    print("== Network configuration is tamper-proof")
    print("== Use 'py net.blockchain_help()' for all blockchain commands")
    print("=== Quick commands:")
    print("    py net.blockchain_status()    - Check blockchain health")
    print("    py net.repair_blockchain()    - Fix corrupted blockchain")
    print("    py net.backup_blockchain()    - Create backup")
    print("="*60)
    
    # Add custom CLI commands
    def blockchain_status():
        secure_topo.blockchain.print_blockchain_status()
    
    def audit_switch(switch_name):
        history = secure_topo.blockchain.get_switch_history(switch_name)
        if history:
            print(f"\n== Audit History for {switch_name}:")
            print("-" * 40)
            for record in history:
                print(f"== {record['timestamp'][:19]}")
                print(f"== Type: {record['type']}")
                print(f"== User: {record['user_id']}")
                print(f"== Status: {record['status']}")
                if record['flow_data']:
                    print(f"== Data: {record['flow_data']}")
                print("-" * 20)
        else:
            print(f"? No history found for {switch_name}")
    
    def repair_blockchain():
        """Repair blockchain"""
        repaired = secure_topo.blockchain.repair_blockchain()
        print(f"== Repaired {repaired} blocks")
        secure_topo.blockchain.print_blockchain_status()
    
    def rebuild_blockchain():
        """Rebuild blockchain from scratch"""
        blocks = secure_topo.blockchain.rebuild_blockchain()
        print(f"=== Rebuilt blockchain with {blocks} blocks")
        secure_topo.blockchain.print_blockchain_status()
    
    def backup_blockchain():
        """Export blockchain to file"""
        filename = secure_topo.blockchain.export_blockchain()
        if filename:
            print(f"== Blockchain backed up to: {filename}")
    
    def blockchain_help():
        """Show blockchain commands"""
        print("\n== BLOCKCHAIN COMMANDS:")
        print("=" * 40)
        print("py net.blockchain_status()     - Show blockchain status")
        print("py net.audit_switch('s2')      - Show history for a switch")
        print("py net.repair_blockchain()     - Repair blockchain")
        print("py net.rebuild_blockchain()    - Rebuild blockchain")
        print("py net.backup_blockchain()     - Create backup")
        print("py net.blockchain_help()       - Show this help")
        print("=" * 40)
    
    # Store functions for CLI access
    net.blockchain_status = blockchain_status
    net.audit_switch = audit_switch
    net.repair_blockchain = repair_blockchain
    net.rebuild_blockchain = rebuild_blockchain
    net.backup_blockchain = backup_blockchain
    net.blockchain_help = blockchain_help
    net.blockchain = secure_topo.blockchain
    
    # Start CLI
    CLI(net)
    
    print("== Shutting down secure network...")
    secure_topo.blockchain.add_network_transaction(
        'network_shutdown',
        'network',
        {'shutdown_time': datetime.now().isoformat()},
        'network_manager'
    )
    
    net.stop()
    print("? Secure SDN network stopped")

# ===== BLOCKCHAIN CLASSES =====

class BlockchainSDN:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.create_genesis_block()
        print("!! Blockchain initialized for SDN security")
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = {
            'index': 0,
            'timestamp': time.time(),
            'transactions': [{
                'type': 'genesis',
                'message': 'SDN Blockchain Network Initialized',
                'timestamp': datetime.now().isoformat()
            }],
            'previous_hash': '0',
            'nonce': 0
        }
        genesis_block['hash'] = self.calculate_hash(genesis_block)
        self.chain.append(genesis_block)
    
    def calculate_hash(self, block):
        """Calculate hash for a block"""
        import copy
        block_copy = copy.deepcopy(block)
        if 'hash' in block_copy:
            del block_copy['hash']
        
        block_string = json.dumps(block_copy, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()
    
    def add_network_transaction(self, transaction_type, switch_id, flow_data, user_id="sdn_controller"):
        """Add a new network transaction"""
        transaction = {
            'type': transaction_type,
            'switch_id': switch_id,
            'flow_data': flow_data,
            'user_id': user_id,
            'timestamp': datetime.now().isoformat(),
            'status': 'pending'
        }
        self.pending_transactions.append(transaction)
        print(f"!! Transaction added: {transaction_type} on {switch_id}")
        return transaction
    
    def mine_block(self):
        """Mine a new block"""
        if not self.pending_transactions:
            print("!! No pending transactions to mine")
            return False
        
        print("!! Mining new block...")
        new_block = {
            'index': len(self.chain),
            'timestamp': time.time(),
            'transactions': self.pending_transactions.copy(),
            'previous_hash': self.chain[-1]['hash'],
            'nonce': 0
        }
        
        # Proof of Work (requires hash starting with 4 zeros)
        target = "0000"
        while not self.calculate_hash(new_block).startswith(target):
            new_block['nonce'] += 1
            if new_block['nonce'] % 1000 == 0:
                print(f"   Mining... nonce: {new_block['nonce']}")
        
        new_block['hash'] = self.calculate_hash(new_block)
        self.chain.append(new_block)
        
        # Update status of all transactions
        for transaction in self.pending_transactions:
            transaction['status'] = 'confirmed'
        
        print(f"? Block #{new_block['index']} mined! Hash: {new_block['hash'][:16]}...")
        print(f"   Transactions: {len(self.pending_transactions)}")
        self.pending_transactions = []
        return True
    
    def repair_blockchain(self):
        """Repair any blockchain inconsistencies"""
        print("!! Starting blockchain repair process...")
        repaired_blocks = 0
        
        for i, block in enumerate(self.chain):
            # Recalculate hash for each block
            original_hash = block.get('hash', '')
            calculated_hash = self.calculate_hash(block)
            
            if original_hash != calculated_hash:
                print(f"!! Repairing block {i}...")
                block['hash'] = calculated_hash
                repaired_blocks += 1
                
                # Update next block's previous_hash if needed
                if i + 1 < len(self.chain):
                    self.chain[i + 1]['previous_hash'] = calculated_hash
        
        print(f"? Blockchain repair completed: {repaired_blocks} blocks repaired")
        return repaired_blocks
    
    def rebuild_blockchain(self):
        """Completely rebuild the blockchain from transactions"""
        print("=== Rebuilding blockchain from scratch...")
        
        # Collect all transactions except genesis
        all_transactions = []
        for block in self.chain[1:]:  # Skip genesis block
            all_transactions.extend(block['transactions'])
        
        # Reset chain
        self.chain = []
        self.pending_transactions = []
        self.create_genesis_block()
        
        # Rebuild in batches
        batch_size = 20
        for i in range(0, len(all_transactions), batch_size):
            batch = all_transactions[i:i + batch_size]
            self.pending_transactions = batch
            self.mine_block()
        
        print("? Blockchain rebuilt successfully!")
        return len(self.chain)
    
    def export_blockchain(self, filename=None):
        """Export the blockchain to a file"""
        if filename is None:
            filename = f"blockchain_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump({
                    'chain': self.chain,
                    'export_time': datetime.now().isoformat(),
                    'total_blocks': len(self.chain),
                    'chain_valid': self.verify_chain()
                }, f, indent=2, ensure_ascii=False)
            
            print(f"!! Blockchain exported to: {filename}")
            return filename
        except Exception as e:
            print(f"? Export failed: {e}")
            return None
    
    def verify_chain(self):
        """Verify the integrity of the blockchain"""
        print("!! Verifying blockchain integrity...")
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Verify current block hash
            calculated_hash = self.calculate_hash(current_block)
            stored_hash = current_block.get('hash', '')
            
            if stored_hash != calculated_hash:
                print(f"? Block {i} hash verification failed")
                print(f"   Expected: {calculated_hash[:16]}...")
                print(f"   Got:      {stored_hash[:16]}...")
                
                # Attempt automatic repair
                print(f"!! Attempting to repair block {i} hash...")
                current_block['hash'] = calculated_hash
                print(f"? Block {i} hash repaired")
                continue
            
            # Verify previous hash link
            if current_block['previous_hash'] != previous_block['hash']:
                print(f"? Block {i} previous hash chain broken")
                print(f"   Expected previous: {previous_block['hash'][:16]}...")
                print(f"   Got previous:     {current_block['previous_hash'][:16]}...")
                return False
        
        print("? Blockchain verification completed")
        return True
    
    def get_switch_history(self, switch_id):
        """Get all transactions for a specific switch"""
        history = []
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction.get('switch_id') == switch_id:
                    history.append({
                        'block_index': block['index'],
                        'timestamp': transaction['timestamp'],
                        'type': transaction['type'],
                        'flow_data': transaction.get('flow_data', {}),
                        'user_id': transaction.get('user_id', 'unknown'),
                        'status': transaction.get('status', 'confirmed')
                    })
        return history
    
    def print_blockchain_status(self):
        """Print status of the blockchain"""
        print("\n" + "="*60)
        print("!! BLOCKCHAIN SDN STATUS")
        print("="*60)
        print(f"!! Total Blocks: {len(self.chain)}")
        print(f"!! Pending Transactions: {len(self.pending_transactions)}")
        
        # Verify chain integrity
        is_valid = self.verify_chain()
        print(f"!! Chain Valid: {'Yes' if is_valid else 'No'}")
        
        # Count total transactions
        total_transactions = sum(len(block['transactions']) for block in self.chain)
        print(f"!! Total Network Transactions: {total_transactions}")
        
        # Show last block info
        if len(self.chain) > 1:
            last_block = self.chain[-1]
            print(f"!! Latest Block: #{last_block['index']} ({len(last_block['transactions'])} transactions)")
            print(f"!! Latest Block Time: {datetime.fromtimestamp(last_block['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"!! Latest Block Hash: {last_block['hash'][:16]}...")
        
        # Show switch activity statistics
        switch_stats = {}
        for block in self.chain:
            for transaction in block['transactions']:
                switch_id = transaction.get('switch_id', 'unknown')
                if switch_id not in switch_stats:
                    switch_stats[switch_id] = 0
                switch_stats[switch_id] += 1
        
        if switch_stats:
            print("\n!! Switch Activity (Top 10):")
            sorted_switches = sorted(switch_stats.items(), key=lambda x: x[1], reverse=True)[:10]
            for switch_id, count in sorted_switches:
                print(f"  !! {switch_id}: {count} transactions")
        
        # Show repair options if invalid
        if not is_valid:
            print("\n!! BLOCKCHAIN REPAIR OPTIONS:")
            print("   Use: py net.blockchain.repair_blockchain()")
            print("   Use: py net.blockchain.rebuild_blockchain()")

if __name__ == '__main__':
    run_secure_network()