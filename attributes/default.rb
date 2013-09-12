
default['iptables_apply_for_real'] = 1
default['iptables_input_default_deny'] = 1
default['iptables_output_default_deny'] = 0

default['iptables_temp_destination'] = '/tmp/chef_iptables_ruleset

default['iptables']['cookbook']['static_inbound'] = {

  'lo accept from anywhere' => {
    'proto' => 'all',
    'source' => '0.0.0.0/0',
    'interface' => 'lo',
    'action' => 'accept'
  },
  
  'eth0 accept icmp from anywhere' => {
    'interface' => 'eth0',
    'source' => '0.0.0.0/0',
    'proto' => 'icmp',
    'action' => 'accept'
  },

  'eth0 accept ssh from anywhere' => {
    'interface' => 'eth0',
    'source' => '0.0.0.0/0',  
    'proto' => 'tcp',
    'dest_ports' => [ '22' ],
    'action' => 'accept'
  },
  
  'eth1 accept icmp from anywhere' => {
    'interface' => 'eth0',
    'source' => '0.0.0.0/0',
    'proto' => 'icmp',
    'action' => 'accept'
  },

  'eth1 accept ssh from anywhere' => {
    'interface' => 'eth1',
    'source' => '0.0.0.0/0',  
    'proto' => 'tcp',
    'dest_ports' => [ '22' ],
    'action' => 'accept'
  }
}

default['iptables']['cookbook']['static_outbound'] = {
  'lo accept from anywhere' => {
    'proto' => 'all',
    'source' => '0.0.0.0/0',
    'interface' => 'lo',
    'action' => 'accept'
  },
}

default['iptables']['cookbook']['dynamic_inbound'] = {

  'allow icmp from *:*' => {
    'search_term' => '*:*',
    'interface' => 'eth1',
    'remote_interface' => 'eth1',
    'proto' => 'icmp',
    'action' => 'accept'
  },
  
  'allow ssh from *:*' => {
    'search_term' => '*:*',
    'interface' => 'eth1',
    'remote_interface' => 'eth1',
    'proto' => 'tcp',
    'dest_ports' => [ '22' ],
    'action' => 'accept'
  },

  'allow dns and bootp from *:*' => {
    'search_term' => '*:*',
    'interface' => 'eth1',
    'remote_interface' => 'eth1',
    'proto' => 'udp',
    'dest_ports' => [ '23', '67' ],
    'action' => 'accept'
  }
  
}

default['iptables']['cookbook']['dynamic_outbound'] = {
  'allow outgoing to port 1234 at *:*' => {
    'search_term' => '*:*',
    'interface' => 'eth1',
    'remote_interface' => 'eth1',
    'proto' => 'tcp',
    'action' => 'accept'
  }
}
