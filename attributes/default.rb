
default['iptables']['apply_for_real'] = 0

default['iptables']['filter'] = {
  'INPUT' => 'DROP [0:0]',
  'FORWARD' => 'ACCEPT [0:0]',
  'OUTPUT' => 'ACCEPT [0:0]',
  'LOGACCEPT' => '- [0:0]',
  'LOGDROP' => '- [0:0]'
}

default['iptables']['static_inbound'] = {

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

default['iptables']['static_outbound'] = {
  'lo accept from anywhere' => {
    'proto' => 'all',
    'source' => '0.0.0.0/0',
    'interface' => 'lo',
    'action' => 'accept'
  },
}

default['iptables']['dynamic_inbound'] = {

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

default['iptables']['dynamic_outbound'] = {
  'allow port 1234 to *:*' => {
    'search_term' => '*:*',
    'interface' => 'eth1',
    'remote_interface' => 'eth1',
    'proto' => 'icmp',
    'action' => 'accept'
  },
  'allow tcp port 1234 to *:*' => {
    'search_term' => '*:*',
    'interface' => 'eth1',
    'remote_interface' => 'eth1',
    'proto' => 'tcp',
    'dest_ports' => [ '1234' ],
    'action' => 'accept'
  },
  'allow udp port 1234 to *:*' => {
    'search_term' => '*:*',
    'interface' => 'eth0',
    'remote_interface' => 'eth1',
    'proto' => 'udp',
    'dest_ports' => [ '1234' ],
    'action' => 'accept'
  }
}
