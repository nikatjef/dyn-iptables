
default['iptables']['apply_for_real'] = 0

default['iptables']['filter'] = {
  'INPUT' => 'DROP [0:0]',
  'FORWARD' => 'ACCEPT [0:0]',
  'OUTPUT' => 'ACCEPT [0:0]',
  'LOGACCEPT' => '- [0:0]',
  'LOGDROP' => '- [0:0]'
}

default['iptables']['static_inbound'] = {

  'accept icmp from anywhere' => {
    'source' => '0.0.0.0/0',
    'proto' => 'icmp',
    'action' => 'accept'
  },

  'accept ssh from anywhere' => {
    'source' => '0.0.0.0/0',  
    'proto' => 'tcp',
    'dest_ports' => [ '22' ],
    'action' => 'accept'
  }
}

default['iptables']['static_outbound'] = {}

default['iptables']['dynamic_inbound'] = {

  'allow icmp from *:*' => {
    'search_term' => '*:*',
    'proto' => 'icmp',
    'action' => 'accept'
  },
  
  'allow ssh from *:*' => {
    'search_term' => '*:*',
    'interface' => 'eth1',
    'proto' => 'tcp',
    'dest_ports' => [ '22', '80' ],
    'action' => 'accept'
  },

  'allow dns and bootp from *:*' => {
    'search_term' => '*:*',
    'interface' => 'eth1',
    'proto' => 'udp',
    'dest_ports' => [ '23', '67' ],
    'action' => 'accept'
  }
  
}

default['iptables']['dynamic_outbound'] = {}
