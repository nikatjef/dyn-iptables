# iptables cookbook

# Usage
The iptables cookbook generates an iptables ruleset, and manages a
persistence file on disk. 

# Attributes
```ruby
default['iptables']['apply_for_real'] = 0
default['iptables']['filter']
default['iptables']['static_inbound']
default['iptables']['static_outbound']
default['iptables']['dynamic_inbound']
default['iptables']['dynamic_outbound']
```

# static_inbound example
```ruby
'lo accept from anywhere' => {
  'proto' => 'all',
  'source' => '0.0.0.0/0',
  'interface' => 'lo',
  'action' => 'accept'
}

# dynamic_inbound examples

'allow icmp from *:*' => {
  'search_term' => '*:*',
  'interface' => 'eth0',
  'remote_interface' => 'eth1',
  'proto' => 'icmp',
  'action' => 'accept'
},
'allow ssh from role:webserver' => {
  'search_term' => 'role:webserver',
  'interface' => 'eth0',
  'remote_interface' => 'eth0',
  'proto' => 'tcp',
  'dest_ports' => [ '22' ],
  'action' => 'accept'
},
'allow mysql from tags:hostclass-dba-workstations' => {
  'search_term' => 'role:webserver',
  'interface' => 'eth0',
  'remote_interface' => 'eth0',
  'proto' => 'tcp',
  'dest_ports' => [ '22' ],
  'action' => 'accept'
}
```

# Recipes
default - Manages template[/etc/sysconfig/iptables] and restarts the iptables service if it changes

# Author
Author:: apachev2 (<Sean OMeara <someara@opscode.com>>)
