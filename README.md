# iptables cookbook

# Usage
The iptables cookbook generates an iptables ruleset, and manages a
persistence file on disk. Firewall rules are described as node
attributes, and are assembled into arrays, which are passed as
arguments to a template resource. There are two kinds of rules, static
and dynamic. Static rules require the user to supply a source
address/range, and dynamic rules require a search term. When
chef-client runs, static and dynamic rules are iterated over to build
inbound and outbound rulesets.

Rules are defined as attributes under the keyspace node['iptables'].
There are sub-keys for static_inbound, dynamic_inbound,
static_outbound, and dynamic_outbound. The cookbook ships some default
rules, and they can be overridden through the usual mechanisms.

In addition to wrapper cookbooks, roles, and environments, the recipe
searches chef-server for two types of data bags. 

First, it checks for a tag on the node object called 'hostclass-*'. If
a hostclass tag is found, it searches the iptables data bag index for
a record with the hostclass tag as an id. If found, it will override
the attribute space the rules found in the data bag.

Next, it searches the iptables data bag index for a record with the
hostname as an id. If found, it will override the attribute space with
the rules found in that data bag.

# Attributes

```ruby
default['iptables']['apply_for_real'] = 0

default['iptables']['filter']
default['iptables']['static_inbound']
default['iptables']['static_outbound']
default['iptables']['dynamic_inbound']
default['iptables']['dynamic_outbound']
```

```ruby
# static_inbound example
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

# Data bags

Example data bags are shipped with the cookbook, and can be found in example_data_bags.

# Recipes
default - Manages template[/etc/sysconfig/iptables] and restarts the iptables service if it changes

# Author
Author:: apachev2 (<Sean OMeara <someara@opscode.com>>)
