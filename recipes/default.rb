#
# Cookbook Name:: iptables
# Recipe:: default
#
# Copyright (C) 2013 apachev2
# 
#

# functions defined in libraries/default.rb
# @ruleset instance variable set for use in recipe

ruleset = IptablesRules.new node

iptables_save_dest = value_for_platform(
  [ 'centos', 'redhat', 'suse', 'fedora', 'amazon', 'scientific', 'oracle' ] => { 'default' => '/etc/sysconfig/iptables' },
  [ 'debian', 'ubuntu' ] => { 'default' => '/etc/iptables.save' },
  'default' => '/etc/iptables.save'
  )

template iptables_save_dest do
  source "chef_iptables_ruleset.erb"
  owner = "root"
  mode "0600"
  variables(
    :static_inbound => ruleset.static_inbound_ruleset.uniq,
    :dynamic_inbound => ruleset.dynamic_inbound_ruleset,
    :static_outbound => ruleset.static_outbound_ruleset,
    :dynamic_outbound => ruleset.dynamic_outbound_ruleset
    )
  if (node['iptables_apply_for_real'].to_i == 1)
    notifies :restart, "service[iptables]", :delayed
  end
end

service "iptables" do
  action :nothing
end
