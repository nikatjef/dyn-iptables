#
# Cookbook Name:: iptables
# Recipe:: default
#
# Copyright (C) 2013 apachev2
# 
#

# functions defined in libraries/default.rb
# @ruleset instance variable set for use in recipe

set_iptables_attributes

# do the work
rule_types = []
node['iptables'].each do |rule_source, types|
   types.each do |type,ruledefs|
     rule_types << type
   end
end

#binding.pry
ruleset = IptablesRules.new rule_types.uniq

node['iptables'].each do | rule_source, types |
  types.each do |type,ruledefs|
    ruleset.send("#{type}", ruledefs)
  end
end

Chef::Log.info( "static_inbound_ruleset:" )
Chef::Log.info( ruleset.static_inbound_ruleset.uniq )
Chef::Log.info( "dynamic_inbound_ruleset:" )
Chef::Log.info( ruleset.dynamic_inbound_ruleset.uniq )
Chef::Log.info( "static_outbound_ruleset:" )
Chef::Log.info( ruleset.static_outbound_ruleset.uniq )
Chef::Log.info( "dynamic_outbound_ruleset:" )
Chef::Log.info( ruleset.dynamic_outbound_ruleset.uniq )

binding.pry

if node['iptables']['apply_for_real'] then
  template "/etc/sysconfig/iptables" do
    source "chef_iptables_ruleset.erb"
    owner = "root"
    mode "0600"
    variables(
      :static_inbound => ruleset.static_inbound_ruleset.uniq,
      :dynamic_inbound => ruleset.dynamic_inbound_ruleset,
      :static_outbound => ruleset.static_outbound_ruleset,
      :dynamic_outbound => ruleset.dynamic_outbound_ruleset
      )
    notifies :restart, "service[iptables]"
  end
else
  template "/tmp/chef_iptables_ruleset" do
    source "chef_iptables_ruleset.erb"
    owner = "root"
    mode "0644"
    variables(
      :static_inbound => ruleset.static_inbound_ruleset.uniq,
      :dynamic_inbound => ruleset.dynamic_inbound_ruleset.uniq,
      :static_outbound => ruleset.static_outbound_ruleset.uniq,
      :dynamic_outbound => ruleset.dynamic_outbound_ruleset.uniq
      )
  end
end

service "iptables" do
  action :start
end
