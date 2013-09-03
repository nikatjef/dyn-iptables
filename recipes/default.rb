#
# Cookbook Name:: iptables
# Recipe:: default
#
# Copyright (C) 2013 apachev2
# 
#

package "emacs-nox"

# functions defined in libraries/default.rb
set_iptables_attributes
filter_ruleset = collect_filter_ruleset
static_inbound_ruleset = collect_static_inbound_ruleset
dynamic_inbound_ruleset = collect_dynamic_inbound_ruleset
static_outbound_ruleset = collect_static_outbound_ruleset
dynamic_outbound_ruleset = collect_dynamic_outbound_ruleset

if node['iptables']['apply_for_real'] then
  template "/etc/sysconfig/iptables" do
    source "chef_iptables_ruleset.erb"
    owner = "root"
    mode "0600"
    variables(
      :filter => filter_ruleset,
      :static_inbound => static_inbound_ruleset,
      :static_outbound => static_outbound_ruleset,
      :dynamic_inbound => dynamic_inbound_ruleset,
      :dynamic_outbound => dynamic_outbound_ruleset
      )
    notifies :restart, "service[iptables]"
  end
else
  template "/tmp/chef_iptables_ruleset" do
    source "chef_iptables_ruleset.erb"
    owner = "root"
    mode "0644"
    variables(
      :filter => filter_ruleset,
      :static_inbound => static_inbound_ruleset,
      :static_outbound => static_outbound_ruleset,
      :dynamic_inbound => dynamic_inbound_ruleset,
      :dynamic_outbound => dynamic_outbound_ruleset
      )
  end
end

service "iptables" do
  action :start
end
