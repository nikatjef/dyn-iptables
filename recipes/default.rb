#
# Cookbook Name:: iptables
# Recipe:: default
#
# Copyright (C) 2013 apachev2
# 
#

package "emacs-nox"

include_recipe "_collect_filter"
include_recipe "_collect_inbound_rules"
include_recipe "_collect_outbound_rules"

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
