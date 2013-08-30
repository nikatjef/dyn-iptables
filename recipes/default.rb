#
# Cookbook Name:: iptables
# Recipe:: default
#
# Copyright (C) 2013 apachev2
# 
#

require 'pry'

filter_ruleset = []
static_inbound_ruleset = []
static_outbound_ruleset = []
dynamic_inbound_ruleset = []
dynamic_outbound_ruleset = []

#######################
# STATIC INBOUND
#######################

if ! node['iptables']['static_inbound'].empty? then
  node['iptables']['static_inbound'].each do | rule_name, rule_data |
    @rule_data = rule_data
    
    case rule_data['proto']
    when 'icmp'
      rule = "-A INPUT -p icmp -s #{@rule_data['source']} -j ACCEPT"
      Chef::Log.info rule
      static_inbound_ruleset << rule
    when 'tcp'    
      rule_data['dest_ports'].each do | dport |
        rule = "-A INPUT -m state --state NEW -m tcp -p tcp -s #{@rule_data['source']} --dport #{dport} -j ACCEPT"
        Chef::Log.info rule
        static_inbound_ruleset << rule
      end    
    when 'udp'    
      rule_data['dest_ports'].each do | dport |
        rule = "-A INPUT -m state --state NEW -m udp -p udp -s #{@rule_data['source']} --dport #{dport} -j ACCEPT"
        Chef::Log.info
        static_inbound_ruleset << rule
      end
    end
  end  
end

#######################
# STATIC OUTBOUND
#######################

if ! node['iptables']['static_outbound'].empty? then
  node['iptables']['static_outbound'].each do | rule_name, rule_data |
    @rule_data = rule_data
    
    case rule_data['proto']
    when 'icmp'
      rule = "-A OUTPUT -p icmp -s #{@rule_data['source']} -j ACCEPT"
      Chef::Log.info rule
      static_outbound_ruleset << rule
    when 'tcp'    
      rule_data['dest_ports'].each do | dport |
        rule = "-A OUTPUT -m state --state NEW -m tcp -p tcp -s #{@rule_data['source']} --dport #{dport} -j ACCEPT"
        Chef::Log.info rule
        static_outbound_ruleset << rule
      end    
    when 'udp'    
      rule_data['dest_ports'].each do | dport |
        rule = "-A OUTPUT -m state --state NEW -m udp -p udp -s #{@rule_data['source']} --dport #{dport} -j ACCEPT"
        Chef::Log.info
        static_outbound_ruleset << rule
      end
    end
    
  end
end

#######################
# DYNAMIC INBOUND
#######################

if ! node['iptables']['dynamic_inbound'].empty? then
  node['iptables']['dynamic_inbound'].each do |rule_name, rule_data |

    @rule_data = rule_data
    Chef::Log.info "processing '#{rule_name}'"
    
    search(:node, @rule_data['search_term']).each do | host |
      
      # dig out correct ip from node record
      case @rule_data['interface']
      when 'eth0'
        host_ip = host['ipaddress']
      when 'eth1'
        unless host['network'].nil?        
          host_ip = host['network']['interfaces']['eth1']['addresses'].select { |address, data| data['family'] == 'inet' }.keys[0]
        end
      end

      # generate rules based on protocol
      case @rule_data['proto']
      when 'icmp'
        rule = "-A INPUT -p icmp -s #{host_ip} -j ACCEPT"
        Chef::Log.info rule
        dynamic_inbound_ruleset << rule
      when 'tcp'
        rule_data['dest_ports'].each do |dport|
          rule = "-A INPUT -m state --state NEW -p tcp -s #{host_ip} --dport #{dport} -j ACCEPT"
          Chef::Log.info rule
          dynamic_inbound_ruleset << rule
        end
      when 'udp'
        rule_data['dest_ports'].each do |dport|
          rule = "-A INPUT -p udp -s #{host_ip} --dport #{dport} -j ACCEPT"
          Chef::Log.info rule
          dynamic_inbound_ruleset << rule
        end        
      end      
    end    
  end  
end

#######################
# DYNAMIC OUTBOUND
#######################

if ! node['iptables']['dynamic_outbound'].empty? then
  node['iptables']['dynamic_outbound'].each do |rule_name, rule_data |

    @rule_data = rule_data
    Chef::Log.info "processing '#{rule_name}'"
    
    search(:node, @rule_data['search_term']).each do | host |
      
      # dig out correct ip from node record
      case @rule_data['interface']
      when 'eth0'
        host_ip = host['ipaddress']
      when 'eth1'
        unless host['network'].nil?        
          host_ip = host['network']['interfaces']['eth1']['addresses'].select { |address, data| data['family'] == 'inet' }.keys[0]
        end
      end

      # generate rules based on protocol
      case @rule_data['proto']
      when 'icmp'
        rule = "-A INPUT -p icmp -s #{host_ip} -j ACCEPT"
        Chef::Log.info rule
        dynamic_outbound_ruleset << rule
      when 'tcp'
        rule_data['dest_ports'].each do |dport|
          rule = "-A OUTPUT -m state --state NEW -p tcp -s #{host_ip} --dport #{dport} -j ACCEPT"
          Chef::Log.info rule
          dynamic_outbound_ruleset << rule
        end
      when 'udp'
        rule_data['dest_ports'].each do |dport|
          rule = "-A OUTPUT -p udp -s #{host_ip} --dport #{dport} -j ACCEPT"
          Chef::Log.info rule
          dynamic_outbound_ruleset << rule
        end      
      end
    end    
  end
end

template "/tmp/chef_iptables_ruleset" do
  owner = "root"
  mode "0644"
  variables( :filter => filter_ruleset )
  variables( :static_inbound => static_inbound_ruleset )
  variables( :static_outbound => static_outbound_ruleset )
  variables( :dynamic_inbound => dynamic_inbound_ruleset )
  variables( :dynamic_outbound => dynamic_inbound_ruleset )
end
