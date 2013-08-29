#
# Cookbook Name:: iptables
# Recipe:: default
#
# Copyright (C) 2013 apachev2
# 
#

iptables_ruleset = []

node['iptables']['static_inbound'].each do | rule_name, rule_data |
  @rule_data = rule_data
  
  case rule_data['proto']
  when 'icmp'
    Chef::Log.info "/sbin/iptables -A INPUT -p icmp -s #{@rule_data['source']} -j ACCEPT"
  when 'tcp'    
    rule_data['dest_ports'].each do | dport |
      Chef::Log.info "/sbin/iptables -A INPUT -m state --state NEW -m tcp -p tcp -s #{@rule_data['source']} --dport #{dport} -j ACCEPT"
    end    
  when 'udp'    
    rule_data['dest_ports'].each do | dport |a
      Chef::Log.info "/sbin/iptables -A INPUT -m state --state NEW -m udp -p udp -s #{@rule_data['source']} --dport #{dport} -j ACCEPT"
    end
  end
  
end


node['iptables']['dynamic_inbound'].each do |rule_name, rule_data |

  @rule_data = rule_data
  Chef::Log.info "processing '#{rule_name}'"
  
  search(:node, @rule_data['search_term']).each do | host |
#    Chef::Log.info "host: #{host}"
#    Chef::Log.info "rule_data: #{@rule_data}"    

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
      Chef::Log.info "/sbin/iptables -A INPUT -p icmp -s #{host_ip} -j ACCEPT"          
    when 'tcp'
      rule_data['dest_ports'].each do |dport|
        Chef::Log.info "/sbin/iptables -A INPUT -m state --state NEW -p tcp -s #{host_ip} --dport #{dport} -j ACCEPT"
      end
    when 'udp'
      rule_data['dest_ports'].each do |dport|
        Chef::Log.info "/sbin/iptables -A INPUT -p udp -s #{host_ip} --dport #{dport} -j ACCEPT"      
      end      
    end
  end
  
end
