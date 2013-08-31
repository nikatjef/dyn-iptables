# =)

#######################
# STATIC OUTBOUND
#######################

if ! node['iptables']['static_outbound'].empty? then
  node['iptables']['static_outbound'].each do | rule_name, rule_data |
    @rule_data = rule_data
    if ! rule_data['interface'].nil? then
      @interface = "-i " + rule_data['interface']
    else
      @interface = ""
    end
    @source = "-s " + rule_data['source']
    dest_ports = rule_data['dest_ports']
    
    case rule_data['proto']
    when 'all'
      static_outbound_ruleset << "-A OUTPUT -j ACCEPT"
    when 'icmp'
      static_outbound_ruleset << "-A OUTPUT -p icmp #{@source} -j ACCEPT"
    when 'udp'
      if dest_ports.nil? then
        static_outbound_ruleset << "-A OUTPUT -p udp #{@source} -j ACCEPT"
      else
        rule_data['dest_ports'].each do | dport |
          static_outbound_ruleset << "-A OUTPUT -p udp #{@source} --dport #{dport} -j ACCEPT"
        end
      end
    when 'tcp'
      if dest_ports.nil? then
        static_outbound_ruleset << "-A OUTPUT -p tcp #{@source} -j ACCEPT"
      else
        rule_data['dest_ports'].each do | dport |
          static_outbound_ruleset << "-A OUTPUT -m state --state NEW -m tcp -p tcp #{@source} --dport #{dport} -j ACCEPT"
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

    Chef::Log.info "Processing dynamic iptables rule: '#{rule_name}'"

    @rule_data = rule_data
    if ! rule_data['interface'].nil? then
      @interface = "-i " + rule_data['interface']
    else
      @interface = ""
    end
    dest_ports = rule_data['dest_ports']
    
    search(:node, @rule_data['search_term']).each do | host |
      # dig out correct ip from node record
      case @rule_data['remote_interface']
      when 'eth0'
        @host_ip = host['ipaddress']
      when 'eth1'
        unless host['network'].nil?        
          @host_ip = host['network']['interfaces']['eth1']['addresses'].select { |address, data| data['family'] == 'inet' }.keys[0]
        end
      end

      # generate rules based on protocol
      case @rule_data['proto']
      when 'all'
        rule = "-A OUTPUT #{@host_ip} -j ACCEPT"
        dynamic_outbound_ruleset << rule
      when 'icmp'
        rule = "-A OUTPUT -p icmp -s #{@host_ip} -j ACCEPT"
        dynamic_outbound_ruleset << rule
      when 'udp'
        if dest_ports.nil? then
          rule = "-A OUTPUT -p udp #{@host_ip} -j ACCEPT"
        else
          rule_data['dest_ports'].each do |dport|
            rule = "-A OUTPUT -p udp -s #{@host_ip} --dport #{dport} -j ACCEPT"
            dynamic_outbound_ruleset << rule
          end
        end
      when 'tcp'
        if dest_ports.nil? then
          rule = "-A OUTPUT -m state --state NEW -p tcp -s #{@host_ip} -j ACCEPT"
          dynamic_outbound_ruleset << rule
        else
          rule_data['dest_ports'].each do |dport|
            rule = "-A OUTPUT -m state --state NEW -p tcp -s #{@host_ip} --dport #{dport} -j ACCEPT"            
            dynamic_outbound_ruleset << rule
          end
        end
      end      
    end    
  end  
end
