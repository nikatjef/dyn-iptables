
def set_iptables_attributes
  # first, override default cookbook rules based on hostname
  hostname = node['hostname']
  search(:iptables_hostname, "id:#{hostname}").each do |result|
    node.default['iptables']['hostname']['static_inbound'] = result['static_inbound']
    node.default['iptables']['hostname']['static_outbound'] = result['static_outbound']
    node.default['iptables']['hostname']['dynamic_inbound'] = result['dynamic_inbound']
    node.default['iptables']['hostname']['dynamic_outbound'] = result['dynamic_outbound']
  end
  
  # next, override default cookbook rules based on hostclass tag  
  hostclass = node['tags'].grep(/hostclass.*/).first
  if ! hostclass.nil? then
    search(:iptables_hostclass, "id:#{hostclass}").each do |result|
      node.default['iptables']['hostclass']['static_inbound'] = result['static_inbound']
      node.default['iptables']['hostclass']['static_outbound'] = result['static_outbound']
      node.default['iptables']['hostclass']['dynamic_inbound'] = result['dynamic_inbound']
      node.default['iptables']['hostclass']['dynamic_outbound'] = result['dynamic_outbound']
    end
  end
end

#######################
# FILTER
#######################

def collect_filter_ruleset 
  filter_ruleset = []
  
  if ! node['iptables']['filter'].empty? then
    node['iptables']['filter'].each do |chain,filter|
      filter_ruleset << "#{chain} #{filter}"
    end
  else
    filter_ruleset << 'INPUT DROP [0:0]'
    filter_ruleset << 'FORWARD ACCEPT [0:0]'
    filter_ruleset << 'OUTPUT ACCEPT [0:0]'
    filter_ruleset << 'LOGACCEPT - [0:0]'
    filter_ruleset << 'LOGDROP - [0:0]'  
  end

  return filter_ruleset  
end

#######################
# STATIC INBOUND
#######################

def collect_static_inbound_ruleset
  static_inbound_ruleset = []
  
  if ! node['iptables']['static_inbound'].empty? then
    node['iptables']['static_inbound'].each do | rule_name, rule_data |
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
        static_inbound_ruleset << "-A INPUT #{@interface} -j ACCEPT"
      when 'icmp'
        static_inbound_ruleset << "-A INPUT #{@interface} -p icmp #{@source} -j ACCEPT"
      when 'udp'
        if dest_ports.nil? then
          static_inbound_ruleset << "-A INPUT #{@interface} -p udp #{@source} -j ACCEPT"
        else
          rule_data['dest_ports'].each do | dport |
            static_inbound_ruleset << "-A INPUT #{@interface} -p udp #{@source} --dport #{dport} -j ACCEPT"
          end
        end
      when 'tcp'
        if dest_ports.nil? then
          static_inbound_ruleset << "-A INPUT #{@interface} -p tcp #{@source} -j ACCEPT"
        else
          rule_data['dest_ports'].each do | dport |
            static_inbound_ruleset << "-A INPUT #{@interface} -m state --state NEW -m tcp -p tcp #{@source} --dport #{dport} -j ACCEPT"
          end
        end
      end
    end  
  end
  
  return static_inbound_ruleset  
end

#######################
# DYNAMIC INBOUND
#######################

def collect_dynamic_inbound_ruleset
  dynamic_inbound_ruleset = []
  
  if ! node['iptables']['dynamic_inbound'].empty? then
    node['iptables']['dynamic_inbound'].each do |rule_name, rule_data |
      
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
          rule = "-A INPUT #{@interface} #{@host_ip} -j ACCEPT"
          dynamic_inbound_ruleset << rule
        when 'icmp'
          rule = "-A INPUT #{@interface} -p icmp -s #{@host_ip} -j ACCEPT"
          dynamic_inbound_ruleset << rule
        when 'udp'
          if dest_ports.nil? then
            rule = "-A INPUT #{@interface} -p udp #{@host_ip} -j ACCEPT"
          else
            rule_data['dest_ports'].each do |dport|
              rule = "-A INPUT #{@interface} -p udp -s #{@host_ip} --dport #{dport} -j ACCEPT"
              dynamic_inbound_ruleset << rule
            end
          end
        when 'tcp'
          if dest_ports.nil? then
            rule = "-A INPUT #{@interface} -m state --state NEW -p tcp -s #{@host_ip} -j ACCEPT"
            dynamic_inbound_ruleset << rule
          else
            rule_data['dest_ports'].each do |dport|
              rule = "-A INPUT #{@interface} -m state --state NEW -p tcp -s #{@host_ip} --dport #{dport} -j ACCEPT"            
              dynamic_inbound_ruleset << rule
            end
          end
        end      
      end    
    end  
  end
  return dynamic_inbound_ruleset
end

#######################
# STATIC OUTBOUND
#######################

def collect_static_outbound_ruleset
  static_outbound_ruleset = []
  
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
  return static_outbound_ruleset
end

#######################
# DYNAMIC OUTBOUND
#######################

def collect_dynamic_outbound_ruleset
  dynamic_outbound_ruleset = []
  
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
  return dynamic_outbound_ruleset
end
