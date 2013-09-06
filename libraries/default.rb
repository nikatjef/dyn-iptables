
class IptablesRules
  attr_accessor :filter_ruleset
  attr_accessor :static_inbound_ruleset
  attr_accessor :dynamic_inbound_ruleset
  attr_accessor :static_outbound_ruleset
  attr_accessor :dynamic_outbound_ruleset
  
  def initialize(rule_types)

    @rule_types = rule_types
    
    # create arrays for ruleset parts
    @filter_ruleset = []
    @static_inbound_ruleset = []
    @dynamic_inbound_ruleset = []
    @static_outbound_ruleset = []
    @dynamic_outbound_ruleset = []

    # register methods
    @rule_types.each do |type|
      IptablesRules.define_component(type)
    end
    
  end # initialize
  
  def self.define_component(name)
    define_method(name) do |ruledefs|
      if ! ruledefs.empty? then

        __method__.to_s =~ /inbound/ ? @direction = "INPUT" : @direction = "OUTPUT"
        
        ruledefs.each do |rule_name,rule_data|          
          (rule_data['interface'].nil? || @direction == 'OUTPUT' ) ? @interface = "" : @interface = "-i " + rule_data['interface']
          (rule_data['proto'].nil? || rule_data['proto'] == 'all') ? @proto = "" : @proto = "-p " + rule_data['proto']
          rule_data['source'].nil? ? @source = "" : @source = "-s " + rule_data['source']
          rule_data['proto'] == 'tcp' ? @state_rule = "-m state --state NEW" : @state_rule = ""
          
          # static
          if __method__.to_s =~ /static/ then          
            if rule_data['dest_ports'].nil? then
              eval("@#{__method__}_ruleset") << "-A #{@direction} #{@interface} #{@state_rule} #{@proto} #{@source} -j ACCEPT".squeeze(" ")
            else
              rule_data['dest_ports'].each do |port|
                eval("@#{__method__}_ruleset") << "-A #{@direction} #{@interface} #{@state_rule} #{@proto} #{@source} --dport #{port} -j ACCEPT".squeeze(" ")
              end
            end            
          end
          
          # dymanic
          if __method__.to_s =~ /dynamic/ then
            if ! rule_data['search_term'].nil?
              results = []
              Chef::Search::Query.new.search(:node, rule_data['search_term'])[0].each { |rows| results << rows }
              results.each do |host|
                # add more? generate?
                case rule_data['remote_interface']
                when 'eth0'
                  @host_ip = host['ipaddress']
                when 'eth1'
                  unless host['network'].nil?
                    @host_ip = host['network']['interfaces']['eth1']['addresses'].select { |address, data| data['family'] == 'inet' }.keys[0]
                  end
                when 'eth2'
                  unless host['network'].nil?
                    @host_ip = host['network']['interfaces']['eth2']['addresses'].select { |address, data| data['family'] == 'inet' }.keys[0]
                  end
                end

                @source = "-s " + @host_ip
                
                if rule_data['dest_ports'].nil? then
                  eval("@#{__method__}_ruleset") << "-A #{@direction} #{@interface} #{@state_rule} #{@proto} #{@source} -j ACCEPT".squeeze(" ")
                else
                  rule_data['dest_ports'].each do |port|
                    eval("@#{__method__}_ruleset") << "-A #{@direction} #{@interface} #{@state_rule} #{@proto} #{@source} --dport #{port} -j ACCEPT".squeeze(" ")
                  end
                end                          
              end # search.each
            end # if ! rule_data['search_term'].nil?
          end # __method__.to_s =~ /static/ then
        end # rule_defs.each
      end # if ! rule_defs.empty?
    end # define_method
  end # self.define_component
end # class IptablesRules

def set_iptables_attributes
  # set node attributes from databags
  hostname = node['hostname']
  begin
    search(:iptables_hostname, "id:#{hostname}").each do |result|
      node.default['iptables']['hostname']['static_inbound'] = result['static_inbound']
      node.default['iptables']['hostname']['static_outbound'] = result['static_outbound']
      node.default['iptables']['hostname']['dynamic_inbound'] = result['dynamic_inbound']
      node.default['iptables']['hostname']['dynamic_outbound'] = result['dynamic_outbound']      
    end
  rescue => exception
    Chef::Log.info("Caught #{exception}. Databag iptables_hostname could not be searched.")
  end

  # next, override default cookbook rules based on hostclass tag  
  hostclass = node['tags'].grep(/hostclass.*/).first
  if ! hostclass.nil? then
    begin    
      search(:iptables_hostclass, "id:#{hostclass}").each do |result|
        node.default['iptables']['hostclass']['static_inbound'] = result['static_inbound']
        node.default['iptables']['hostclass']['static_outbound'] = result['static_outbound']
        node.default['iptables']['hostclass']['dynamic_inbound'] = result['dynamic_inbound']
        node.default['iptables']['hostclass']['dynamic_outbound'] = result['dynamic_outbound']
      end
    rescue => exception
      Chef::Log.info("Caught #{exception}. Databag iptables_hostclass could not be searched.")
    end
  end
end
