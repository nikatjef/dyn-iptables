require 'pry'

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

#    binding.pry
    
    # if ! node['iptables']['filter'].empty? then
    #   node['iptables']['filter'].each do |chain,filter|
    #     @filter_ruleset << "#{chain} #{filter}"
    #   end
    # else
    #   @filter_ruleset << 'INPUT DROP [0:0]'
    #   @filter_ruleset << 'FORWARD ACCEPT [0:0]'
    #   @filter_ruleset << 'OUTPUT ACCEPT [0:0]'
    #   @filter_ruleset << 'LOGACCEPT - [0:0]'
    #   @filter_ruleset << 'LOGDROP - [0:0]'  
    # end
    

    # register methods
    @rule_types.each do |type|
      IptablesRules.define_component(type)
    end
    
  end # initialize
  
  def self.define_component(name)
    define_method(name) do |ruledefs|
      if ! ruledefs.empty? then

        if __method__.to_s =~ /inbound/ then
          @direction = "INPUT"
        else
          @direction = "OUTPUT"
        end
        
        ruledefs.each do |rule_name,rule_data|          
          (rule_data['interface'].nil? || @direction == 'OUTPUT' ) ? @interface = "" : @interface = "-i " + rule_data['interface']
          (rule_data['proto'].nil? || rule_data['proto'] == 'all') ? @proto = "" : @proto = "-p " + rule_data['proto']
          rule_data['source'].nil? ? @source = "" : @source = "-s " + rule_data['source']
          rule_data['proto'] == 'tcp' ? @state_rule = "-m state --state NEW" : @state_rule = ""
          
          if rule_data['dest_ports'].nil? then
            eval("@#{__method__}_ruleset") << "-A #{@direction} #{@interface} #{@state_rule} #{@proto} #{@source} -j ACCEPT".squeeze(" ")
          else
            rule_data['dest_ports'].each do |port|
              eval("@#{__method__}_ruleset") << "-A #{@direction} #{@interface} #{@state_rule} #{@proto} #{@source} --dport #{port} -j ACCEPT".squeeze(" ")
            end
          end
          
        end
      end
    end    
  end
  
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
