# =)

filter_ruleset = []
static_inbound_ruleset = []
static_outbound_ruleset = []
dynamic_inbound_ruleset = []
dynamic_outbound_ruleset = []

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
