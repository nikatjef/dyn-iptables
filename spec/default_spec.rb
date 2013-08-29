require 'spec_helper'

describe "iptables::default" do

  static_inbound = {
    '0.0.0.0/0' => {
      'proto' => 'tcp',
      'source_ports' => [ 'any' ],
      'dest_ports' => [ '22' ],
      'jump' => 'ACCEPT'
    }
  }
  
  dynamic_inbound = {
    '*:*' => {
      'node_attribute' => 'ipaddress',
      'source_ports' => [ 'any' ],
      'dest_ports' => [ '22' ],
      'jump' => 'ACCEPT'
    },
    'role:webserver' => {
      'node_attribute' => 'fqdn',
      'source_ports' => [ 'any' ],
      'dest_ports' => [ '80', '443' ],
      'jump' => 'ACCEPT'
    },
    'role:worker_nodes' => {
      'node_attribute' => 'fqdn',
      'source_ports' => [ 'any' ],
      'dest_ports' => [ '8080', '1337' ],
      'jump' => 'ACCEPT'
    }
  }

  dynamic_outbound = {}
  
  let(:runner) {
    ChefSpec::ChefRunner.new.converge('iptables::default')
  }

  it "intalls the iptables package" do
    expect(runner).to install_package('iptables')
  end
  
end

