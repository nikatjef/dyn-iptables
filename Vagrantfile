# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

#  config.chef_zero.enabled = true
  
  # box 1
  config.vm.define :box1 do |box1|

    box1.vm.hostname = "iptables-1"
    box1.vm.box = "opscode-centos-6.4"
    box1.vm.box_url = "https://opscode-vm-bento.s3.amazonaws.com/vagrant/opscode_centos-6.4_provisionerless.box"
    box1.vm.network :private_network, ip: "33.33.33.10"
    
    box1.ssh.max_tries = 40
    box1.ssh.timeout   = 120

    box1.berkshelf.enabled = true
    
    box1.vm.provision :chef_client do |chef|
      chef.chef_server_url = "https://api.opscode.com/organizations/someara"
      chef.validation_client_name = "someara-validator"
      chef.validation_key_path = "/Users/someara/.chef/someara-validator.pem"
      chef.client_key_path = "/Users/someara/.chef/someara.pem"
      
      chef.run_list = [
        "recipe[iptables::default]"
      ]
    end
  end

  # box 2
  config.vm.define :box2 do |box2|
    box2.vm.hostname = "iptables-2"
    box2.vm.box = "opscode-centos-6.4"
    box2.vm.box_url = "https://opscode-vm-bento.s3.amazonaws.com/vagrant/opscode_centos-6.4_provisionerless.box"
    box2.vm.network :private_network, ip: "33.33.33.11"
    
    box2.ssh.max_tries = 40
    box2.ssh.timeout   = 120

    box2.berkshelf.enabled = true
    
    box2.vm.provision :chef_client do |chef|
      chef.chef_server_url = "https://api.opscode.com/organizations/someara"
      chef.validation_client_name = "someara-validator"
      chef.validation_key_path = "/Users/someara/.chef/someara-validator.pem"
      chef.client_key_path = "/Users/someara/.chef/someara.pem"
      
      chef.run_list = [
        "recipe[iptables::default]"
      ]
    end
  end
  
end

