BOX_IMAGE = "ubuntu/focal64"

Vagrant.configure("2") do |config|

  config.vm.boot_timeout = 600
# VM L4S Client
  config.vm.define "clientp4" do |client|
    client.vm.box = BOX_IMAGE 
    client.vm.hostname = "clientl4s-p4"
    client.vm.network "private_network", ip: "192.168.56.10", mac: "080027AAAAAA",
      virtualbox__intnet: "l4s_client-router"
#    client.ssh.insert_key = false
#    client.ssh.private_key_path = "vagrant_key"

    client.vm.provider "virtualbox" do |vb|
      vb.name = "clientp4"
      vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"] 
    end

    client.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/client_l4s.yml"
    end
  end

  # VM Classic Client (Subnet 192.168.55.0/24)
  config.vm.define "classic-clientp4" do |classic_client|
    classic_client.vm.box = BOX_IMAGE 
    classic_client.vm.hostname = "classic-client"
    classic_client.vm.network "private_network", ip: "192.168.57.10", mac:"080027BBBBBB",
      virtualbox__intnet: "classic_client-router"
    classic_client.vm.provider "virtualbox" do |vb|
      vb.name = "classic-client-p4" 
    end
    classic_client.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/client_classic.yml"
    end
  end

  # VM Malicious Client (Nova subnet 192.168.54.0/24)
  config.vm.define "malicious-clientp4" do |malicious_client|
    malicious_client.vm.box = BOX_IMAGE
    malicious_client.vm.hostname = "malicious-client"
    malicious_client.vm.network "private_network", ip: "192.168.58.10", mac: "080027CCCCCC",
      virtualbox__intnet: "malicious_client-router"
    malicious_client.vm.provider "virtualbox" do |vb|
      vb.name = "malicious-client-p4" 
    end

    malicious_client.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/client_malicious.yml"
    end
  end

  # VM Roteador
  config.vm.define "router_bmv2"do |router|
    router.vm.box = "viniciussimao/bmv2-p4"
    router.vm.box_version = "01"
    router.vm.hostname = "router-bmv2"
    # --- Configurações de Hardware ---
    router.vm.provider "virtualbox" do |vb|
      vb.memory = 4096   
      vb.cpus = 4 
      vb.name = "router-p4" 
    end
    # Interface enp0s8 (Interface de Gerenciamento)
    router.vm.network "private_network", ip: "192.168.63.2", netmask: "255.255.255.252", name: "vboxnet0"

    # Interface enp0s9 (Client_l4s - bmv2)
    router.vm.network "private_network", auto_config: false,
      virtualbox__intnet: "l4s_client-router"

    # Interface enp0s10 (Classic_Client - bmv2)
    router.vm.network "private_network", auto_config: false,
      virtualbox__intnet: "classic_client-router"

    # Interface enp0s16 (Malicious_client - bmv2)
    router.vm.network "private_network", auto_config: false,
      virtualbox__intnet: "malicious_client-router"
    
    # Interface (L4S_Server - bmv2)
    router.vm.network "private_network", auto_config:  false,
      virtualbox__intnet: "servers-router"
    
    router.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/router.yml"
    end
  end

  # VM Servidor (L4S)
  config.vm.define "serverp4" do |server|
    server.vm.box = BOX_IMAGE
    server.vm.hostname = "server-l4s-p4"
    server.vm.network "private_network",ip: "192.168.59.10", mac: "080027DDDDDD",
      virtualbox__intnet: "servers-router"
    server.vm.provider "virtualbox" do |vb|
      vb.name = "servidor-l4s-p4" 
    end

    server.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/server_l4s.yml"
    end
  end

  # VM Classic Server
  config.vm.define "classic-serverp4" do |classic_server|
    classic_server.vm.box = BOX_IMAGE
    classic_server.vm.hostname = "classic-server"
    classic_server.vm.network "private_network", ip: "192.168.59.20", mac: "080027EEEEEE",
      virtualbox__intnet: "servers-router"
    classic_server.vm.provider "virtualbox" do |vb|
      vb.name = "classic-server-p4"
    end 

    classic_server.vm.provision "ansible" do |ansible|
      ansible.playbook = "playbooks/server_classic.yml"
    end
  end
end
