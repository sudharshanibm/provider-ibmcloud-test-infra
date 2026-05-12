data "ibm_is_vpc" "existing_vpc" {
  count = var.vpc_name != "" ? 1 : 0
  name  = var.vpc_name
}

resource "ibm_is_vpc" "vpc" {
  count                       = var.vpc_name == "" ? 1 : 0
  name                        = "${var.cluster_name}-vpc"
  default_security_group_name = "${var.cluster_name}-security-group"
  resource_group              = var.resource_group
}

locals {
  vpc_id         = var.vpc_name != "" ? data.ibm_is_vpc.existing_vpc[0].id : ibm_is_vpc.vpc[0].id
  security_group = ibm_is_security_group.primary.id
}

resource "ibm_is_security_group" "primary" {
  name           = "${var.cluster_name}-security-group"
  vpc            = local.vpc_id
  resource_group = var.resource_group
}

resource "ibm_is_floating_ip" "gateway" {
  name           = "${var.cluster_name}-gateway-ip"
  zone           = var.zone
  resource_group = var.resource_group
}

resource "ibm_is_public_gateway" "gateway" {
  name           = "${var.cluster_name}-gateway"
  vpc            = local.vpc_id
  zone           = var.zone
  resource_group = var.resource_group
  floating_ip = {
    id = ibm_is_floating_ip.gateway.id
  }
}

resource "ibm_is_subnet" "primary" {
  name                     = "${var.cluster_name}-subnet"
  vpc                      = local.vpc_id
  zone                     = var.zone
  resource_group           = var.resource_group
  total_ipv4_address_count = 256
  public_gateway           = ibm_is_public_gateway.gateway.id
}

resource "ibm_is_security_group_rule" "primary_outbound" {
  group     = local.security_group
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

resource "ibm_is_security_group_rule" "primary_inbound" {
  group     = local.security_group
  direction = "inbound"
  remote    = local.security_group
}

resource "ibm_is_security_group_rule" "primary_ssh" {
  group     = local.security_group
  direction = "inbound"
  remote    = "0.0.0.0/0"

  tcp {
    port_min = 22
    port_max = 22
  }
}

resource "ibm_is_security_group_rule" "primary_k8s" {
  group     = local.security_group
  direction = "inbound"
  remote    = "0.0.0.0/0"

  tcp {
    port_min = 80
    port_max = 80
  }
}

resource "ibm_is_security_group_rule" "primary_ping" {
  group     = local.security_group
  direction = "inbound"
  remote    = "0.0.0.0/0"

  icmp {
    code = 0
    type = 8
  }
}

resource "ibm_is_security_group_rule" "primary_api_server" {
  group     = local.security_group
  direction = "inbound"
  remote    = "0.0.0.0/0"

  tcp {
    port_min = 992
    port_max = 992
  }
}
