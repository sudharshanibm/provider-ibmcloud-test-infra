data "ibm_resource_group" "default_group" {
  name = var.vpc_resource_group
}

data "ibm_is_image" "node_image" {
  name = var.node_image
}

data "ibm_is_ssh_key" "ssh_key" {
  name = var.vpc_ssh_key
}

module "vpc" {
  source          = "./vpc-instance"
  vpc_name        = var.vpc_name
  vpc_subnet_name = var.vpc_subnet_name
  cluster_name    = var.cluster_name
  zone            = var.vpc_zone
  resource_group  = data.ibm_resource_group.default_group.id
}

locals {
  vpc_id            = module.vpc.vpc_id
  subnet_id         = module.vpc.subnet_id
  security_group_id = module.vpc.security_group_id
}

resource "ibm_is_instance_template" "node_template" {
  name           = "${var.cluster_name}-node-template"
  image          = data.ibm_is_image.node_image.id
  profile        = var.node_profile
  vpc            = local.vpc_id
  zone           = var.vpc_zone
  resource_group = data.ibm_resource_group.default_group.id
  keys           = [data.ibm_is_ssh_key.ssh_key.id]

  primary_network_interface {
    subnet          = local.subnet_id
    security_groups = [local.security_group_id]
  }

  user_data = <<-EOT
#cloud-config
users:
  - default
  - name: k8s-admin
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [sudo]
    ssh_authorized_keys:
      - ${data.ibm_is_ssh_key.ssh_key.public_key}
runcmd:
  - |
    # Ensure k8s-admin SSH dir has correct permissions
    mkdir -p /home/k8s-admin/.ssh
    chown -R k8s-admin:k8s-admin /home/k8s-admin/.ssh
    chmod 700 /home/k8s-admin/.ssh
    chmod 600 /home/k8s-admin/.ssh/authorized_keys
EOT
}

module "master" {
  source                    = "./node"
  node_name                 = "${var.cluster_name}-master"
  node_instance_template_id = ibm_is_instance_template.node_template.id
  resource_group            = data.ibm_resource_group.default_group.id
  subnet_id                 = local.subnet_id
  security_group_id         = local.security_group_id
}

module "workers" {
  source                    = "./node"
  count                     = var.workers_count
  node_name                 = "${var.cluster_name}-worker-${count.index}"
  node_instance_template_id = ibm_is_instance_template.node_template.id
  resource_group            = data.ibm_resource_group.default_group.id
  subnet_id                 = local.subnet_id
  security_group_id         = local.security_group_id
}

resource "null_resource" "wait-for-master-completes" {
  depends_on = [module.master]

  # First wait for cloud-init to complete using root user (still available during boot)
  provisioner "local-exec" {
    command = <<-EOT
      max_attempts=60
      attempt=0
      host="${module.master.public_ip}"
      ssh_key="${var.ssh_private_key}"
      
      echo "=== Attempting SSH to master at $host ==="
      echo "=== SSH key: $ssh_key ==="
      
      while [ $attempt -lt $max_attempts ]; do
        attempt=$((attempt + 1))
        
        # Use verbose SSH on first attempt for diagnostics
        if [ $attempt -eq 1 ]; then
          echo "=== First attempt - verbose SSH for diagnostics ==="
          ssh -v -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
              -i "$ssh_key" k8s-admin@"$host" "echo SSH_OK" 2>&1 || true
          echo "=== End verbose diagnostics ==="
        fi

        # Try k8s-admin (cloud-init created user)
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
               -i "$ssh_key" k8s-admin@"$host" \
               "sudo cloud-init status --wait" 2>&1; then
          echo "Cloud-init completed on master (via k8s-admin)"
          break
        fi

        # Try ubuntu (IBM Cloud default user on Ubuntu images)
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
               -i "$ssh_key" ubuntu@"$host" \
               "sudo cloud-init status --wait" 2>&1; then
          echo "Cloud-init completed on master (via ubuntu)"
          break
        fi

        # Fallback to root for older images
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
               -i "$ssh_key" root@"$host" \
               "cloud-init status --wait" 2>&1; then
          echo "Cloud-init completed on master (via root)"
          break
        fi

        echo "Waiting for cloud-init on master (attempt $attempt/$max_attempts)..."
        sleep 10
      done
      if [ $attempt -eq $max_attempts ]; then
        echo "ERROR: Timed out waiting for cloud-init on master after $max_attempts attempts"
        echo "=== Final diagnostic: trying all users with verbose ==="
        for user in k8s-admin ubuntu root; do
          echo "--- Trying $user ---"
          ssh -v -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
              -i "$ssh_key" "$user"@"$host" "echo SUCCESS" 2>&1 || true
        done
        exit 1
      fi
    EOT
  }

  # Then verify k8s-admin user is accessible
  connection {
    type        = "ssh"
    user        = "k8s-admin"
    host        = module.master.public_ip
    private_key = file(var.ssh_private_key)
    timeout     = "5m"
  }
  provisioner "remote-exec" {
    inline = [
      "echo 'k8s-admin user is ready on master'"
    ]
  }
}

resource "null_resource" "wait-for-workers-completes" {
  count      = var.workers_count
  depends_on = [module.workers]

  # First wait for cloud-init to complete using root user (still available during boot)
  provisioner "local-exec" {
    command = <<-EOT
      max_attempts=60
      attempt=0
      worker_ip="${module.workers[count.index].public_ip}"
      worker_index="${count.index}"
      ssh_key="${var.ssh_private_key}"
      
      echo "=== Attempting SSH to worker $worker_index at $worker_ip ==="
      
      while [ $attempt -lt $max_attempts ]; do
        attempt=$((attempt + 1))

        # Use verbose SSH on first attempt for diagnostics
        if [ $attempt -eq 1 ]; then
          echo "=== First attempt - verbose SSH for diagnostics ==="
          ssh -v -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
              -i "$ssh_key" k8s-admin@"$worker_ip" "echo SSH_OK" 2>&1 || true
          echo "=== End verbose diagnostics ==="
        fi

        # Try k8s-admin (cloud-init created user)
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
               -i "$ssh_key" k8s-admin@"$worker_ip" \
               "sudo cloud-init status --wait" 2>&1; then
          echo "Cloud-init completed on worker $worker_index (via k8s-admin)"
          break
        fi

        # Try ubuntu (IBM Cloud default user on Ubuntu images)
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
               -i "$ssh_key" ubuntu@"$worker_ip" \
               "sudo cloud-init status --wait" 2>&1; then
          echo "Cloud-init completed on worker $worker_index (via ubuntu)"
          break
        fi

        # Fallback to root for older images
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
               -i "$ssh_key" root@"$worker_ip" \
               "cloud-init status --wait" 2>&1; then
          echo "Cloud-init completed on worker $worker_index (via root)"
          break
        fi

        echo "Waiting for cloud-init on worker $worker_index (attempt $attempt/$max_attempts)..."
        sleep 10
      done
      if [ $attempt -eq $max_attempts ]; then
        echo "ERROR: Timed out waiting for cloud-init on worker $worker_index"
        echo "=== Final diagnostic: trying all users with verbose ==="
        for user in k8s-admin ubuntu root; do
          echo "--- Trying $user ---"
          ssh -v -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
              -i "$ssh_key" "$user"@"$worker_ip" "echo SUCCESS" 2>&1 || true
        done
        exit 1
      fi
    EOT
  }

  # Then verify k8s-admin user is accessible
  connection {
    type        = "ssh"
    user        = "k8s-admin"
    host        = module.workers[count.index].public_ip
    private_key = file(var.ssh_private_key)
    timeout     = "5m"
  }
  provisioner "remote-exec" {
    inline = [
      "echo 'k8s-admin user is ready on worker ${count.index}'"
    ]
  }
}
