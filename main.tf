provider "aws" {
  region = "us-east-1"
}

locals {
  region = "us-east-1"
  name   = "wordpress"

  vpc_cidr = "10.0.0.0/16"
  azs      = ["us-east-1a", "us-east-1b"]

  container_name = "wordpress"
  container_port = 8080

  tags = {
    Name    = local.name
    Example = local.name
  }

  # Used by ASG to run in the AWS EC2 AMI, to define ECS cluster, and install efs-utils for volume persistence
  on_demand_user_data = <<-EOT
    #!/bin/bash

    yum install -y amazon-efs-utils
    mkdir -p /mnt/efs
    mount -t efs -o tls,accesspoint=${module.efs.access_points["root"]["id"]} ${module.efs.id}:/ /mnt/efs
    echo '${module.efs.id}:/ /mnt/efs efs tls,accesspoint=${module.efs.access_points["root"]["id"]} 0 0' >> /etc/fstab

    cat <<'EOF' >> /etc/ecs/ecs.config
    ECS_CLUSTER=${local.name}
    ECS_LOGLEVEL=debug
    ECS_CONTAINER_INSTANCE_TAGS=${jsonencode(local.tags)}
    ECS_ENABLE_TASK_IAM_ROLE=true
    EOF
  EOT
}

################################################################################
# RDS
################################################################################

module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.5.2"

  identifier = "rds"

  engine                = "mysql"
  engine_version        = "8.0"
  family                = "mysql8.0" # DB parameter group
  major_engine_version  = "8.0"      # DB option group
  instance_class        = "db.t4g.micro"
  storage_type          = "gp3"
  allocated_storage     = 20
  max_allocated_storage = 100

  availability_zone = module.vpc.azs[0]

  depends_on = [module.secret_db_password]

  username                            = "wordpress"
  password                            = data.aws_secretsmanager_secret_version.secret_db_password.secret_string # fetch actual password string from secrets manger
  db_name                             = "wordpressdb"
  port                                = 3306
  manage_master_user_password         = false
  iam_database_authentication_enabled = false

  skip_final_snapshot    = true
  create_db_option_group = false

  db_subnet_group_name   = module.vpc.database_subnet_group
  vpc_security_group_ids = [module.security_group.security_group_id]
}

module "security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = local.name
  description = "EC2 docker access to RDS"
  vpc_id      = module.vpc.vpc_id


  ingress_with_cidr_blocks = [
    { # RDS Ingress
      from_port   = 3306
      to_port     = 3306
      protocol    = "tcp"
      description = "MySQL access from within VPC"
      cidr_blocks = module.vpc.vpc_cidr_block
    },
  ]

  tags = local.tags
}

################################################################################
# ECS Cluster
################################################################################

module "ecs_cluster" {
  source  = "terraform-aws-modules/ecs/aws//modules/cluster"
  version = "~> 5.10"

  cluster_name = local.name

  cloudwatch_log_group_retention_in_days = 1

  # Capacity provider - autoscaling groups
  default_capacity_provider_use_fargate = false
  autoscaling_capacity_providers = {
    # On-demand instances
    ex_1 = {
      auto_scaling_group_arn         = module.autoscaling["ex_1"].autoscaling_group_arn
      managed_termination_protection = "DISABLED"

      managed_scaling = { # Enabling would allow for autoscaling instances
        maximum_scaling_step_size = 1
        minimum_scaling_step_size = 1
        status                    = "DISABLED"
        target_capacity           = 100
      }

      default_capacity_provider_strategy = { # This would be edited for multiple capacity providers
        weight = 60
        base   = 20
      }
    }
  }
  tags = local.tags
}

################################################################################
# ECS Service
################################################################################

module "ecs_service" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "~> 5.10"

  # Service
  name        = local.name
  cluster_arn = module.ecs_cluster.arn
  cpu         = 1843 # CPU units for the task, reserving some for system overhead (t3.micro)
  memory      = 724  # Memory for the task, reserving system overhead (t3.micro)

  # Task Definition (The Task IAM role is defined in the Autoscaling module)
  requires_compatibilities = ["EC2"]
  capacity_provider_strategy = {
    # On-demand instances
    ex_1 = {
      capacity_provider = module.ecs_cluster.autoscaling_capacity_providers["ex_1"].name
      weight            = 1
      base              = 1
    }
  }

  # EFS volume
  volume = {
    wordpress_data = {
      efs_volume_configuration = {
        file_system_id     = module.efs.id
        transit_encryption = "ENABLED"
        authorization_config = {
          access_point_id = module.efs.access_points["root"]["id"]
          iam             = "ENABLED"
        }
      }
    }
  }

  # Fetch passwords before populating container definitions
  depends_on = [module.secret_user_password, module.secret_db_password]

  # Container definition(s)
  container_definitions = {
    (local.container_name) = {
      image     = "docker.io/bitnami/wordpress:6"
      user      = "root" # Ideally run docker container as non-root user
      essential = true
      port_mappings = [
        {
          name          = local.container_name
          containerPort = local.container_port # Port 8080 is bitnami container default
          hostPort      = local.container_port # ALB listens on port 80, forwards to target group on port 8080
        }
      ]
      cpu    = 1843 # Allocate nearly all CPU units to this container
      memory = 724  # Allocate majority of memory to this container

      environment = [
        {
          name  = "WORDPRESS_DATABASE_HOST"
          value = module.rds.db_instance_address
        },
        {
          name  = "WORDPRESS_DATABASE_PORT_NUMBER"
          value = 3306
        },
        {
          name  = "WORDPRESS_DATABASE_USER"
          value = "wordpress"
        },
        {
          name  = "WORDPRESS_DATABASE_NAME"
          value = "wordpressdb"
        },
        {
          name  = "WORDPRESS_USERNAME"
          value = "wordpress"
        },
        {
          name  = "WORDPRESS_ENABLE_HTTPS"
          value = "yes"
        },
        {
          name  = "WORDPRESS_VOLUME_DIR"
          value = "/mnt/efs/"
        },
      ]

      secrets = [
        {
          name      = "WORDPRESS_DATABASE_PASSWORD"
          valueFrom = module.secret_db_password.secret_arn
        },
        {
          name      = "WORDPRESS_PASSWORD"
          valueFrom = module.secret_user_password.secret_arn
        }
      ]

      mount_points = [
        {
          sourceVolume  = "wordpress_data",
          containerPath = "/bitnami/wordpress" # by default wp-config.php wp-content are persisted, env WORDPRESS_DATA_TO_PERSIST
          readOnly      = false
        }
      ]

      readonly_root_filesystem = false

      enable_cloudwatch_logging              = true
      create_cloudwatch_log_group            = true
      cloudwatch_log_group_name              = "/aws/ecs/${local.name}/${local.container_name}"
      cloudwatch_log_group_retention_in_days = 1

      log_configuration = {
        logDriver = "awslogs"
      }
    }
  }

  load_balancer = {
    service = {
      target_group_arn = module.alb.target_groups["ex_ecs"].arn
      container_name   = local.container_name
      container_port   = local.container_port
    }
  }

  subnet_ids = module.vpc.private_subnets
  security_group_rules = {
    alb_http_ingress = {
      type                     = "ingress"
      from_port                = local.container_port
      to_port                  = local.container_port
      protocol                 = "tcp"
      description              = "Service port"
      source_security_group_id = module.alb.security_group_id
    },
    "allow-internet" = { # to fetch docker image outside AWS (not in ECR)
      type        = "egress"
      protocol    = "all"
      cidr_blocks = ["0.0.0.0/0"]
      from_port   = 0
      to_port     = 0
    }
  }
}

################################################################################
# ALB
################################################################################

# https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-optimized_AMI.html#ecs-optimized-ami-linux
# Extract the last version of AWS Optimized AMI for ECS
data "aws_ssm_parameter" "ecs_optimized_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended"
}

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 9.0"

  name = local.name

  load_balancer_type = "application"

  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnets

  # For example only
  enable_deletion_protection = false

  # Security Group
  security_group_ingress_rules = {
    all_http = {
      from_port   = 80
      to_port     = 80
      ip_protocol = "tcp"
      description = "HTTP web traffic"
      cidr_ipv4   = "0.0.0.0/0"
    }
    all_https = {
      from_port   = 443
      to_port     = 443
      ip_protocol = "tcp"
      description = "HTTPS web traffic"
      cidr_ipv4   = "0.0.0.0/0"
    }

  }
  security_group_egress_rules = {
    all = {
      ip_protocol = "-1"
      cidr_ipv4   = module.vpc.vpc_cidr_block
    }
  }

  listeners = {
    ex-http-https-redirect = {
      port     = 80
      protocol = "HTTP"
      redirect = {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
    ex-https = {
      port            = 443
      protocol        = "HTTPS"
      ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
      certificate_arn = module.acm.acm_certificate_arn

      forward = {
        target_group_key = "ex_ecs"
      }
    }
  }

  target_groups = {
    ex_ecs = {
      backend_protocol                  = "HTTP"
      backend_port                      = local.container_port
      target_type                       = "ip"
      deregistration_delay              = 5
      load_balancing_cross_zone_enabled = true

      health_check = {
        enabled             = true
        healthy_threshold   = 5
        interval            = 30
        matcher             = "200"
        path                = "/"
        port                = "traffic-port"
        protocol            = "HTTP"
        timeout             = 5
        unhealthy_threshold = 2
      }

      # Theres nothing to attach here in this definition. Instead,
      # ECS will attach the IPs of the tasks to this target group
      create_attachment = false
    }
  }

  tags = local.tags
}

################################################################################
# ASG
################################################################################

module "autoscaling" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "~> 6.5"

  for_each = {
    # On-demand instances
    ex_1 = {
      instance_type              = "t3.micro"
      use_mixed_instances_policy = false
    }
  }

  name = local.name

  image_id      = jsondecode(data.aws_ssm_parameter.ecs_optimized_ami.value)["image_id"]
  instance_type = "t3.micro"

  instance_market_options = {
    market_type = "spot" # Lower cost for testing purposes
  }

  security_groups                 = [aws_security_group.autoscaling_sg.id]
  user_data                       = base64encode(local.on_demand_user_data)
  ignore_desired_capacity_changes = true

  create_iam_instance_profile = true
  iam_role_name               = local.name
  iam_role_description        = "ECS role for ${local.name}"
  iam_role_policies = {
    AmazonEC2ContainerServiceforEC2Role = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    AmazonSSMManagedInstanceCore        = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    EFSFullAccess                       = aws_iam_policy.efs_full_access.arn
    RDSFullAccess                       = aws_iam_policy.rds_full_access.arn
    ecs-secrets-manager-access          = aws_iam_policy.secrets_manager_access.arn
  }

  vpc_zone_identifier = module.vpc.private_subnets
  health_check_type   = "EC2"
  min_size            = 2 # Make task Highly Available maintaining 2 ec2 instances across each AZ
  max_size            = 4 # Allow for temporary creation of extra instances while reaching desired capacity
  desired_capacity    = 2

  # https://github.com/hashicorp/terraform-provider-aws/issues/12582
  autoscaling_group_tags = {
    AmazonECSManaged = true
  }

  # Required for  managed_termination_protection = "ENABLED"
  protect_from_scale_in = false

}

# Security Groups for EC2 instances
resource "aws_security_group" "autoscaling_sg" {
  name        = "autoscaling_sg"
  description = "Autoscaling group security group"
  vpc_id      = module.vpc.vpc_id
  tags        = local.tags
}

resource "aws_security_group_rule" "ingress_http_from_alb" { # HTTP
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = aws_security_group.autoscaling_sg.id
  source_security_group_id = module.alb.security_group_id
}

resource "aws_security_group_rule" "ingress_mysql_from_alb" { # RDS
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  security_group_id        = aws_security_group.autoscaling_sg.id
  source_security_group_id = module.alb.security_group_id # Adjust this if the source is not the ALB
}

resource "aws_security_group_rule" "ingress_nfs_from_alb" { # EFS
  type                     = "ingress"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  security_group_id        = aws_security_group.autoscaling_sg.id
  source_security_group_id = module.alb.security_group_id # Adjust this if the source is not the ALB
}

resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1" # Represents all protocols
  security_group_id = aws_security_group.autoscaling_sg.id
  cidr_blocks       = ["0.0.0.0/0"] # Allows all outbound traffic
}

# Role Policies to add to EC2 Role
resource "aws_iam_policy" "efs_full_access" {
  name        = "EFSFullAccess"
  description = "Provides full access to EFS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = "elasticfilesystem:*"
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# elasticfilesystem:Describe* elasticfilesystem:ClientWrite elasticfilesystem:ClientMount
# "Resource": "${module.efs.arn}"

resource "aws_iam_policy" "rds_full_access" {
  name        = "RDSFullAccess"
  description = "Provides full access to RDS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = "rds:*"
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

################################################################################
# VPC
################################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = local.name
  cidr = local.vpc_cidr

  azs              = local.azs
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 3)]
  database_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 6)]

  create_database_subnet_group = true

  enable_nat_gateway = true
  single_nat_gateway = true
}

output "alb" {
  value = module.alb.dns_name
}

################################################################################
# EFS
################################################################################

module "efs" {
  source  = "terraform-aws-modules/efs/aws"
  version = "~> 1.6.1"

  # File system
  name           = local.name
  creation_token = local.name
  encrypted      = false
  #kms_key_arn    = module.kms.key_arn

  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"

  lifecycle_policy = {
    transition_to_ia                    = "AFTER_30_DAYS"
    transition_to_primary_storage_class = "AFTER_1_ACCESS"
  }

  # File system policy
  attach_policy                      = true
  bypass_policy_lockout_safety_check = false # for KMS key management

  deny_nonsecure_transport = false # Allow non encrypted traffic for testing

  policy_statements = [
    {
      sid     = "Example"
      actions = ["elasticfilesystem:*"]
      principals = [
        {
          type        = "AWS"
          identifiers = ["*"]
        }
      ]
    }
  ]
  # Replace "*" with [module.ecs_service.tasks_iam_role_arn]

  # Mount targets / security group
  mount_targets              = { for k, v in zipmap(local.azs, module.vpc.private_subnets) : k => { subnet_id = v } }
  security_group_description = "Example EFS security group"
  security_group_vpc_id      = module.vpc.vpc_id
  security_group_rules = {
    vpc = {
      # Relying on the defaults provided for EFS/NFS (2049/TCP + ingress)
      description = "NFS ingress from VPC private subnets"
      cidr_blocks = module.vpc.private_subnets_cidr_blocks
    }
  }

  # Access point(s)
  access_points = {
    posix = { # Used for strict security controls and user isolation
      name = "posix-example"
      posix_user = {
        gid            = 1001
        uid            = 1001
        secondary_gids = [1002]
      }

      tags = {
        Additional = "Wordpress EFS"
      }
    }
    root = { # Default
      root_directory = {
        path = "/"
        creation_info = {
          owner_gid   = 0 # Non-root user is 1001. (as defined in dockerfile) root is 0
          owner_uid   = 0 # Non-root user is 1001. (as defined in dockerfile) root is 0
          permissions = "755"
        }
      }
    }
  }

  # Backup policy
  # enable_backup_policy = true

  tags = local.tags
}

################################################################################
# ACM / CloudFlare
################################################################################

# Obtain SSL certificate
module "acm" {
  source  = "terraform-aws-modules/acm/aws"
  version = "~> 5.0.1"

  domain_name            = "wp.tbalza.net"
  validation_method      = "DNS"
  wait_for_validation    = false
  create_route53_records = false

  tags = {
    Name = "wp.tbalza.net"
  }
}

# Validate ACM SSL certificate. Uses the output of acm module to to complete DNS validation in CloudFlare
variable "validation_record_keys" {
  type    = list(string)
  default = ["record1", "record2", "record3", "record4"] # Adjust based on the number of expected ACM validation records
}

locals { # The output is a map within a single list item, iterate through to define values
  acm_validation_records = {
    for idx, val in module.acm.acm_certificate_domain_validation_options :
    "record${idx + 1}" => {
      name  = val.resource_record_name  # Will appear as unresolved ref before apply
      value = val.resource_record_value # Will appear as unresolved ref before apply
    }
  }
}

resource "cloudflare_record" "acm_validation" {
  for_each = local.acm_validation_records

  zone_id = var.cloudflare_zone_id
  name    = each.value.name # Will appear as unresolved ref before apply
  type    = "CNAME"
  value   = each.value.value # Will appear as unresolved ref before apply
  ttl     = 1
  proxied = false
}

# Create wp. subdomain for ALB. Update DNS (managed by CloudFlare) CNAME to point wp.tbalza.net to ALB
provider "cloudflare" {
  api_token = var.cloudflare_api_token # Ensure you have this variable in your variables.tf or passed in via environment variables
}
resource "cloudflare_record" "wp_cname" {
  zone_id = var.cloudflare_zone_id # Ensure you have this variable in your variables.tf or passed in via environment variables
  name    = "wp"
  value   = module.alb.dns_name
  type    = "CNAME"
  proxied = false
}

################################################################################
# Secrets Manager
################################################################################

data "aws_caller_identity" "current" {}

# Allow ECS tasks to access secrets
resource "aws_iam_policy" "secrets_manager_access" {
  name        = "ecs-secrets-manager-access"
  description = "Allows ECS tasks to access secrets in Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ],
        Effect   = "Allow",
        Resource = "*" # It's better to specify exact ARNs of secrets
      }
    ]
  })
}

# Generate wordpress db password
data "aws_secretsmanager_secret_version" "secret_db_password" { # required to return the actual pw string for the RDS module
  secret_id  = module.secret_db_password.secret_id
  depends_on = [module.secret_db_password]
}

module "secret_db_password" {
  source  = "terraform-aws-modules/secrets-manager/aws"
  version = "~> 1.1.2"

  name_prefix = "wordpress-db-password-"
  description = "Secret for WordPress Database Password"

  create_random_password           = true
  random_password_length           = 41  # RDS length limit
  random_password_override_special = "_" # list of permitted special characters

}

# Generate wordpress user password
data "aws_secretsmanager_secret_version" "secret_user_password" {
  secret_id  = module.secret_user_password.secret_id
  depends_on = [module.secret_user_password]
}

module "secret_user_password" {
  source  = "terraform-aws-modules/secrets-manager/aws"
  version = "~> 1.1.2"

  name_prefix = "wordpress-user-password-"
  description = "Secret for WordPress User Password"

  create_random_password           = true
  random_password_length           = 41  # RDS length limit
  random_password_override_special = "_" # list of permitted special characters
}

################################################################################
# Outputs for testing purposes
################################################################################

output "aws_cname_acm_validation" {
  value     = module.acm.acm_certificate_domain_validation_options
  sensitive = true
}

output "wp_db_password" {
  value     = data.aws_secretsmanager_secret_version.secret_db_password.secret_string
  sensitive = true
}

output "service_tasks_iam_role_name" {
  value = module.ecs_service.tasks_iam_role_name #ecs_service.tasks_iam_role_name
}

output "service_tasks_iam_arn" {
  value = module.ecs_service.task_exec_iam_role_arn #ecs_service.tasks_iam_role_arn
}

output "efs_id" {
  value = module.efs.id
}

output "efs_root_id" {
  value = module.efs.access_points["root"]["id"]
}

output "efs_arn" {
  value = module.efs.arn
}

output "sg_alb" {
  value = module.alb.security_group_id
}

output "sg_asg" {
  value = aws_security_group.autoscaling_sg.id
}

output "sg_ecs_service" {
  value = module.ecs_service.security_group_id
}

output "sg_vpc" {
  value = module.security_group.security_group_id
}

output "sg_efs" {
  value = module.efs.security_group_id
}