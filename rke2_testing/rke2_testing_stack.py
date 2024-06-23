from aws_cdk import (
    Duration,
    Stack,
    Tags,
    aws_ec2 as ec2,

    aws_iam as iam,
    aws_elasticloadbalancingv2 as elbv2,
    aws_autoscaling as asg,
    aws_ssm as ssm,
    aws_s3_assets as s3_assets,
    aws_logs as logs
)
from constructs import Construct

from yaml import dump
from os import path


class Rke2TestingStack(Stack):

    def userdata(self, server, bucket, config_key):
        common = [
            "dnf install --allowerasing --nobest -y curl vim git jq",
            "systemctl disable --now nm-cloud-setup.service",
            "systemctl disable --now nm-cloud-setup.timer",
            "systemctl disable --now firewalld.service",
            "modprobe br_netfilter",
            "modprobe xt_REDIRECT",
            "modprobe iptable_nat",
            "modprobe iptable_filter",
            "modprobe iptable_mangle",
            "modprobe nf_conntrack",
            "modprobe nf_conntrack_ipv4",
            "modprobe nf_nat",
            "modprobe nf_nat_ipv4",
            "modprobe overlay",

        ]
        ssh_pub = None
        with open(path.expanduser("~/.ssh/id_ecdsa.pub")) as f:
            ssh_pub = f.read().strip()
        userdata = dump({
            "ssh_authorized_keys": [
                ssh_pub
            ],
            "runcmd": common + [
                "TOKEN=$( curl -X PUT \"http://169.254.169.254/latest/api/token\" -H \"X-aws-ec2-metadata-token-ttl-seconds: 30\" )",
                "INSTANCE_ID=$( curl -H \"X-aws-ec2-metadata-token: $TOKEN\" -v http://169.254.169.254/latest/meta-data/instance-id )",
                "TAGS=$( aws ec2 describe-tags --filters Name=resource-type,Values=instance Name=resource-id,Values=$INSTANCE_ID --output json )",

                "ROLE=$( echo $TAGS | jq '.Tags[] | select(.Key == \"node-role.kubernetes.io\") | .Value' -r )",
                "VERSION=$( echo $TAGS | jq '.Tags[] | select(.Key == \"rke2-version\") | .Value' -r )",
                "LEADER=$( echo $TAGS | jq '.Tags[] | select(.Key == \"cluster-lead\") | .Value' -r )",

                f"aws s3 cp s3://{bucket}/{config_key} /root/generate_config",
                "chmod +x /root/generate_config",
                "RKE2_TOKEN=$( aws ssm get-parameter --name /rke2_testing/token --query 'Parameter.Value' --output text )",
                f"/root/generate_config $ROLE {server} $RKE2_TOKEN $LEADER",
                f"curl -sfL https://get.rke2.io | INSTALL_RKE2_VERSION=$VERSION INSTALL_RKE2_TYPE=$ROLE sh -",
                "systemctl enable --now rke2-$ROLE",
            ]})

        return ec2.UserData.custom(f"#cloud-config\n\n{userdata}")

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        iam.Role.customize_roles(self, prevent_synthesis=True)

        self.vpc = ec2.Vpc(self, "VPC",
                           ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
                           max_azs=2,
                           nat_gateways=0,
                           subnet_configuration=[
                               ec2.SubnetConfiguration(
                                   name="Public",
                                   subnet_type=ec2.SubnetType.PUBLIC
                               ),
                               ec2.SubnetConfiguration(
                                   name="Private",
                                   subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
                               )
                           ]
                           )

        role = iam.Role(self, "Role",
                        role_name="AFC2S-EC2-ROLE",
                        assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
                        managed_policies=[
                            iam.ManagedPolicy.from_aws_managed_policy_name(
                                "AmazonSSMManagedInstanceCore")
                        ],
                        inline_policies={
                            "default": iam.PolicyDocument(statements=[
                                iam.PolicyStatement(
                                    actions=[
                                        "ec2:DescribeTags"
                                    ],
                                    resources=["*"],
                                    effect=iam.Effect.ALLOW
                                )

                            ])
                        }
                        )
        token = ssm.StringParameter(
            self, "rke2-token", parameter_name="/rke2_testing/token", string_value="token")
        token.grant_read(role)
        config = s3_assets.Asset(self, "config", path=path.expanduser(
            "./helper-scripts/generate-config"))
        nlb = elbv2.NetworkLoadBalancer(self, "NLB", vpc=self.vpc, internet_facing=False, cross_zone_enabled=True, security_groups=[ec2.SecurityGroup(self, "nlb-sg", vpc=self.vpc, allow_all_outbound=True)],
                                        vpc_subnets=ec2.SubnetSelection(
                                            subnet_type=ec2.SubnetType.PUBLIC),
                                        )

        config.bucket.grant_read(role)
        common_params = {
            "user_data": self.userdata(nlb.load_balancer_dns_name, config.s3_bucket_name, config.s3_object_key),
            "instance_type": ec2.InstanceType.of(
                ec2.InstanceClass.M5A,
                ec2.InstanceSize.XLARGE2,
            ),
            "machine_image": ec2.MachineImage.latest_amazon_linux2023(),
            "block_devices": [
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(250)
                )
            ],
            "security_group": ec2.SecurityGroup(
                self, "control-plane-sg", vpc=self.vpc, allow_all_outbound=True),
            "require_imdsv2": True,

        }
        instance = ec2.Instance(self, "control-plane",
                                vpc=self.vpc,
                                vpc_subnets=ec2.SubnetSelection(
                                    subnet_type=ec2.SubnetType.PUBLIC),
                                **common_params)

        if not instance.node.try_remove_child("InstanceProfile"):
            exit(255)
        lt = ec2.LaunchTemplate(self, "LaunchTemplate",
                                role=role,
                                http_put_response_hop_limit=2,
                                http_tokens=ec2.LaunchTemplateHttpTokens.REQUIRED,
                                **common_params
                                )
        log_group = logs.LogGroup(
            self, "nlb-logs", retention=logs.RetentionDays.ONE_DAY)
        flow_log_role = iam.Role(self, "flow-log-role", assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),

                                 inline_policies={
            "default": iam.PolicyDocument(statements=[
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams",
                    ],
                    resources=[
                        log_group.log_group_arn + ":*"],
                    effect=iam.Effect.ALLOW
                )
            ])

        })

        Tags.of(lt).add("node-role.kubernetes.io",
                        "server", apply_to_launched_instances=True)
        Tags.of(lt).add("rke2-version", "v1.28.9+rke2r1",
                        apply_to_launched_instances=True)
        Tags.of(lt).add("kubernetes.io/cluster/dev",
                        "owned", apply_to_launched_instances=True)

        cp_asg = asg.AutoScalingGroup(self, "control-plane-asg", launch_template=lt, min_capacity=0, max_capacity=3, desired_capacity=0, vpc=self.vpc,
                                      vpc_subnets=ec2.SubnetSelection(
                                          subnet_type=ec2.SubnetType.PUBLIC),
                                      default_instance_warmup=Duration.seconds(
                                          30),

                                      health_check=asg.HealthCheck.elb(grace=Duration.seconds(300)))
        Tags.of(cp_asg).add("k8s.io/cluster-autoscaler/enabled",
                            "true", apply_to_launched_instances=False)
        Tags.of(cp_asg).add("k8s.io/cluster-autoscaler/dev",
                            "1", apply_to_launched_instances=False)

        api_listener = nlb.add_listener("api-server", port=6443)
        api_listener.add_targets("api-server", port=6443, targets=[cp_asg], health_check=elbv2.HealthCheck(protocol=elbv2.Protocol.HTTPS, path="/",
                                 enabled=True, healthy_http_codes="200-500", healthy_threshold_count=5, unhealthy_threshold_count=5, interval=Duration.seconds(15)))

        supervisor_listener = nlb.add_listener("supervisor", port=9345)
        supervisor_listener.add_targets("supervisor", port=9345, targets=[cp_asg], health_check=elbv2.HealthCheck(
            protocol=elbv2.Protocol.HTTPS, path="/", enabled=True, healthy_http_codes="200-500", healthy_threshold_count=5, unhealthy_threshold_count=5, interval=Duration.seconds(15)))

        nlb.connections.allow_from_any_ipv4(ec2.Port.tcp(6443))
        nlb.connections.allow_from_any_ipv4(ec2.Port.tcp(9345))

        cp_asg.connections.allow_from(nlb, ec2.Port.tcp(6443))

        cp_asg.connections.allow_from(cp_asg, ec2.Port.tcp(6443))

        cp_asg.connections.allow_from(nlb, ec2.Port.tcp(9345))
        cp_asg.connections.allow_from(cp_asg, ec2.Port.tcp(9345))
        cp_asg.connections.allow_from(cp_asg, ec2.Port.tcp(10250))

        cp_asg.connections.allow_from(cp_asg, ec2.Port.udp(8472))
        cp_asg.connections.allow_from(cp_asg, ec2.Port.udp(4789))

        cp_asg.connections.allow_from(cp_asg, ec2.Port.tcp_range(2379, 2381))
