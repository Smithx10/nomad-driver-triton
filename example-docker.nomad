job "nexus" {
  datacenters = ["dc1"]
  type        = "service"

  update {
    canary            = 1
    max_parallel      = 1
    healthy_deadline  = "8m"
    progress_deadline = "10m"
  }

  group "nexus" {
    count = 1

    task "nexus" {
      driver = "triton"

      service {
        name         = "nexus-ui"
        tags         = ["nexus", "avleen"]
        port         = "8081"
        address_mode = "driver"

        check {
          type         = "http"
          port         = "8081"
          path         = "/"
          interval     = "5s"
          timeout      = "2s"
          address_mode = "driver"
        }
      }

      config {
        api_type = "docker_api"

        docker_api {
          public_network  = "sdc_nat"
          private_network = "consul"

          labels {
            bob.bill.john = "label"
            test          = "test"
          }

          dns = [
            "10.45.137.14",
            "10.45.137.15",
          ]

          extra_hosts = [
            "bob:10.10.10.10",
            "jim:10.10.10.1",
          ]

          domain_name = "bill.com"

          hostname = "b00p"

          user = "root"

          ports {
            tcp = [
              22,
              8081,
            ]

            udp = [
              22,
            ]
          }

          image {
            name      = "sonatype/nexus3"
            tag       = "latest"
            auto_pull = true
          }
        }

        package {
          name = "sample-512M"
        }

        fwenabled = false

        cns = [
          "nexus",
        ]

        tags = {
          nexus = "true"
        }

        fwrules {
          anytonexus = "FROM any TO tag nexus ALLOW tcp PORT 8081"
          nexustcp   = "FROM tag nexus TO tag nexus ALLOW tcp PORT all"
          nexusudp   = "FROM tag nexus TO tag nexus ALLOW udp PORT all"
        }
      }

      env {
        envtest = "test"
      }

      meta {
        my-key = "my-value"
      }
    }
  }
}
