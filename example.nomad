job "job" {
  datacenters = ["dc1"]
  type        = "service"

  update {
    canary       = 2
    max_parallel = 3
  }

  group "group" {
    count = 5

    task "task" {
      driver = "triton"

      service {
        name         = "job-group-task-ssh"
        tags         = ["example"]
        port         = "22"
        address_mode = "driver"

        check {
          type         = "tcp"
          port         = "22"
          interval     = "10s"
          timeout      = "2s"
          address_mode = "driver"
        }
      }

      service {
        name         = "job-group-task-bob"
        tags         = ["bob"]
        port         = "22"
        address_mode = "driver"

        check {
          type         = "tcp"
          port         = "22"
          interval     = "10s"
          timeout      = "2s"
          address_mode = "driver"
        }
      }

      config {
        package = "f1eb7de6-28fb-65da-cb69-a5d1ac905b8b"

        image     = "7b5981c4-1889-11e7-b4c5-3f3bdfc9b88b"
        fwenabled = true

        #image = "3dbbdcca-2eab-11e8-b925-23bf77789921"

        networks = [
          "a99cbb20-3bf2-4469-8236-81862b0a9c7b",
          "71a1abac-f003-4b51-ac63-28d37f2ef0af",
        ]
        cns = [
          "rawrsauce",
        ]
        tags = {
          fwtag = "true"
        }
        fwrules = {
          fwrule0 = "FROM any TO tag fwtag ALLOW tcp (PORT 22 AND PORT 8080)"
        }
      }

      env {
        my_key = "test"
      }

      meta {
        my-key = "my-value"
      }
    }
  }
}
